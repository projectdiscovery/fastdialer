package utils

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/utils/errkit"
	iputil "github.com/projectdiscovery/utils/ip"
)

// == DialWrap =====
// DialWrap is a net dialer wrapper optimized for dialing hostnames with multiple IPs.
// It attempts the first dial in parallel, blocking all other dials until this first dial is complete.
// If multiple connections are established during this first parallel dial, they are randomly distributed to
// all paused dials. If the first dial was successful or failed due to temporary reason like context cancellation,
// new connections are created as needed. if it was a permanent error like port being filtered new connections
// are not created and that permanent error is returned.
//
// when dialing new connections after first dial, a happy eyeballs algorithm is used to establish new connections
// Happy Eyeballs Algo =
// Ips are split into Ipv4 and Ipv6
// Ipv6 are first dialed in serial and after fallback delay (300ms) Ipv4 are dialed in parallel
// whichever returns first is used while the other is cancelled
// stdlib dialer uses the same approach
//
// Note:
// Earlier we had tried to reuse connections by always dialing in parallel,
// but that resulted in `use of closed network connection` error. which happens
// when tcp keep alive is disabled / not supported or the connection was used when it was expired(keep alive timeout)
// i.e why we have fallen back to use happy eyeballs algorithm.

// Error constants
var (
	// errGotConnection has already been established
	ErrInflightCancel       = errkit.New("context cancelled before establishing connection")
	ErrNoIPs                = errkit.New("no ips provided in dialWrap")
	ExpireConnAfter         = time.Duration(5) * time.Second
	ErrPortClosedOrFiltered = errkit.New("port closed or filtered").SetKind(errkit.ErrKindNetworkPermanent)
)

// dialResult represents the result of a dial operation
type dialResult struct {
	net.Conn
	error
	primary bool
	done    bool
	expiry  time.Time
}

// DialWrap wraps the net dialer taking in and only dials
// to given ips. This implementation retains the orignal
// Happy Eyeballs algorithm and dual stack support.
type DialWrap struct {
	dialer  *net.Dialer
	ipv4    []net.IP
	ipv6    []net.IP
	ips     []net.IP
	network string
	address string
	port    string
	// below fields implement a singleflight like pattern
	// where first connection is established and subsequent calls receive
	// a shared result
	wg                   sync.WaitGroup
	mu                   sync.Mutex
	completedFirstFlight *atomic.Bool
	dups                 uint8
	err                  error // error returned by first flight
}

// NewDialWrap creates a new dial wrap instance and returns it.
func NewDialWrap(dialer *net.Dialer, ips []string, network, address, port string) (*DialWrap, error) {
	var ipv4, valid, ipv6 []net.IP
	for _, ip := range ips {
		if iputil.IsIP(ip) {
			valid = append(valid, net.ParseIP(ip))
			if iputil.IsIPv4(ip) {
				ipv4 = append(ipv4, net.ParseIP(ip))
			} else {
				ipv6 = append(ipv6, net.ParseIP(ip))
			}
		}
	}
	if len(valid) == 0 {
		return nil, ErrNoIPs
	}
	return &DialWrap{
		dialer:               dialer,
		ipv4:                 ipv4,
		ipv6:                 ipv6,
		ips:                  valid,
		completedFirstFlight: &atomic.Bool{},
		network:              network,
		address:              address,
		port:                 port,
	}, nil
}

// DialContext is the main entry point for dialing
func (d *DialWrap) DialContext(ctx context.Context, _ string, _ string) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, errkit.Append(ErrInflightCancel, ctx.Err())
	case res, ok := <-d.doFirstFlight(ctx):
		if !ok {
			// closed channel so depending on the error
			// either dial new or return the error
			if d.err == nil {
				return d.dial(ctx)
			}
			return nil, d.err
		}
		if res.Conn != nil {
			// check expiry
			if res.expiry.Before(time.Now()) {
				res.Conn.Close()
				return d.dial(ctx)
			}
			return res.Conn, nil
		}
		if d.err != nil {
			return nil, d.err
		}
		return nil, res.error
	case <-d.hasCompletedFirstFlight():
		// if first flight completed and it failed due to other reasons
		// and not due to context cancellation
		if d.err != nil && !errkit.Is(d.err, ErrInflightCancel) && !errkit.Is(d.err, context.Canceled) {
			return nil, d.err
		}
		return d.dial(ctx)
	}
}

// firstFlight is a singleflight pattern implementation
// TODO: remove singleflight pattern
func (d *DialWrap) doFirstFlight(ctx context.Context) chan *dialResult {
	size := len(d.ipv4) + len(d.ipv6)
	ch := make(chan *dialResult, size)
	d.mu.Lock()
	if d.dups > 0 {
		// allow stuck routines to exit and proceed with default dial
		defer close(ch)
		d.mu.Unlock()
		d.wg.Wait()
		return ch
	}
	d.dups++
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()
	// dial parallel
	conns, err := d.dialAllParallel(ctx)
	defer func() {
		d.completedFirstFlight.Store(true)
		close(ch)
	}()
	if err != nil {
		d.err = err
		ch <- &dialResult{error: err}
		return ch
	}
	for _, conn := range conns {
		ch <- conn
	}
	return ch
}

func (d *DialWrap) hasCompletedFirstFlight() chan struct{} {
	if d.completedFirstFlight.Load() {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return nil
}

// dialAllParallel connects to all the given addresses in parallel, returning
// the first successful connection, or the first error.
func (d *DialWrap) dialAllParallel(ctx context.Context) ([]*dialResult, error) {
	// check / adjust deadline
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	rec := make(chan *dialResult, len(d.ipv4)+len(d.ipv6))

	wg := &sync.WaitGroup{}

	go func() {
		defer close(rec)
		defer wg.Wait()
		for _, ip := range d.ips {
			wg.Add(1)
			go func(ipx net.IP) {
				defer wg.Done()
				select {
				case <-ctx.Done():
					rec <- &dialResult{error: errkit.Append(ErrInflightCancel, ctx.Err())}
				default:
					c, err := d.dialer.DialContext(ctx, d.network, net.JoinHostPort(ipx.String(), d.port))
					rec <- &dialResult{Conn: c, error: err, expiry: time.Now().Add(ExpireConnAfter)}
				}
			}(ip)
		}
	}()

	conns := []*dialResult{}
	errs := []*dialResult{}

	for result := range rec {
		if result.Conn != nil {
			conns = append(conns, result)
		} else {
			if !errkit.Is(result.error, ErrInflightCancel) {
				errs = append(errs, result)
			}
		}
	}

	if len(conns) > 0 {
		return conns, nil
	}
	if len(conns) == 0 && len(errs) == 0 {
		// this means all connections were cancelled before we could establish a connection
		return nil, ErrInflightCancel
	}

	// this could be improved to check for permanent errors
	// and blacklist those ips permanently
	var finalErr error
	for _, v := range errs {
		finalErr = errkit.Append(finalErr, v.error)
	}
	// if this is the case then most likely the port is closed or filtered
	// so return appropriate error
	if !errkit.Is(finalErr, ErrInflightCancel) {
		// if it not inflight cancel then it is a permanent error
		return nil, errkit.Append(ErrPortClosedOrFiltered, finalErr)
	}
	return nil, finalErr
}

// dial is the main dialing function
func (d *DialWrap) dial(ctx context.Context) (net.Conn, error) {
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	if d.network == "tcp" && d.dualStack() {
		return d.dialParallel(ctx, d.ipv4, d.ipv6, d.network, d.port)
	}
	return d.dialParallel(ctx, d.ips, nil, d.network, d.port)
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *DialWrap) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.dialer.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.dialer.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return earliest
}

// MultipathTCP is a getter for the MultipathTCP field
func (d *DialWrap) MultipathTCP() bool {
	return d.dialer.MultipathTCP()
}

// SetMultipathTCP is a setter for the MultipathTCP field
func (d *DialWrap) SetMultipathTCP(use bool) {
	d.dialer.SetMultipathTCP(use)
}

// dualStack is a getter for the dualStack field
func (d *DialWrap) dualStack() bool { return d.dialer.FallbackDelay >= 0 }

// fallbackDelay is a getter for the fallbackDelay field
func (d *DialWrap) fallbackDelay() time.Duration {
	if d.dialer.FallbackDelay > 0 {
		return d.dialer.FallbackDelay
	} else {
		return 300 * time.Millisecond
	}
}

// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func (d *DialWrap) dialParallel(ctx context.Context, primaries, fallbacks []net.IP, network string, port string) (net.Conn, error) {
	if len(fallbacks) == 0 {
		return d.dialSerial(ctx, primaries, network, port)
	}

	returned := make(chan struct{})
	defer close(returned)

	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		c, err := d.dialSerial(ctx, ras, network, port)
		select {
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(d.fallbackDelay())
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// Address returns ip and port of the target
// if multiple ips are present, it returns the first one
func (d *DialWrap) Address() (string, string) {
	if len(d.ips) == 0 {
		return "", ""
	}
	return d.ips[0].String(), d.port
}

// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func (d *DialWrap) dialSerial(ctx context.Context, ras []net.IP, network, port string) (net.Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for _, ra := range ras {
		select {
		case <-ctx.Done():
			// improve this error message
			return nil, ctx.Err()
		default:
		}

		c, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(ra.String(), port))
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = errkit.Wrap(net.UnknownNetworkError(network), "dialSerial")
	}
	return nil, firstErr
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

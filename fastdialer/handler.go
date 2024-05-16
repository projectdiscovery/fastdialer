package fastdialer

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/fastdialer/fastdialer/cache"
	"github.com/projectdiscovery/utils/errkit"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"go.uber.org/multierr"
)

// temporary struct to store dial results
type dialResult struct {
	conn net.Conn
	err  error
	ip   string
}

// Close closes the connection
func (d *dialResult) Close() {
	if d.conn != nil {
		_ = d.conn.Close()
	}
}

// L4HandlerOpts contains options for managing and pooling
// layer 4 connections to a particular address
type L4HandlerOpts struct {
	// PoolSize is the size of connection pool to maintain
	// if any more connections are created, they are closed
	PoolSize int
}

// l4ConnHandler handles dial requests to a particular address
// and handles pooling of connections and more
type l4ConnHandler struct {
	// fastdialer instance to use for dialing
	fd *Dialer
	// firstFlight returns true if this is the first dial request for this address
	firstFlight *atomic.Bool
	// address
	hostname string
	// port
	port string
	// network to use for dialing
	network string
	// ips to dial
	ips []string
	// bag of connections
	bag *cache.Bag[*dialResult]
	// permaError is a permanent error for this handler
	// this only happens when all ips:[port] are dead or unreachable
	permaError error
	// m protects the ips slice
	m sync.Mutex
}

// getDialHandler returns a new dialHandler instance for the given address or returns an existing one
func (fd *Dialer) getDialHandler(ctx context.Context, hostname, network, port string, ips []string) (*l4ConnHandler, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	key := network + ":" + hostname + ":" + port
	// if handler already exists for this address, return it no need to create a new one
	if h, err := fd.l4HandlerCache.GetIFPresent(key); !errkit.Is(err, gcache.KeyNotFoundError) && h != nil {
		return h, nil
	}

	fd.m.Lock()
	defer fd.m.Unlock()

	// check again if handler was already created by another goroutine
	if h, err := fd.l4HandlerCache.GetIFPresent(key); !errkit.Is(err, gcache.KeyNotFoundError) && h != nil {
		return h, nil
	}

	handlerOpts := L4HandlerOpts{
		PoolSize: fd.options.MaxPooledConnPerHandler,
	}
	// while creating new handler always check for preferred options from
	// context
	opts, ok := ctx.Value(L4HandlerOpts{}).(L4HandlerOpts)
	if !ok {
		if opts.PoolSize > 0 {
			handlerOpts.PoolSize = opts.PoolSize
		}
	}

	h := &l4ConnHandler{
		fd:          fd,
		hostname:    hostname,
		network:     network,
		port:        port,
		firstFlight: &atomic.Bool{},
		ips:         ips,
		bag:         cache.NewBag[*dialResult](handlerOpts.PoolSize),
	}
	h.firstFlight.Store(true)
	// put this handler in cache
	if err := fd.l4HandlerCache.Set(key, h); err != nil {
		return nil, err
	}
	return h, nil
}

// getKey returns a key for the handler
func (d *l4ConnHandler) getKey() string {
	return d.network + ":" + d.hostname + ":" + d.port
}

// ips return a copy of ips
func (d *l4ConnHandler) getIps() []string {
	d.m.Lock()
	defer d.m.Unlock()
	return sliceutil.Clone(d.ips)
}

// updateIps updates the ips for the handler
func (d *l4ConnHandler) updateIps(ips []string) {
	d.m.Lock()
	defer d.m.Unlock()
	d.ips = ips
}

// getPermaError returns the permanent error for the handler
func (d *l4ConnHandler) getPermaError() error {
	d.m.Lock()
	defer d.m.Unlock()
	return d.permaError
}

// setPermaError sets the permanent error for the handler
func (d *l4ConnHandler) setPermaError(err error) {
	d.m.Lock()
	defer d.m.Unlock()
	d.permaError = err
}

// dialFirst performs the first dial to the address
// and stored results to be used by other dials
func (d *l4ConnHandler) dialFirst(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, err, _ := d.fd.group.Do(d.getKey(), func() (interface{}, error) {
		errX := d.dialAllParallel(ctx)
		if errX != nil {
			if errkit.IsDeadlineErr(errX) {
				return false, errkit.WithAttr(errX, slog.Any("hostname", d.hostname), slog.Any("port", d.port))
			}
			return false, errkit.Append(errkit.WithAttr(CouldNotConnectError, slog.Any("hostname", d.hostname), slog.Any("port", d.port)), errX)
		}
		return true, nil
	})
	d.firstFlight.Store(false)
	return err
}

// dialAllParallel dials to all ip addresses in parallel and returns error if all of them failed
// if any of them succeeded, it puts them in initChan to be used by immediate calls
func (d *l4ConnHandler) dialAllParallel(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	ch := make(chan dialResult, len(d.ips))
	go func() {
		defer close(ch)
		var wg sync.WaitGroup

		defer func() {
			if ctx.Err() != nil {
				return
			}
			wg.Wait()
		}()

		for _, ip := range d.getIps() {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				if ctx.Err() != nil {
					return
				}

				d.fd.acquire() // no-op if max open connections is not set
				conn, err := d.fd.simpleDialer.Dial(ctx, d.network, net.JoinHostPort(ip, d.port))
				conn = d.fd.releaseWithHook(conn)
				select {
				case ch <- dialResult{conn, err, ip}:
				case <-ctx.Done():
					if conn != nil {
						_ = conn.Close()
					}
					return
				}
			}(ip)
		}
	}()

	var err error
	results := []dialResult{}

loop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res, ok := <-ch:
			if !ok {
				break loop
			}
			if res.err != nil {
				err = multierr.Append(err, res.err)
				continue loop
			}
			results = append(results, res)
		}
	}

	if !d.firstFlight.Load() {
		// if all failed return error
		if len(results) == 0 {
			return err
		}
		// if this is not first flight then put all successful connections in bag
		for _, res := range results {
			d.bag.Put(&res)
		}
		return nil
	}

	// if it is first flight then do more processing
	if len(results) == 0 {
		if errkit.IsNetworkPermanentErr(err) {
			// most likely a permanent error
			d.setPermaError(err)
		}
		return err
	}

	alive := []string{}
	for _, res := range results {
		alive = append(alive, res.ip)
		tmp := res
		d.bag.Put(&tmp)
	}
	d.updateIps(alive)
	return nil
}

// getConn returns a connection to the address
func (d *l4ConnHandler) getConn(ctx context.Context) (net.Conn, string, error) {
	// if this is a first flight use singleflight
	if d.firstFlight.Load() {
		// dialFirst will perform preflight dial to all ips
		// and removes dead ips and reuses already created connections
		// this will block all concurrent calls to dialFirst until first dial is complete
		err := d.dialFirst(ctx)
		if err != nil {
			return nil, "", err
		}
	}

	// check if there is a permanent error
	if err := d.getPermaError(); err != nil {
		return nil, "", err
	}

	// try to get one from a bag
	result, err := d.bag.Get()
	if err != nil && errkit.Is(err, cache.ErrNoItemsInBag) {
		// if bag is empty, dial to all ips and return one
		err = d.dialAllParallel(ctx)
		if err != nil {
			return nil, "", err
		}
		// pick new connection in next iteration
		return d.getConn(ctx)
	}
	return result.conn, result.ip, result.err
}

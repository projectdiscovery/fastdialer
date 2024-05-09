package fastdialer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Mzack9999/gcache"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

// L4HandlerOpts contains options for managing and pooling
// layer 4 connections to a particular address
type L4HandlerOpts struct {
	// PoolSize is the size of connection pool to maintain
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
	// ctx for l4handler
	ctx context.Context
	// cancel function for l4handler
	cancel context.CancelFunc
	// poolingChan is the channel that continiously dials to the address
	// and stores the results in the cache
	poolingChan chan dialResult
	// initChan contains intial dial results
	initChan chan dialResult
}

// temporary struct to store dial results
type dialResult struct {
	conn net.Conn
	err  error
	ip   string
}

// getDialHandler returns a new dialHandler instance for the given address or returns an existing one
func getDialHandler(ctx context.Context, fd *Dialer, hostname, network, port string, ips []string) (*l4ConnHandler, error) {
	// if handler already exists for this address, return it no need to create a new one
	if h, err := fd.l4HandlerCache.GetIFPresent(network + ":" + hostname + ":" + port); !errors.Is(err, gcache.KeyNotFoundError) && h != nil {
		return h, nil
	}

	handlerOpts := L4HandlerOpts{
		PoolSize: 3,
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
		poolingChan: make(chan dialResult, 3), // cache 3 connections
		ips:         ips,
	}
	h.firstFlight.Store(true)

	// Note: this context should not be tied/inherited from connection/dial
	// context since it's lifetime is limited to dialing only
	// so this context should be inherited from fastdialer instance context
	// if it has any
	ctx, cancel := context.WithCancel(context.TODO())
	h.cancel = cancel
	h.ctx = ctx
	go h.run(ctx)

	// put this handler in cache
	if err := fd.l4HandlerCache.Set(network+":"+hostname+":"+port, h); err != nil {
		cancel()
		return nil, err
	}

	return h, nil
}

// dialFirst performs the first dial to the address
// and stored results to be used by other dials
func (d *l4ConnHandler) dialFirst(ctx context.Context) error {
	_, err, _ := d.fd.group.Do(d.hostname+":"+d.port, func() (interface{}, error) {
		errX := d.dialAllParallel(ctx)
		if errX != nil {
			return false, errX
		}
		return true, nil
	})
	d.firstFlight.Store(false)
	return err
}

// dialAllParallel dials to all ip addresses in parallel and returns error if all of them failed
// if any of them succeeded, it puts them in initChan to be used by immediate calls
func (d *l4ConnHandler) dialAllParallel(ctx context.Context) error {
	ch := make(chan dialResult, len(d.ips))
	go func() {
		var wg sync.WaitGroup
		defer close(ch)
		defer wg.Wait()

		alive := []string{}

		for _, ip := range d.ips {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				conn, err := d.fd.simpleDialer.Dial(ctx, d.network, net.JoinHostPort(ip, d.port))
				ch <- dialResult{conn, err, ip}
				if err == nil {
					alive = append(alive, ip)
				}
			}(ip)
		}
		wg.Wait()
		// only store alive ips
		d.ips = alive
	}()

	var err error
	idle := []net.Conn{}

	for res := range ch {
		if res.err != nil {
			err = multierr.Append(err, res.err)
			continue
		}
		// put conn in cache
		idle = append(idle, res.conn)
	}
	if len(idle) == 0 {
		return err
	}
	// put all in initChan
	d.initChan = make(chan dialResult, len(idle))
	for _, conn := range idle {
		d.initChan <- dialResult{conn: conn}
	}
	return nil
}

// run continiously dials to the address and stores the results in the cache
// it runs in background and is used by getConn to get connections
func (d *l4ConnHandler) run(ctx context.Context) {
	defer close(d.poolingChan)
	defer close(d.initChan)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// dial new conn and put it in buffered chan
			conn, err := d.fd.simpleDialer.Dial(ctx, d.network, net.JoinHostPort(d.hostname, d.port))
			d.poolingChan <- dialResult{conn, err, d.hostname}
		}
	}
}

// getConn returns a connection to the address
func (d *l4ConnHandler) getConn(ctx context.Context) (net.Conn, string, error) {
	// if this is a first flight use singleflight
	if d.firstFlight.Load() {
		err := d.dialFirst(ctx)
		if err != nil {
			return nil, "", err
		}
	}

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case res := <-d.initChan:
		return res.conn, res.ip, res.err
	case res := <-d.poolingChan:
		return res.conn, res.ip, res.err
	}
}

// Close closes the dial handler
func (d *l4ConnHandler) Close() {
	d.cancel()
}

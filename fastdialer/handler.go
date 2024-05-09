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
	poolingChan chan *dialResult
	// initChan contains intial dial results
	initChan chan *dialResult
	// synchronize initChan etc to avoid parallel data race
	m sync.Mutex
}

// temporary struct to store dial results
type dialResult struct {
	conn net.Conn
	err  error
	ip   string
}

// getDialHandler returns a new dialHandler instance for the given address or returns an existing one
func getDialHandler(ctx context.Context, fd *Dialer, hostname, network, port string, ips []string) (*l4ConnHandler, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// if handler already exists for this address, return it no need to create a new one
	if h, err := fd.l4HandlerCache.GetIFPresent(network + ":" + hostname + ":" + port); !errors.Is(err, gcache.KeyNotFoundError) && h != nil {
		return h, nil
	}

	handlerOpts := L4HandlerOpts{
		PoolSize: fd.options.MaxL4ConnsPrefetchSize,
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
		poolingChan: make(chan *dialResult, handlerOpts.PoolSize), // cache size
		ips:         ips,
	}
	h.firstFlight.Store(true)

	// Note: this context should not be tied/inherited from connection/dial
	// context since it's lifetime is limited to dialing only
	// so this context should be inherited from fastdialer instance context
	// if it has any
	ctx, cancel := context.WithCancel(fd.ctx)
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
	if ctx.Err() != nil {
		return ctx.Err()
	}
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
	if ctx.Err() != nil {
		return ctx.Err()
	}

	ch := make(chan dialResult, len(d.ips))
	go func() {
		defer close(ch)
		var wg sync.WaitGroup
		alive := []string{}

		defer func() {
			if ctx.Err() != nil {
				return
			}
			wg.Wait()
			// only store alive ips
			d.m.Lock()
			d.ips = alive
			d.m.Unlock()
		}()

		for _, ip := range d.ips {
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
				if err == nil {
					d.m.Lock()
					alive = append(alive, ip)
					d.m.Unlock()
				}
			}(ip)
		}
	}()

	var err error
	idle := []net.Conn{}

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
				continue
			}
			// put conn in cache
			idle = append(idle, res.conn)
		}
	}

	if len(idle) == 0 {
		return err
	}
	// put all in initChan
	d.m.Lock()
	d.initChan = make(chan *dialResult, len(idle))
	d.m.Unlock()
	for _, conn := range idle {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d.initChan <- &dialResult{conn: conn}:
		}
	}
	return nil
}

// run continiously dials to the address and stores the results in the cache
// it runs in background and is used by getConn to get connections
func (d *l4ConnHandler) run(ctx context.Context) {
	defer func() {
		d.m.Lock()
		close(d.poolingChan)
		if d.initChan != nil {
			close(d.initChan)
		}
		d.m.Unlock()
	}()

	var lastResult *dialResult
	index := 0

	d.m.Lock()
	ips := d.ips
	d.m.Unlock()

	for {
		select {
		case <-ctx.Done():
			if lastResult != nil && lastResult.conn != nil {
				_ = lastResult.conn.Close()
			}
			return
		case d.poolingChan <- lastResult:

		default:
			// reset index if it is out of bounds
			if index >= len(ips) {
				index = 0
			}
			ip := ips[index]

			// dial new conn and put it in buffered chan
			d.fd.acquire() // no-op if max open connections is not set
			conn, err := d.fd.simpleDialer.Dial(ctx, d.network, net.JoinHostPort(ip, d.port))
			conn = d.fd.releaseWithHook(conn)
			// this is to avoid blocking when context is cancelled
			lastResult = &dialResult{conn, err, ip}
			index++
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
	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case res := <-d.initChan:
			if res == nil {
				continue
			}
			return res.conn, res.ip, res.err
		case res := <-d.poolingChan:
			if res == nil {
				continue
			}
			return res.conn, res.ip, res.err
		}
	}
}

// Close closes the dial handler
func (d *l4ConnHandler) Close() {
	d.cancel()
}

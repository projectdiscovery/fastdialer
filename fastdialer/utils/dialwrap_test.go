package utils

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The caller that starts the first connection must get that connection back.
// The completion signal can be observed before the connection is handed over,
// and dialing again then leaves the first connection open and unused, so a
// server accepting a single connection serves the one nobody talks on.
func TestDialWrapFirstDialOpensOneConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	wrap, err := NewDialWrap(&net.Dialer{}, []string{host}, "tcp", listener.Addr().String(), port)
	require.NoError(t, err)
	// the interleaving a loaded scheduler produces: completion is visible
	// while the first connection is still on its way to the caller
	wrap.completedFirstConnection.Store(true)

	conn, err := wrap.DialContext(context.Background(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.Eventually(t, func() bool { return accepted.Load() >= 1 }, 5*time.Second, 10*time.Millisecond)
	// give an extra connection time to be accepted before counting
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, 1, accepted.Load())
}

// Concurrent callers on a new DialWrap that all hit a closed port share one
// first dial (#666). If two callers each started one, they would make two
// connect attempts and could read d.err while the other first dial writes it.
// -race reports that read; without it, the connect count still shows the
// extra dial, though only on some runs.
func TestDialWrapConcurrentFirstDialsToClosedPort(t *testing.T) {
	t.Parallel()

	const (
		rounds  = 500
		callers = 5
	)

	// take a free port and close it, so every dial is refused
	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	for round := range rounds {
		var attempts atomic.Int64

		var dialer net.Dialer

		dialer.Timeout = 5 * time.Second
		dialer.Control = func(string, string, syscall.RawConn) error {
			attempts.Add(1)

			return nil
		}

		wrap, err := NewDialWrap(&dialer, []string{"127.0.0.1"}, "tcp", addr, port)
		require.NoError(t, err)

		errs := make([]error, callers)
		start := make(chan struct{})

		var done sync.WaitGroup
		for caller := range callers {
			done.Go(func() {
				<-start

				conn, err := wrap.DialContext(context.Background(), "tcp", addr)
				if conn != nil {
					_ = conn.Close()
				}

				errs[caller] = err
			})
		}

		close(start)
		done.Wait()

		for _, err := range errs {
			require.ErrorIs(t, err, ErrPortClosedOrFiltered, "round %d", round)
		}

		require.EqualValues(t, 1, attempts.Load(), "round %d: every caller must share one first dial", round)
	}
}

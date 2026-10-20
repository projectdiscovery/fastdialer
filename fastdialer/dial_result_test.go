package fastdialer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type dialResultKey struct{}

type dialResult struct {
	tag            any
	hostname, port string
	err            error
}

func TestOnDialResultReportsEachConnectionAttempt(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	var mu sync.Mutex
	var results []dialResult
	options := DefaultOptions
	options.DialerTimeout = 2 * time.Second
	options.OnDialResult = func(ctx context.Context, hostname, port string, err error) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, dialResult{tag: ctx.Value(dialResultKey{}), hostname: hostname, port: port, err: err})
	}
	dialer, err := NewDialer(options)
	require.NoError(t, err)
	defer dialer.Close()

	// the caller's context reaches the callback, so it can tell its own dials apart
	ctx := context.WithValue(context.Background(), dialResultKey{}, "scan")
	conn, err := dialer.Dial(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err)
	_ = conn.Close()

	require.NoError(t, listener.Close())
	_, err = dialer.Dial(ctx, "tcp", listener.Addr().String())
	require.Error(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, results, 2)
	require.Equal(t, dialResult{tag: "scan", hostname: "127.0.0.1", port: port}, results[0])
	require.Equal(t, "scan", results[1].tag)
	require.Equal(t, "127.0.0.1", results[1].hostname)
	require.Equal(t, port, results[1].port)
	require.Error(t, results[1].err)
}

// A target that never got as far as a connection attempt is not reported:
// nothing was asked of the host.
func TestOnDialResultSkipsTargetsNeverDialed(t *testing.T) {
	called := false
	options := DefaultOptions
	options.OnDialResult = func(context.Context, string, string, error) { called = true }
	dialer, err := NewDialer(options)
	require.NoError(t, err)
	defer dialer.Close()

	_, err = dialer.Dial(context.Background(), "tcp", "127.0.0.1")
	require.ErrorIs(t, err, NoPortSpecifiedError)
	require.False(t, called)
}

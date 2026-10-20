package fastdialer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
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

// nilAddrConn reports no remote address.
type nilAddrConn struct{ net.Conn }

func (nilAddrConn) RemoteAddr() net.Addr { return nil }

type nilAddrProxy struct{ conn net.Conn }

func (p *nilAddrProxy) Dial(network, addr string) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	p.conn = nilAddrConn{Conn: client}
	return p.conn, nil
}

// A connection with no remote address is a failed dial, so the callback
// reports that error rather than a success.
func TestOnDialResultReportsMissingRemoteAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	pdialer := &nilAddrProxy{}
	t.Cleanup(func() {
		if pdialer.conn != nil {
			_ = pdialer.conn.Close()
		}
	})
	var pd proxy.Dialer = pdialer
	var got error
	options := DefaultOptions
	options.ProxyDialer = &pd
	options.OnDialResult = func(_ context.Context, _, _ string, err error) { got = err }

	dialer, err := NewDialer(options)
	require.NoError(t, err)
	defer dialer.Close()

	conn, err := dialer.Dial(context.Background(), "tcp", listener.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
	require.Contains(t, err.Error(), "remote address is nil")
	require.Equal(t, err, got)
}

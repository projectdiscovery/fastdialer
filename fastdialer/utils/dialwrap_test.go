package utils

import (
	"context"
	"net"
	"sync/atomic"
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

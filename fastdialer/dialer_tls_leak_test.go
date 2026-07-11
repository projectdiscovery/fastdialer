package fastdialer

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestDialTLSHandshakeFailureNoGoroutineLeak ensures a failed TLS handshake
// does not leak goroutines. The handshake timeout is now enforced via a
// connection deadline rather than a per handshake watchdog goroutine, so a
// burst of fast handshake failures must not grow the goroutine count.
func TestDialTLSHandshakeFailureNoGoroutineLeak(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// accept then immediately close so the client TLS handshake fails fast
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	addr := ln.Addr().String()
	ctx := context.Background()

	// warm up lazy/background goroutines before measuring the baseline
	if conn, err := d.DialTLS(ctx, "tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatalf("expected tls handshake to fail against a closing server")
	}

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	const n = 40
	for i := 0; i < n; i++ {
		conn, err := d.DialTLS(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("expected tls handshake to fail against a closing server")
		}
	}

	// measure promptly: leaked watchdogs live for GetTimeout (default 10s),
	// so without the cancel-on-error fix ~n goroutines would still be alive here
	runtime.GC()
	after := runtime.NumGoroutine()
	if after-base > n/2 {
		t.Fatalf("goroutine leak after %d failed tls handshakes: base=%d after=%d", n, base, after)
	}
}

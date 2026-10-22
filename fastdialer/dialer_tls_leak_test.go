package fastdialer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
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
	defer func() { _ = ln.Close() }()

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

// A dial whose identity utls rejects must close its connection (#608).
func TestDialTLSWithConfigImpersonateClosesConnOnInvalidIdentity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	// utls supports at most two GREASE extensions
	identity := &impersonate.Identity{
		TLSVersMin: tls.VersionTLS12,
		TLSVersMax: tls.VersionTLS12,
		Extensions: []utls.TLSExtension{&utls.UtlsGREASEExtension{}, &utls.UtlsGREASEExtension{}, &utls.UtlsGREASEExtension{}},
	}
	conn, err := d.DialTLSWithConfigImpersonate(context.Background(), "tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}, impersonate.Custom, identity)
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial succeeded with an identity that utls rejects")
	}

	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never connected")
	}
	defer func() { _ = server.Close() }()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server read: %v, want EOF from a closed connection", err)
	}
}

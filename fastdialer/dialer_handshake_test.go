package fastdialer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// recordConn captures the deadline passed to SetDeadline so the helper logic can
// be asserted without a real network connection.
type recordConn struct {
	net.Conn
	deadline time.Time
}

func (r *recordConn) SetDeadline(t time.Time) error {
	r.deadline = t
	return nil
}

func TestSetHandshakeDeadline(t *testing.T) {
	// GetTimeout clamps DialerTimeout to [1s, 1m]; 5s stays 5s.
	d := &Dialer{options: &Options{DialerTimeout: 5 * time.Second}}

	t.Run("dialer timeout when ctx has no deadline", func(t *testing.T) {
		rc := &recordConn{}
		before := time.Now()
		clear := d.setHandshakeDeadline(context.Background(), rc)
		if got := rc.deadline.Sub(before); got < 4*time.Second || got > 6*time.Second {
			t.Fatalf("expected ~5s deadline, got %v", got)
		}
		clear()
		if !rc.deadline.IsZero() {
			t.Fatalf("expected deadline cleared, got %v", rc.deadline)
		}
	})

	t.Run("earlier ctx deadline wins", func(t *testing.T) {
		rc := &recordConn{}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ctxDl, _ := ctx.Deadline()
		clear := d.setHandshakeDeadline(ctx, rc)
		defer clear()
		if diff := rc.deadline.Sub(ctxDl); diff < -50*time.Millisecond || diff > 50*time.Millisecond {
			t.Fatalf("expected ctx deadline honored, diff=%v", diff)
		}
	})

	t.Run("later ctx deadline ignored", func(t *testing.T) {
		rc := &recordConn{}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		before := time.Now()
		clear := d.setHandshakeDeadline(ctx, rc)
		defer clear()
		if got := rc.deadline.Sub(before); got > 6*time.Second {
			t.Fatalf("expected dialer timeout (~5s) to win, got %v", got)
		}
	})
}

// TestDialTLSContextDeadlineHonored verifies a short ctx deadline aborts a stalled
// handshake well before the (much larger) dialer timeout would.
func TestDialTLSContextDeadlineHonored(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// accept but never send a ServerHello so the client handshake stalls
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()

	opts := DefaultOptions
	opts.DialerTimeout = 30 * time.Second
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := d.DialTLS(ctx, "tcp", ln.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected handshake to fail on ctx deadline")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("ctx deadline not honored, took %v (dialer timeout was 30s)", elapsed)
	}
}

// TestDialTLSClearsHandshakeDeadlineOnSuccess guards the main risk of the deadline
// based approach: after a successful handshake the connection deadline must be
// cleared, otherwise the first read past the handshake window fails spuriously.
func TestDialTLSClearsHandshakeDeadlineOnSuccess(t *testing.T) {
	ln := newDelayedTLSServer(t)
	defer ln.Close()

	opts := DefaultOptions
	opts.DialerTimeout = 100 * time.Millisecond // GetTimeout clamps to 1s
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	conn, err := d.DialTLS(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer conn.Close()

	// the handshake deadline was ~now+1s; the server replies only after 1.5s, so a
	// leftover deadline would surface here as an i/o timeout.
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read after handshake failed (stale deadline?): %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 byte, got %d", n)
	}
}

// newDelayedTLSServer starts a TLS server that completes the handshake then stays
// idle for 1.5s before sending a byte, used to detect a leftover handshake deadline.
func newDelayedTLSServer(t *testing.T) net.Listener {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(1500 * time.Millisecond)
				_, _ = c.Write([]byte("x"))
				_ = c.Close()
			}(c)
		}
	}()
	return ln
}

func newTLSEchoServer(t testing.TB) (addr string, closeFn func()) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	return ts.Listener.Addr().String(), ts.Close
}

// TestSuccessfulHandshakeNoExtraGoroutine verifies that successful TLS handshakes
// do not leave a watchdog goroutine behind: the deadline based timeout adds no
// per handshake goroutine.
func TestSuccessfulHandshakeNoExtraGoroutine(t *testing.T) {
	addr, stop := newTLSEchoServer(t)
	defer stop()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	conn, err := d.DialTLS(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("warmup handshake failed: %v", err)
	}
	_ = conn.Close()

	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	base := runtime.NumGoroutine()

	const n = 40
	for i := 0; i < n; i++ {
		conn, err := d.DialTLS(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("handshake %d failed: %v", i, err)
		}
		_ = conn.Close()
	}

	runtime.GC()
	if after := runtime.NumGoroutine(); after-base > n/2 {
		t.Fatalf("goroutine growth after %d successful handshakes: base=%d after=%d", n, base, after)
	}
}

func BenchmarkDialTLSHandshake(b *testing.B) {
	addr, stop := newTLSEchoServer(b)
	defer stop()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		b.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := d.DialTLS(ctx, "tcp", addr)
		if err != nil {
			b.Fatalf("handshake failed: %v", err)
		}
		_ = conn.Close()
	}
}

// benchWatchdogOld mirrors the removed closeAfterTimeout implementation so the
// per handshake overhead it added (a goroutine plus two contexts) can be
// compared against the new deadline based arming below.
func benchWatchdogOld(d time.Duration) func() {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	doneCtx, doneCancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
		case <-doneCtx.Done():
		}
	}()
	return func() {
		doneCancel()
		cancel()
	}
}

type benchDeadlineConn struct{}

func (benchDeadlineConn) SetDeadline(t time.Time) error { return nil }

func BenchmarkHandshakeTimeoutWatchdogOld(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cancel := benchWatchdogOld(time.Second)
		cancel()
	}
}

func BenchmarkHandshakeTimeoutDeadlineNew(b *testing.B) {
	var c benchDeadlineConn
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_ = c.SetDeadline(time.Time{})
	}
}

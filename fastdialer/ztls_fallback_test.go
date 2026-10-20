package fastdialer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/proxy"
)

// errProxyDown is the error returned by [failingProxy].
var errProxyDown = errors.New("proxy is down")

// failingProxy is a [proxy.Dialer] whose Dial always fails.
type failingProxy struct{}

func (failingProxy) Dial(network, addr string) (net.Conn, error) {
	return nil, errProxyDown
}

// settle gives the server side time to observe connections the client has
// already dropped, so that "no connection" assertions can't pass by racing.
func settle() { time.Sleep(200 * time.Millisecond) }

func newFallbackTestDialer(t *testing.T, mutate func(*Options)) *Dialer {
	t.Helper()
	options := DefaultOptions
	options.DialerTimeout = 5 * time.Second
	if mutate != nil {
		mutate(&options)
	}
	dialer, err := NewDialer(options)
	if err != nil {
		t.Fatalf("could not create dialer: %v", err)
	}
	t.Cleanup(dialer.Close)
	return dialer
}

// newRSAOnlyServer starts a TLS 1.2 server that only accepts
// TLS_RSA_WITH_AES_128_GCM_SHA256, and counts the connections it accepts.
func newRSAOnlyServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	conns := &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, conns
}

// ecdheOnlyConfig is a client config that shares no cipher suite with the
// server from [newRSAOnlyServer], so crypto/tls fails with "handshake failure".
func ecdheOnlyConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}

func hostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

// countingListener accepts connections and closes them right away.
func countingListener(t *testing.T) (addr string, conns *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), conns
}

// A plain dial through a failing proxy must return the proxy's error and must
// not reach the target directly (#613).
func TestPlainDialDoesNotBypassProxy(t *testing.T) {
	var pd proxy.Dialer = failingProxy{}
	dialer := newFallbackTestDialer(t, func(o *Options) { o.ProxyDialer = &pd })

	tlsSrv, tlsConns := newRSAOnlyServer(t)
	rawAddr, rawConns := countingListener(t)

	targets := []struct {
		name  string
		addr  string
		conns *atomic.Int32
	}{
		{"TLSServer", hostPort(t, tlsSrv), tlsConns},
		{"RawTCPServer", rawAddr, rawConns},
	}
	for _, tt := range targets {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := dialer.Dial(context.Background(), "tcp", tt.addr)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatalf("expected the proxy error, got a %T and nil error", conn)
			}
			if !strings.Contains(err.Error(), errProxyDown.Error()) {
				t.Fatalf("expected the proxy error %q, got: %v", errProxyDown, err)
			}
			settle()
			if n := tt.conns.Load(); n != 0 {
				t.Fatalf("target accepted %d connection(s), want 0 (proxy bypassed)", n)
			}
		})
	}
}

// A crypto/tls handshake failure on a config that does not authenticate the
// server falls back to ztls (#614).
func TestDialTLSFallsBackToZTLS(t *testing.T) {
	srv, conns := newRSAOnlyServer(t)
	dialer := newFallbackTestDialer(t, nil)

	conn, err := dialer.DialTLSWithConfig(context.Background(), "tcp", hostPort(t, srv), ecdheOnlyConfig())
	if err != nil {
		t.Fatalf("expected the ztls fallback to connect, got: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, ok := conn.(*ztls.Conn); !ok {
		t.Fatalf("expected *ztls.Conn, got %T", conn)
	}
	if n := conns.Load(); n != 2 {
		t.Fatalf("server saw %d connection(s), want 2 (crypto/tls, then ztls)", n)
	}
}

// Configs that authenticate the server must not fall back: AsZTLSConfig drops
// RootCAs and the verification callbacks (#614).
func TestDialTLSNoFallbackWhenVerifying(t *testing.T) {
	srv, conns := newRSAOnlyServer(t)
	dialer := newFallbackTestDialer(t, nil)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	tests := map[string]*tls.Config{
		"RootCAs": {
			RootCAs:      pool,
			ServerName:   "example.com",
			CipherSuites: ecdheOnlyConfig().CipherSuites,
		},
		"VerifyPeerCertificate": {
			InsecureSkipVerify: true,
			CipherSuites:       ecdheOnlyConfig().CipherSuites,
			VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
				return nil
			},
		},
		"VerifyConnection": {
			InsecureSkipVerify: true,
			CipherSuites:       ecdheOnlyConfig().CipherSuites,
			VerifyConnection: func(tls.ConnectionState) error {
				return nil
			},
		},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			conns.Store(0)
			conn, err := dialer.DialTLSWithConfig(context.Background(), "tcp", hostPort(t, srv), cfg)
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatalf("expected a handshake error, got a %T", conn)
			}
			settle()
			if n := conns.Load(); n != 1 {
				t.Fatalf("server saw %d connection(s), want exactly 1 (no fallback)", n)
			}
		})
	}
}

// The fallback runs only when a ztls retry can reach a server that crypto/tls
// couldn't, and keeps the server checks, client certificate and ECH settings
// of the config. Every tls.Config field is classified, so a field added by a
// later Go release fails this test until it is.
func TestCanFallbackToZTLS(t *testing.T) {
	dialer := newFallbackTestDialer(t, nil)
	handshakeErr := errors.New("tls: handshake failure")
	allowed := func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
	if !dialer.canFallbackToZTLS(context.Background(), allowed(), handshakeErr) {
		t.Fatal("a config that doesn't verify the server should fall back")
	}

	// fields that block the fallback, set as a caller would
	blocking := map[string]func(*tls.Config){
		"InsecureSkipVerify": func(c *tls.Config) { c.InsecureSkipVerify = false },
		"VerifyPeerCertificate": func(c *tls.Config) {
			c.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		},
		"VerifyConnection": func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { return nil }
		},
		"Certificates": func(c *tls.Config) { c.Certificates = []tls.Certificate{{Certificate: [][]byte{{1}}}} },
		"GetClientCertificate": func(c *tls.Config) {
			c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }
		},
		"EncryptedClientHelloConfigList": func(c *tls.Config) { c.EncryptedClientHelloConfigList = []byte{1} },
		"EncryptedClientHelloRejectionVerify": func(c *tls.Config) {
			c.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }
		},
		// only from TLS 1.3, which leaves no older version or cipher to retry with
		"MinVersion": func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 },
	}
	nonBlocking := []string{
		// carried over by AsZTLSConfig
		"NextProtos", "ServerName", "ClientAuth", "SessionTicketsDisabled", "MaxVersion",
		// replaced by ztls.ChromeCiphers and the default ztls curves, which
		// is what lets the retry reach servers that crypto/tls rejects
		"CipherSuites", "CurvePreferences",
		// only verify the server, which InsecureSkipVerify turns off
		"RootCAs", "Time",
		// dropped without weakening the connection
		"Rand", "ClientSessionCache", "DynamicRecordSizingDisabled", "Renegotiation", "KeyLogWriter",
		// server only
		"NameToCertificate", "GetCertificate", "GetConfigForClient", "ClientCAs", "PreferServerCipherSuites",
		"SessionTicketKey", "UnwrapSession", "WrapSession", "GetEncryptedClientHelloKeys", "EncryptedClientHelloKeys",
	}
	for name, set := range blocking {
		cfg := allowed()
		set(cfg)
		if dialer.canFallbackToZTLS(context.Background(), cfg, handshakeErr) {
			t.Errorf("%s: should not fall back", name)
		}
	}
	config := reflect.TypeOf(tls.Config{})
	for i := range config.NumField() {
		field := config.Field(i)
		if !field.IsExported() {
			continue
		}
		if _, blocks := blocking[field.Name]; blocks == slices.Contains(nonBlocking, field.Name) {
			t.Errorf("%s: classify it once, as blocking the fallback or not", field.Name)
		}
	}

	// a retry can't help after these
	for name, err := range map[string]error{
		"not TLS": tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
		"timeout": os.ErrDeadlineExceeded,
	} {
		if dialer.canFallbackToZTLS(context.Background(), allowed(), err) {
			t.Errorf("%s: should not fall back", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if dialer.canFallbackToZTLS(ctx, allowed(), handshakeErr) {
		t.Error("done context: should not fall back")
	}
}

// When the ztls retry fails too, the error keeps the crypto/tls failure.
func TestDialTLSFallbackKeepsHandshakeError(t *testing.T) {
	conns := &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	dialer := newFallbackTestDialer(t, nil)

	cfg := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}
	conn, err := dialer.DialTLSWithConfig(context.Background(), "tcp", hostPort(t, srv), cfg)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected both handshakes to fail")
	}
	for _, want := range []string{"could not tls handshake", "ztls fallback failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't contain %q", err, want)
		}
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("server saw %d connection(s), want 2 (crypto/tls, then ztls)", n)
	}
}

// A failed ztls handshake must not leave the connection open.
func TestDialZTLSClosesConnOnHandshakeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// not a TLS record: the client handshake fails, then we wait for the
		// client to hang up.
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()

	// a long timeout, so closeAfterTimeout can't be what closes the conn.
	dialer := newFallbackTestDialer(t, func(o *Options) { o.DialerTimeout = time.Minute })
	conn, err := dialer.DialZTLSWithConfig(context.Background(), "tcp", ln.Addr().String(), DefaultZTLSConfig)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected a handshake error")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("connection still open after failed ztls handshake")
	}
}

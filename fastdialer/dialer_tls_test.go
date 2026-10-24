package fastdialer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// newTLSServer starts an HTTPS server with cfg. Its responses report how many
// certificates the client sent, whether the session resumed, and the SNI.
func newTLSServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "certs=%d resumed=%t sni=%s", len(r.TLS.PeerCertificates), r.TLS.DidResume, r.TLS.ServerName)
	}))
	srv.TLS = cfg
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// httpGet sends a request over conn, closes it, and returns the response body.
func httpGet(conn net.Conn) (string, error) {
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)

	return string(body), err
}

// newClientCert returns a self-signed certificate and its key.
func newClientCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return der, key
}

func TestDialZTLSWithConfigSendsCertificates(t *testing.T) {
	srv := newTLSServer(t, &tls.Config{ClientAuth: tls.RequireAnyClientCert})
	addr := srv.Listener.Addr().String()
	der, key := newClientCert(t)

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	for _, minVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(minVersion), func(t *testing.T) {
			cfg := &ztls.Config{
				InsecureSkipVerify: true,
				MinVersion:         minVersion,
				Certificates:       []ztls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			}
			conn, err := d.DialZTLSWithConfig(context.Background(), "tcp", addr, cfg)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			// TLS 1.3 servers check the client certificate after the client
			// finishes its handshake, so a missing one shows up as a read error.
			body, err := httpGet(conn)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if !strings.HasPrefix(body, "certs=1 ") {
				t.Fatalf("server got %q, want one certificate", body)
			}
		})
	}
}

// Options.TLSConfig and Options.ZTLSConfig replace the default configs of
// DialTLS and DialZTLS, and leave the configs passed to WithConfig dials alone.
func TestDialTLSUsesOptionsConfig(t *testing.T) {
	srv := newTLSServer(t, &tls.Config{NextProtos: []string{"from-options", "from-caller"}})
	addr := srv.Listener.Addr().String()

	opts := DefaultOptions
	opts.TLSConfig = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"from-options"}}
	opts.ZTLSConfig = &ztls.Config{InsecureSkipVerify: true, NextProtos: []string{"from-options"}}
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	t.Cleanup(d.Close)

	ctx := context.Background()
	dials := map[string]func() (net.Conn, error){
		"DialTLS":  func() (net.Conn, error) { return d.DialTLS(ctx, "tcp", addr) },
		"DialZTLS": func() (net.Conn, error) { return d.DialZTLS(ctx, "tcp", addr) },
		"DialTLSWithConfig": func() (net.Conn, error) {
			return d.DialTLSWithConfig(ctx, "tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"from-caller"}})
		},
	}
	want := map[string]string{"DialTLS": "from-options", "DialZTLS": "from-options", "DialTLSWithConfig": "from-caller"}
	for name, dial := range dials {
		t.Run(name, func(t *testing.T) {
			conn, err := dial()
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = conn.Close() }()

			var got string
			switch c := conn.(type) {
			case *tls.Conn:
				got = c.ConnectionState().NegotiatedProtocol
			case *ztls.Conn:
				got = c.ConnectionState().NegotiatedProtocol
			default:
				t.Fatalf("unexpected conn type %T", conn)
			}
			if got != want[name] {
				t.Fatalf("negotiated %q, want %q", got, want[name])
			}
		})
	}
}

// DialTLS offers the cipher suites of crypto/tls and http/1.1, and still offers
// TLS 1.0 for old servers.
func TestDialTLSDefaultClientHello(t *testing.T) {
	hellos := make(chan *tls.ClientHelloInfo, 1)
	srv := newTLSServer(t, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			hellos <- chi
			return nil, nil
		},
	})
	d := newFallbackTestDialer(t, nil)

	conn, err := d.DialTLS(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	chi := <-hellos
	if !slices.Equal(chi.SupportedProtos, []string{"http/1.1"}) {
		t.Fatalf("ALPN %q, want [http/1.1]", chi.SupportedProtos)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if slices.Contains(chi.CipherSuites, suite.ID) {
			t.Fatalf("offered insecure cipher suite %s", suite.Name)
		}
	}
	if !slices.Contains(chi.SupportedVersions, tls.VersionTLS10) {
		t.Fatal("TLS 1.0 not offered")
	}
}

// Servers that only accept a legacy cipher suite are reached through the ztls
// fallback.
func TestDialTLSDefaultReachesLegacyCipherServer(t *testing.T) {
	srv := newTLSServer(t, &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	})
	d := newFallbackTestDialer(t, nil)

	conn, err := d.DialTLS(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, ok := conn.(*ztls.Conn); !ok {
		t.Fatalf("got %T, want the ztls fallback connection", conn)
	}
	if _, err := httpGet(conn); err != nil {
		t.Fatalf("request: %v", err)
	}
}

// A non-HTTP server that rejects the http/1.1 of DefaultTLSConfig is retried
// without ALPN, while a caller's own protocols are never dropped.
func TestDialTLSRetriesWithoutRejectedALPN(t *testing.T) {
	srv := newTLSServer(t, nil)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates, NextProtos: []string{"imap"}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()
		}
	}()
	addr := ln.Addr().String()
	d := newFallbackTestDialer(t, nil)

	conn, err := d.DialTLS(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if proto := conn.(*tls.Conn).ConnectionState().NegotiatedProtocol; proto != "" {
		t.Fatalf("negotiated %q, want no ALPN", proto)
	}
	_ = conn.Close()

	config := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	if conn, err := d.DialTLSWithConfig(context.Background(), "tcp", addr, config); err == nil {
		_ = conn.Close()
		t.Fatal("expected the caller's rejected ALPN to fail the dial")
	}
}

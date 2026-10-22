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

package fastdialer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/stretchr/testify/require"
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

func generateTestCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Fastdialer Test"},
		},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func startTestTLSServer(t *testing.T, helloCallback func(h *tls.ClientHelloInfo)) net.Listener {
	cert, err := generateTestCert()
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if helloCallback != nil {
				helloCallback(h)
			}
			return nil, nil
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
				}()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}(conn)
		}
	}()

	return ln
}

func TestDialer_WithModernTLS(t *testing.T) {
	var capturedHello *tls.ClientHelloInfo
	ln := startTestTLSServer(t, func(h *tls.ClientHelloInfo) {
		capturedHello = h
	})
	defer func() {
		_ = ln.Close()
	}()

	opts := DefaultOptions
	opts.WithModernTLS = true
	fd, err := NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	ctx := context.Background()
	conn, err := fd.DialTLS(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	require.NotNil(t, capturedHello)
	require.Equal(t, []string{"h2", "http/1.1"}, capturedHello.SupportedProtos)
	require.False(t, slices.Contains(capturedHello.SupportedVersions, tls.VersionTLS10))
	require.False(t, slices.Contains(capturedHello.SupportedVersions, tls.VersionTLS11))
}

func TestDialer_WithCustomALPN(t *testing.T) {
	var capturedHello *tls.ClientHelloInfo
	ln := startTestTLSServer(t, func(h *tls.ClientHelloInfo) {
		capturedHello = h
	})
	defer func() {
		_ = ln.Close()
	}()

	opts := DefaultOptions
	opts.ALPN = []string{"custom-proto", "http/1.1"}
	fd, err := NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	ctx := context.Background()
	conn, err := fd.DialTLS(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	require.NotNil(t, capturedHello)
	require.Equal(t, []string{"custom-proto", "http/1.1"}, capturedHello.SupportedProtos)
}

func TestDialer_WithTLSMinVersion(t *testing.T) {
	var capturedHello *tls.ClientHelloInfo
	ln := startTestTLSServer(t, func(h *tls.ClientHelloInfo) {
		capturedHello = h
	})
	defer func() {
		_ = ln.Close()
	}()

	opts := DefaultOptions
	opts.TLSMinVersion = tls.VersionTLS13
	fd, err := NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	ctx := context.Background()
	conn, err := fd.DialTLS(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	require.NotNil(t, capturedHello)
	require.Equal(t, []uint16{tls.VersionTLS13}, capturedHello.SupportedVersions)
}

func TestDialer_WithCustomTLSConfig(t *testing.T) {
	var capturedHello *tls.ClientHelloInfo
	ln := startTestTLSServer(t, func(h *tls.ClientHelloInfo) {
		capturedHello = h
	})
	defer func() {
		_ = ln.Close()
	}()

	customConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"custom-config-alpn"},
	}

	opts := DefaultOptions
	opts.TLSConfig = customConfig
	fd, err := NewDialer(opts)
	require.NoError(t, err)
	defer fd.Close()

	ctx := context.Background()
	conn, err := fd.DialTLS(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	require.NotNil(t, capturedHello)
	require.Equal(t, []string{"custom-config-alpn"}, capturedHello.SupportedProtos)
}

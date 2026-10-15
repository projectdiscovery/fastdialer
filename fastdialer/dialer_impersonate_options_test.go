package fastdialer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	"github.com/stretchr/testify/require"
)

func TestDialTLSWithConfigImpersonate_RootCAs(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	fd, err := NewDialer(DefaultOptions)
	require.NoError(t, err)
	defer fd.Close()

	// Dialing with custom RootCAs trusting the server cert
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	cfg := &tls.Config{RootCAs: pool, ServerName: "example.com"}
	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
	require.NoError(t, err)
	_ = conn.Close()

	// Dialing with empty RootCAs should fail verification
	cfgFail := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"}
	connFail, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfgFail, impersonate.Random, nil)
	require.Error(t, err)
	if connFail != nil {
		_ = connFail.Close()
	}
}

func TestDialTLSWithConfigImpersonate_Certificates(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		ClientAuth:       tls.RequireAnyClientCert,
		NextProtos:       []string{"http/1.1"},
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)

	fd, err := NewDialer(DefaultOptions)
	require.NoError(t, err)
	defer fd.Close()

	// With client cert
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{
			{Certificate: [][]byte{der}, PrivateKey: key},
		},
	}
	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "200 OK")
}

func TestDialTLSWithConfigImpersonate_VerifyPeerCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	fd, err := NewDialer(DefaultOptions)
	require.NoError(t, err)
	defer fd.Close()

	expectedErr := errors.New("custom cert verification failed")
	called := false

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			called = true
			return expectedErr
		},
	}

	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
	require.Error(t, err)
	require.True(t, called)
	require.Contains(t, err.Error(), expectedErr.Error())
	if conn != nil {
		_ = conn.Close()
	}
}

func TestDialTLSWithConfigImpersonate_VerifyConnection(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	fd, err := NewDialer(DefaultOptions)
	require.NoError(t, err)
	defer fd.Close()

	expectedErr := errors.New("connection rejected by callback")
	called := false

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			called = true
			require.NotEmpty(t, cs.PeerCertificates)
			return expectedErr
		},
	}

	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
	require.Error(t, err)
	require.True(t, called)
	require.Contains(t, err.Error(), expectedErr.Error())
	if conn != nil {
		_ = conn.Close()
	}
}

func TestDialTLSWithConfigImpersonate_KeyLogWriter(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	fd, err := NewDialer(DefaultOptions)
	require.NoError(t, err)
	defer fd.Close()

	var buf bytes.Buffer
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       &buf,
	}

	conn, err := fd.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NotEmpty(t, buf.Bytes())
	require.Contains(t, buf.String(), "CLIENT_")
}

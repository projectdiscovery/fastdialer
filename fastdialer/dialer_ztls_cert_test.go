package fastdialer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ztls "github.com/zmap/zcrypto/tls"
)

func TestDialZTLSWithConfigCertificates(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"},
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

	for _, minVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(minVersion), func(t *testing.T) {
			cfg := &ztls.Config{
				InsecureSkipVerify: true,
				MinVersion:         minVersion,
				Certificates:       []ztls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			}
			conn, err := fd.DialZTLSWithConfig(context.Background(), "tcp", addr, cfg)
			require.NoError(t, err)
			defer conn.Close()

			_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
			require.NoError(t, err)

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			require.NoError(t, err)
			require.Contains(t, string(buf[:n]), "200 OK")
		})
	}
}

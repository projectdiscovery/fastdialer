package fastdialer

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
)

func TestAsTLSConfig(t *testing.T) {
	ztlsConfig := &ztls.Config{}
	tlsConfig, err := AsTLSConfig(ztlsConfig)
	require.Nil(t, err)
	require.NotNil(t, tlsConfig)
}

func TestAsZTLSConfig(t *testing.T) {
	tlsConfig := &tls.Config{}
	ztlsConfig, err := AsZTLSConfig(tlsConfig)
	require.Nil(t, err)
	require.NotNil(t, ztlsConfig)
}

func TestAsZTLSConfigCopiesCertificates(t *testing.T) {
	key := &ecdsa.PrivateKey{}
	cert := tls.Certificate{
		Certificate:                  [][]byte{{1}},
		PrivateKey:                   key,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		OCSPStaple:                   []byte{2},
		SignedCertificateTimestamps:  [][]byte{{3}},
		Leaf:                         &x509.Certificate{},
	}

	ztlsConfig, err := AsZTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	// Leaf stays unset, see asZTLSCertificates
	require.Equal(t, []ztls.Certificate{{
		Certificate:                  cert.Certificate,
		PrivateKey:                   key,
		SupportedSignatureAlgorithms: []ztls.SignatureScheme{ztls.ECDSAWithP256AndSHA256},
		OCSPStaple:                   cert.OCSPStaple,
		SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
	}}, ztlsConfig.Certificates)
}

func TestAsTLSConfigCopiesCertificates(t *testing.T) {
	key := &ecdsa.PrivateKey{}
	cert := ztls.Certificate{
		Certificate:                  [][]byte{{1}},
		PrivateKey:                   key,
		SupportedSignatureAlgorithms: []ztls.SignatureScheme{ztls.ECDSAWithP256AndSHA256},
		OCSPStaple:                   []byte{2},
		SignedCertificateTimestamps:  [][]byte{{3}},
		Leaf:                         &zx509.Certificate{},
	}

	tlsConfig, err := AsTLSConfig(&ztls.Config{Certificates: []ztls.Certificate{cert}})
	require.NoError(t, err)
	// Leaf stays unset, see asTLSCertificates
	require.Equal(t, []tls.Certificate{{
		Certificate:                  cert.Certificate,
		PrivateKey:                   key,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		OCSPStaple:                   cert.OCSPStaple,
		SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
	}}, tlsConfig.Certificates)
}

// A crypto/tls client that uses a converted config must send the client
// certificate (#610).
func TestAsTLSConfigSendsCertificates(t *testing.T) {
	srv := newTLSServer(t, &tls.Config{ClientAuth: tls.RequireAnyClientCert})
	der, key := newClientCert(t)

	tlsConfig, err := AsTLSConfig(&ztls.Config{
		InsecureSkipVerify: true,
		Certificates:       []ztls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	require.NoError(t, err)

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), tlsConfig)
	require.NoError(t, err)
	// TLS 1.3 servers check the client certificate after the client finishes
	// its handshake, so a missing one shows up as a read error.
	body, err := httpGet(conn)
	require.NoError(t, err)
	require.Contains(t, body, "certs=1 ")
}

// The converters must carry the same fields in both directions.
func TestTLSConfigRoundTrip(t *testing.T) {
	key := &ecdsa.PrivateKey{}

	t.Run("tls", func(t *testing.T) {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate:                  [][]byte{{1}},
				PrivateKey:                   key,
				SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
				OCSPStaple:                   []byte{2},
				SignedCertificateTimestamps:  [][]byte{{3}},
			}},
			NextProtos:             []string{"h2", "http/1.1"},
			ServerName:             "example.com",
			ClientAuth:             tls.RequireAnyClientCert,
			InsecureSkipVerify:     true,
			CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SessionTicketsDisabled: true,
			MinVersion:             tls.VersionTLS12,
			MaxVersion:             tls.VersionTLS13,
		}

		ztlsConfig, err := AsZTLSConfig(tlsConfig)
		require.NoError(t, err)
		got, err := AsTLSConfig(ztlsConfig)
		require.NoError(t, err)
		require.Equal(t, tlsConfig, got)
	})

	t.Run("ztls", func(t *testing.T) {
		ztlsConfig := &ztls.Config{
			Certificates: []ztls.Certificate{{
				Certificate:                  [][]byte{{1}},
				PrivateKey:                   key,
				SupportedSignatureAlgorithms: []ztls.SignatureScheme{ztls.ECDSAWithP256AndSHA256},
				OCSPStaple:                   []byte{2},
				SignedCertificateTimestamps:  [][]byte{{3}},
			}},
			NextProtos:             []string{"h2", "http/1.1"},
			ServerName:             "example.com",
			ClientAuth:             ztls.RequireAnyClientCert,
			InsecureSkipVerify:     true,
			CipherSuites:           []uint16{ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SessionTicketsDisabled: true,
			MinVersion:             ztls.VersionTLS12,
			MaxVersion:             ztls.VersionTLS13,
		}

		tlsConfig, err := AsTLSConfig(ztlsConfig)
		require.NoError(t, err)
		got, err := AsZTLSConfig(tlsConfig)
		require.NoError(t, err)
		require.Equal(t, ztlsConfig, got)
	})
}

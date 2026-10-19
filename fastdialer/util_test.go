package fastdialer

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
	ztls "github.com/zmap/zcrypto/tls"
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

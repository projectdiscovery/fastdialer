package fastdialer

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
	ztls "github.com/zmap/zcrypto/tls"
)

func TestAsTLSConfig(t *testing.T) {
	// nil config
	cfg, err := AsTLSConfig(nil)
	require.Nil(t, err)
	require.Nil(t, cfg)

	// empty config
	ztlsConfig := &ztls.Config{}
	tlsConfig, err := AsTLSConfig(ztlsConfig)
	require.Nil(t, err)
	require.NotNil(t, tlsConfig)
	require.Empty(t, tlsConfig.Certificates)

	// config with certificates
	certBytes := [][]byte{{0x01, 0x02, 0x03}}
	ocsp := []byte{0x04, 0x05}
	ztlsConfigWithCert := &ztls.Config{
		Certificates: []ztls.Certificate{
			{
				Certificate: certBytes,
				OCSPStaple:  ocsp,
			},
		},
	}
	tlsConfigWithCert, err := AsTLSConfig(ztlsConfigWithCert)
	require.Nil(t, err)
	require.NotNil(t, tlsConfigWithCert)
	require.Len(t, tlsConfigWithCert.Certificates, 1)
	require.Equal(t, certBytes, tlsConfigWithCert.Certificates[0].Certificate)
	require.Equal(t, ocsp, tlsConfigWithCert.Certificates[0].OCSPStaple)
}

func TestAsZTLSConfig(t *testing.T) {
	// nil config
	zcfg, err := AsZTLSConfig(nil)
	require.Nil(t, err)
	require.Nil(t, zcfg)

	// empty config
	tlsConfig := &tls.Config{}
	ztlsConfig, err := AsZTLSConfig(tlsConfig)
	require.Nil(t, err)
	require.NotNil(t, ztlsConfig)
	require.Empty(t, ztlsConfig.Certificates)

	// config with certificates
	certBytes := [][]byte{{0x01, 0x02, 0x03}}
	ocsp := []byte{0x04, 0x05}
	tlsConfigWithCert := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: certBytes,
				OCSPStaple:  ocsp,
			},
		},
	}
	ztlsConfigWithCert, err := AsZTLSConfig(tlsConfigWithCert)
	require.Nil(t, err)
	require.NotNil(t, ztlsConfigWithCert)
	require.Len(t, ztlsConfigWithCert.Certificates, 1)
	require.Equal(t, certBytes, ztlsConfigWithCert.Certificates[0].Certificate)
	require.Equal(t, ocsp, ztlsConfigWithCert.Certificates[0].OCSPStaple)
}

package fastdialer

import (
	"crypto/tls"
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

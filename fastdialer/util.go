package fastdialer

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"

	ztls "github.com/zmap/zcrypto/tls"
)

func AsTLSConfig(ztlsConfig *ztls.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	err := To(ztlsConfig, tlsConfig)
	return tlsConfig, err
}

func AsZTLSConfig(tlsConfig *tls.Config) (*ztls.Config, error) {
	ztlsConfig := &ztls.Config{}
	err := To(tlsConfig, ztlsConfig)
	return ztlsConfig, err
}

func To(from, to interface{}) error {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(from)
	if err != nil {
		return err
	}
	err = gob.NewDecoder(&buf).Decode(to)
	if err != nil {
		return err
	}
	return nil
}

func IsTLS13(config interface{}) bool {
	switch c := config.(type) {
	case *tls.Config:
		return c.MinVersion == tls.VersionTLS13
	case *ztls.Config:
		return c.MinVersion == tls.VersionTLS13
	}

	return false
}

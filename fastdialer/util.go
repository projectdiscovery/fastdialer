package fastdialer

import (
	"crypto/tls"

	ztls "github.com/zmap/zcrypto/tls"
	"golang.org/x/net/idna"
)

func AsTLSConfig(ztlsConfig *ztls.Config) (*tls.Config, error) {
	if ztlsConfig == nil {
		return nil, nil
	}
	tlsConfig := &tls.Config{
		NextProtos:             ztlsConfig.NextProtos,
		ServerName:             ztlsConfig.ServerName,
		ClientAuth:             tls.ClientAuthType(ztlsConfig.ClientAuth),
		InsecureSkipVerify:     ztlsConfig.InsecureSkipVerify,
		CipherSuites:           ztlsConfig.CipherSuites,
		SessionTicketsDisabled: ztlsConfig.SessionTicketsDisabled,
		MinVersion:             ztlsConfig.MinVersion,
		MaxVersion:             ztlsConfig.MaxVersion,
	}
	if len(ztlsConfig.Certificates) > 0 {
		tlsConfig.Certificates = make([]tls.Certificate, len(ztlsConfig.Certificates))
		for i, cert := range ztlsConfig.Certificates {
			tlsConfig.Certificates[i] = tls.Certificate{
				Certificate: cert.Certificate,
				PrivateKey:  cert.PrivateKey,
				OCSPStaple:  cert.OCSPStaple,
			}
		}
	}
	return tlsConfig, nil
}

func AsZTLSConfig(tlsConfig *tls.Config) (*ztls.Config, error) {
	if tlsConfig == nil {
		return nil, nil
	}
	ztlsConfig := &ztls.Config{
		NextProtos:             tlsConfig.NextProtos,
		ServerName:             tlsConfig.ServerName,
		ClientAuth:             ztls.ClientAuthType(tlsConfig.ClientAuth),
		InsecureSkipVerify:     tlsConfig.InsecureSkipVerify,
		CipherSuites:           tlsConfig.CipherSuites,
		SessionTicketsDisabled: tlsConfig.SessionTicketsDisabled,
		MinVersion:             tlsConfig.MinVersion,
		MaxVersion:             tlsConfig.MaxVersion,
	}
	if len(tlsConfig.Certificates) > 0 {
		ztlsConfig.Certificates = make([]ztls.Certificate, len(tlsConfig.Certificates))
		for i, cert := range tlsConfig.Certificates {
			ztlsConfig.Certificates[i] = ztls.Certificate{
				Certificate: cert.Certificate,
				PrivateKey:  cert.PrivateKey,
				OCSPStaple:  cert.OCSPStaple,
			}
		}
	}
	return ztlsConfig, nil
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

func asAscii(hostname string) string {
	hostnameAscii, _ := idna.ToASCII(hostname)
	return hostnameAscii
}

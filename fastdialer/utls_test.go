package fastdialer

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestAsUTLSConfigCopiesClientFields(t *testing.T) {
	// the fields asUTLSConfig leaves unset, and why
	unset := map[string]string{
		"Rand":                        "deprecated in Go 1.27, and crypto/tls may ignore it too",
		"NameToCertificate":           "server only",
		"GetCertificate":              "server only",
		"GetConfigForClient":          "server only",
		"ClientAuth":                  "server only",
		"ClientCAs":                   "server only",
		"PreferServerCipherSuites":    "server only",
		"SessionTicketKey":            "server only",
		"UnwrapSession":               "server only",
		"WrapSession":                 "server only",
		"GetEncryptedClientHelloKeys": "server only",
		"EncryptedClientHelloKeys":    "server only",
	}
	cfg := &tls.Config{
		Time:                                time.Now,
		Certificates:                        []tls.Certificate{{}},
		GetClientCertificate:                func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil },
		VerifyPeerCertificate:               func([][]byte, [][]*x509.Certificate) error { return nil },
		VerifyConnection:                    func(tls.ConnectionState) error { return nil },
		RootCAs:                             x509.NewCertPool(),
		NextProtos:                          []string{"h2"},
		ServerName:                          "example.com",
		InsecureSkipVerify:                  true,
		CipherSuites:                        []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SessionTicketsDisabled:              true,
		ClientSessionCache:                  tls.NewLRUClientSessionCache(1),
		MinVersion:                          tls.VersionTLS12,
		MaxVersion:                          tls.VersionTLS13,
		CurvePreferences:                    []tls.CurveID{tls.X25519},
		DynamicRecordSizingDisabled:         true,
		Renegotiation:                       tls.RenegotiateOnceAsClient,
		KeyLogWriter:                        io.Discard,
		EncryptedClientHelloConfigList:      []byte{0},
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	}

	src := reflect.ValueOf(cfg).Elem()
	dst := reflect.ValueOf(asUTLSConfig(cfg)).Elem()
	for i := range src.NumField() {
		field := src.Type().Field(i)
		if _, ok := unset[field.Name]; ok || !field.IsExported() {
			continue
		}
		// a field added to tls.Config fails here until it is copied or
		// listed as unset
		if src.Field(i).IsZero() {
			t.Errorf("%s: set it in the test config, or list it as unset", field.Name)
			continue
		}
		if got := dst.FieldByName(field.Name); !got.IsValid() || got.IsZero() {
			t.Errorf("%s not copied", field.Name)
		}
	}
}

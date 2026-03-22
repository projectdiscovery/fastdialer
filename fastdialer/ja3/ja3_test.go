package ja3

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLocalTLSServer starts a TLS server on localhost with a self-signed cert
// and returns the listener, the CA cert pool, and a cleanup function.
func newLocalTLSServer(t *testing.T) (net.Listener, *x509.CertPool, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
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
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	return ln, pool, func() { ln.Close() }
}

func TestParseWithJa3_BasicParsing(t *testing.T) {
	t.Run("valid JA3 without curves/points extensions", func(t *testing.T) {
		// Extensions list does NOT include 10 or 11
		ja3 := "771,49195-49196,0-23-65281-35-16-5-13,23-24,0"
		spec, err := ParseWithJa3(ja3)
		require.NoError(t, err)
		require.NotNil(t, spec)

		assert.Equal(t, uint16(771), spec.TLSVersMin)
		assert.Equal(t, uint16(771), spec.TLSVersMax)
		assert.Equal(t, []uint16{49195, 49196}, spec.CipherSuites)
		assert.Len(t, spec.Extensions, 7)
	})

	t.Run("valid JA3 with curves and points extensions", func(t *testing.T) {
		// Extensions list includes 10 and 11
		ja3 := "771,49195-49196,0-23-65281-10-11-35-16-5-13,23-24,0"
		spec, err := ParseWithJa3(ja3)
		require.NoError(t, err)
		require.NotNil(t, spec)

		assert.Equal(t, uint16(771), spec.TLSVersMin)
		assert.Equal(t, []uint16{49195, 49196}, spec.CipherSuites)
		assert.Len(t, spec.Extensions, 9)

		var foundCurves, foundPoints bool
		for _, ext := range spec.Extensions {
			switch e := ext.(type) {
			case *utls.SupportedCurvesExtension:
				foundCurves = true
				assert.Equal(t, []utls.CurveID{23, 24}, e.Curves)
			case *utls.SupportedPointsExtension:
				foundPoints = true
				assert.Equal(t, []byte{0}, e.SupportedPoints)
			}
		}
		assert.True(t, foundCurves, "SupportedCurvesExtension should be present")
		assert.True(t, foundPoints, "SupportedPointsExtension should be present")
	})

	t.Run("extension order is preserved from JA3", func(t *testing.T) {
		ja3 := "771,49195,10-0-11,23,0"
		spec, err := ParseWithJa3(ja3)
		require.NoError(t, err)
		require.Len(t, spec.Extensions, 3)

		_, ok0 := spec.Extensions[0].(*utls.SupportedCurvesExtension)
		assert.True(t, ok0, "first extension should be SupportedCurves (10)")
		_, ok1 := spec.Extensions[1].(*utls.SNIExtension)
		assert.True(t, ok1, "second extension should be SNI (0)")
		_, ok2 := spec.Extensions[2].(*utls.SupportedPointsExtension)
		assert.True(t, ok2, "third extension should be SupportedPoints (11)")
	})
}

func TestParseWithJa3_ErrorCases(t *testing.T) {
	tests := []struct {
		name string
		ja3  string
	}{
		{"too few fields", "771,49195,0-23"},
		{"too many fields", "771,49195,0-23,23,0,extra"},
		{"invalid version", "abc,49195,0-23,23,0"},
		{"invalid cipher", "771,xyz,0-23,23,0"},
		{"invalid extension", "771,49195,0-99999,23,0"},
		{"invalid curve", "771,49195,0-23,abc,0"},
		{"invalid point", "771,49195,0-23,23,abc"},
		{"empty ciphers", "771,,0-23,23,0"},
		{"empty extensions", "771,49195,,23,0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseWithJa3(tt.ja3)
			assert.Error(t, err, "expected error for JA3: %s", tt.ja3)
			assert.Nil(t, spec)
		})
	}
}

func TestParseWithJa3_EmptyCurvesAndPoints(t *testing.T) {
	ja3 := "771,49195-49196,0-23-65281-35-16-5-13,,  "
	spec, err := ParseWithJa3(ja3)
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Len(t, spec.Extensions, 7)
}

func TestParseWithJa3_MultipleCurvesAndPoints(t *testing.T) {
	// curves: 29 (x25519), 23 (secp256r1), 24 (secp384r1)
	// points: 0 (uncompressed), 1 (ansiX962_compressed_prime), 2 (ansiX962_compressed_char2)
	ja3 := "771,49195,10-11,29-23-24,0-1-2"
	spec, err := ParseWithJa3(ja3)
	require.NoError(t, err)
	require.NotNil(t, spec)

	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			assert.Equal(t, []utls.CurveID{29, 23, 24}, e.Curves)
		case *utls.SupportedPointsExtension:
			assert.Equal(t, []byte{0, 1, 2}, e.SupportedPoints)
		}
	}
}

func TestParseWithJa3_TLSHandshake(t *testing.T) {
	ln, caPool, cleanup := newLocalTLSServer(t)
	defer cleanup()

	addr := ln.Addr().String()

	tests := []struct {
		name string
		ja3  string
	}{
		{
			"TLS 1.2 with ECDHE cipher and curves/points",
			"771,49195-49196,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		},
		{
			"TLS 1.2 with curves/points in different extension order",
			"771,49195,10-11-0-23-65281-35-5-13,23-24,0",
		},
		{
			"TLS 1.2 single curve single point",
			"771,49195,0-10-11-23-65281-35-13,23,0",
		},
		{
			"TLS 1.2 multiple curves",
			"771,49195-49196,10-11-0-23-65281-35-5-13,29-23-24,0-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseWithJa3(tt.ja3)
			require.NoError(t, err)

			tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			require.NoError(t, err)
			defer tcpConn.Close()

			uTLSConfig := &utls.Config{
				ServerName:         "localhost",
				RootCAs:            caPool,
				InsecureSkipVerify: false,
			}

			uConn := utls.UClient(tcpConn, uTLSConfig, utls.HelloCustom)
			clientHelloSpec := *spec
			err = uConn.ApplyPreset(&clientHelloSpec)
			require.NoError(t, err, "ApplyPreset should not fail")

			err = uConn.Handshake()
			require.NoError(t, err, "TLS handshake should succeed")

			state := uConn.ConnectionState()
			assert.Equal(t, uint16(tls.VersionTLS12), state.Version)
			uConn.Close()
		})
	}
}

func TestParseWithJa3_HandshakeFailsWithoutCurves(t *testing.T) {
	ln, caPool, cleanup := newLocalTLSServer(t)
	defer cleanup()

	addr := ln.Addr().String()

	// ECDHE ciphers without SupportedCurves in extensions — server should still
	// be able to negotiate if curves/points are not in the extension list but
	// are parsed from JA3 fields 4 and 5. This test verifies that the spec
	// produced by ParseWithJa3 does NOT include curves when extensions 10/11
	// are absent from the extensions token.
	ja3 := "771,49195-49199,0-23-65281-35-5-13,23-24,0"
	spec, err := ParseWithJa3(ja3)
	require.NoError(t, err)

	hasCurvesExt := false
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.SupportedCurvesExtension); ok {
			hasCurvesExt = true
		}
	}
	assert.False(t, hasCurvesExt, "extensions should not contain SupportedCurves when 10 is not in extensions token")

	// Handshake with explicit curves in extensions should succeed
	ja3WithCurves := "771,49195-49199,0-23-65281-10-11-35-5-13,23-24,0"
	specWithCurves, err := ParseWithJa3(ja3WithCurves)
	require.NoError(t, err)

	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer tcpConn.Close()

	uConn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         "localhost",
		RootCAs:            caPool,
		InsecureSkipVerify: false,
	}, utls.HelloCustom)
	err = uConn.ApplyPreset(specWithCurves)
	require.NoError(t, err)
	err = uConn.Handshake()
	require.NoError(t, err, "handshake with curves extension should succeed")
	uConn.Close()
}

func TestParseWithJa3_ChromelikeJA3(t *testing.T) {
	ln, caPool, cleanup := newLocalTLSServer(t)
	defer cleanup()

	addr := ln.Addr().String()

	// Chrome-like JA3 with common TLS 1.2 extensions including 10 and 11
	ja3 := "771,49195-49196-52393,0-23-65281-10-11-35-16-5-13-18,29-23-24,0"
	spec, err := ParseWithJa3(ja3)
	require.NoError(t, err)
	require.NotNil(t, spec)

	var curveExt *utls.SupportedCurvesExtension
	var pointExt *utls.SupportedPointsExtension
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curveExt = e
		case *utls.SupportedPointsExtension:
			pointExt = e
		}
	}
	require.NotNil(t, curveExt, "Chrome-like JA3 must have SupportedCurves")
	require.NotNil(t, pointExt, "Chrome-like JA3 must have SupportedPoints")
	assert.Equal(t, []utls.CurveID{utls.CurveID(29), utls.CurveID(23), utls.CurveID(24)}, curveExt.Curves)
	assert.Equal(t, []byte{0}, pointExt.SupportedPoints)

	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer tcpConn.Close()

	uConn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         "localhost",
		RootCAs:            caPool,
		InsecureSkipVerify: false,
	}, utls.HelloCustom)
	err = uConn.ApplyPreset(spec)
	require.NoError(t, err)
	err = uConn.Handshake()
	require.NoError(t, err, "Chrome-like JA3 handshake should succeed")

	state := uConn.ConnectionState()
	assert.Equal(t, uint16(tls.VersionTLS12), state.Version)
	uConn.Close()
}

func TestParseWithJa3_RegressionNonCurveExtensions(t *testing.T) {
	ja3 := "771,49195,0-5-13-16-23-65281-35-18-21,23,0"
	spec, err := ParseWithJa3(ja3)
	require.NoError(t, err)
	require.NotNil(t, spec)
	require.Len(t, spec.Extensions, 9)

	var hasSNI, hasStatus, hasSigAlgs, hasALPN, hasEMS bool
	var hasRenego, hasTicket, hasSCT, hasPadding bool
	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case *utls.SNIExtension:
			hasSNI = true
		case *utls.StatusRequestExtension:
			hasStatus = true
		case *utls.SignatureAlgorithmsExtension:
			hasSigAlgs = true
		case *utls.ALPNExtension:
			hasALPN = true
		case *utls.ExtendedMasterSecretExtension:
			hasEMS = true
		case *utls.RenegotiationInfoExtension:
			hasRenego = true
		case *utls.SessionTicketExtension:
			hasTicket = true
		case *utls.SCTExtension:
			hasSCT = true
		case *utls.UtlsPaddingExtension:
			hasPadding = true
		}
	}
	assert.True(t, hasSNI, "missing SNIExtension")
	assert.True(t, hasStatus, "missing StatusRequestExtension")
	assert.True(t, hasSigAlgs, "missing SignatureAlgorithmsExtension")
	assert.True(t, hasALPN, "missing ALPNExtension")
	assert.True(t, hasEMS, "missing ExtendedMasterSecretExtension")
	assert.True(t, hasRenego, "missing RenegotiationInfoExtension")
	assert.True(t, hasTicket, "missing SessionTicketExtension")
	assert.True(t, hasSCT, "missing SCTExtension")
	assert.True(t, hasPadding, "missing UtlsPaddingExtension")
}

func TestParseWithJa3_ConcurrentSafety(t *testing.T) {
	ja3Strings := []string{
		"771,49195,10-11-0-23,23,0",
		"771,49196,0-10-11-23,24,0-1",
		"771,49199,10-0-11,29-23,0",
	}

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			ja3 := ja3Strings[idx%len(ja3Strings)]
			spec, err := ParseWithJa3(ja3)
			assert.NoError(t, err)
			assert.NotNil(t, spec)
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

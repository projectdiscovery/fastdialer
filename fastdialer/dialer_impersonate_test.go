package fastdialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
)

// impersonationCurves keeps a test server from asking for a key share that
// the impersonated ClientHellos don't send.
var impersonationCurves = []tls.CurveID{tls.X25519, tls.CurveP256}

// newALPNServer starts a TLS server that prefers h2 over http/1.1.
func newALPNServer(t *testing.T) string {
	t.Helper()

	srv := newTLSServer(t, &tls.Config{CurvePreferences: impersonationCurves, NextProtos: []string{"h2", "http/1.1"}})

	return srv.Listener.Addr().String()
}

// negotiatedProtocol dials addr with impersonation and returns the ALPN
// protocol the server selected.
func negotiatedProtocol(t *testing.T, d *Dialer, addr string, nextProtos []string, strategy impersonate.Strategy, identity *impersonate.Identity) string {
	t.Helper()

	cfg := &tls.Config{InsecureSkipVerify: true, NextProtos: nextProtos}
	conn, err := d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, strategy, identity)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	return conn.(*utls.UConn).ConnectionState().NegotiatedProtocol
}

// alpnProtocols returns the protocols of the identity's ALPN extension.
func alpnProtocols(identity *impersonate.Identity) []string {
	for _, ext := range identity.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			return alpn.AlpnProtocols
		}
	}
	return nil
}

// ja3Identity returns a TLS 1.2 identity with ECDHE-ECDSA and ECDHE-RSA
// AES-GCM suites, a session ticket extension (35), and ALPN (16) advertising
// h2 and http/1.1.
func ja3Identity(t *testing.T) *impersonate.Identity {
	t.Helper()

	spec, err := ja3.ParseWithJa3("771,49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13,29-23-24,0")
	if err != nil {
		t.Fatalf("parse ja3: %v", err)
	}

	return (*impersonate.Identity)(spec)
}

// pskIdentity returns a TLS 1.3 identity with a pre_shared_key extension.
func pskIdentity(t *testing.T) *impersonate.Identity {
	t.Helper()

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_100_PSK)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}

	return (*impersonate.Identity)(&spec)
}

type tlsDial struct {
	name string
	dial func(addr string, cfg *tls.Config) (net.Conn, error)
	// resumes is set when the dial resumes sessions from a ClientSessionCache.
	// TLS 1.3 resumes only with a pre_shared_key extension, which the chrome,
	// random, and custom ClientHellos lack, and utls can't read the TLS 1.2
	// sessions of crypto/tls.
	resumes bool
}

// tlsDials returns a DialTLSWithConfig dial, whose behavior the impersonated
// dials must match, followed by a dial for each impersonation strategy. Each
// custom dial reuses its identity, as callers do.
func tlsDials(t *testing.T, d *Dialer) []tlsDial {
	t.Helper()

	impersonated := func(strategy impersonate.Strategy, identity *impersonate.Identity) func(string, *tls.Config) (net.Conn, error) {
		return func(addr string, cfg *tls.Config) (net.Conn, error) {
			return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, strategy, identity)
		}
	}

	return []tlsDial{
		{name: "none", dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
			return d.DialTLSWithConfig(context.Background(), "tcp", addr, cfg)
		}, resumes: true},
		{name: "random", dial: impersonated(impersonate.Random, nil)},
		{name: "chrome", dial: impersonated(impersonate.Chrome, nil)},
		{name: "custom", dial: impersonated(impersonate.Custom, ja3Identity(t))},
		{name: "custom-psk", dial: impersonated(impersonate.Custom, pskIdentity(t)), resumes: true},
	}
}

// countingSessionCache counts the lookups and stored sessions of a session
// cache.
type countingSessionCache struct {
	tls.ClientSessionCache
	gets, puts atomic.Int32
}

func (c *countingSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.gets.Add(1)
	return c.ClientSessionCache.Get(sessionKey)
}

func (c *countingSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	if cs != nil {
		c.puts.Add(1)
	}
	c.ClientSessionCache.Put(sessionKey, cs)
}

// dialAndGet dials addr with cfg, sends a request, and returns the response
// body.
func dialAndGet(t *testing.T, dial tlsDial, addr string, cfg *tls.Config) string {
	t.Helper()

	conn, err := dial.dial(addr, cfg)
	if err != nil {
		t.Fatalf("%s: dial: %v", dial.name, err)
	}
	body, err := httpGet(conn)
	if err != nil {
		t.Fatalf("%s: request: %v", dial.name, err)
	}

	return body
}

func TestDialTLSWithConfigImpersonateHonorsConfig(t *testing.T) {
	srv := newTLSServer(t, &tls.Config{CurvePreferences: impersonationCurves})
	addr := srv.Listener.Addr().String()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()
	dials := tlsDials(t, d)

	t.Run("ClientCertificate", func(t *testing.T) {
		srv := newTLSServer(t, &tls.Config{CurvePreferences: impersonationCurves, ClientAuth: tls.RequireAnyClientCert})
		addr := srv.Listener.Addr().String()
		der, key := newClientCert(t)
		cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

		configs := []struct {
			field string
			cfg   *tls.Config
		}{
			{"Certificates", &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}},
			{"GetClientCertificate", &tls.Config{
				InsecureSkipVerify: true,
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					// the request must describe the server's CertificateRequest
					if err := cri.SupportsCertificate(&cert); err != nil {
						return nil, err
					}
					return &cert, nil
				},
			}},
		}
		for _, c := range configs {
			for _, tt := range dials {
				t.Run(c.field+"/"+tt.name, func(t *testing.T) {
					// TLS 1.3 servers check the client certificate after the
					// client finishes its handshake, so a missing one fails the
					// request
					if body := dialAndGet(t, tt, addr, c.cfg); !strings.HasPrefix(body, "certs=1 ") {
						t.Fatalf("server got %q, want one certificate", body)
					}
				})
			}
		}
	})

	t.Run("ServerName", func(t *testing.T) {
		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				// custom dials reuse their identity, which must not keep the
				// name of an earlier dial
				for _, name := range []string{"a.example.com", "b.example.com"} {
					body := dialAndGet(t, tt, addr, &tls.Config{InsecureSkipVerify: true, ServerName: name})
					if !strings.HasSuffix(body, " sni="+name) {
						t.Fatalf("server got %q, want SNI %s", body, name)
					}
				}
			})
		}
	})

	t.Run("RootCAs", func(t *testing.T) {
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())

		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				// the httptest certificate is valid for example.com
				conn, err := tt.dial(addr, &tls.Config{RootCAs: roots, ServerName: "example.com"})
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				_ = conn.Close()
			})
		}
	})

	t.Run("VerifyPeerCertificate", func(t *testing.T) {
		errPin := errors.New("certificate pin mismatch")

		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &tls.Config{
					InsecureSkipVerify:    true,
					VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return errPin },
				}
				conn, err := tt.dial(addr, cfg)
				if err == nil {
					_ = conn.Close()
				}
				if !errors.Is(err, errPin) {
					t.Fatalf("dial error = %v, want %v", err, errPin)
				}
			})
		}
	})

	t.Run("VerifyConnection", func(t *testing.T) {
		errRejected := errors.New("connection rejected")

		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &tls.Config{
					InsecureSkipVerify: true,
					VerifyConnection: func(cs tls.ConnectionState) error {
						if len(cs.PeerCertificates) == 0 {
							return errors.New("no peer certificates")
						}
						return errRejected
					},
				}
				conn, err := tt.dial(addr, cfg)
				if err == nil {
					_ = conn.Close()
				}
				if !errors.Is(err, errRejected) {
					t.Fatalf("dial error = %v, want %v", err, errRejected)
				}
			})
		}
	})

	t.Run("KeyLogWriter", func(t *testing.T) {
		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				var keyLog bytes.Buffer
				conn, err := tt.dial(addr, &tls.Config{InsecureSkipVerify: true, KeyLogWriter: &keyLog})
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				_ = conn.Close()
				if keyLog.Len() == 0 {
					t.Fatal("no secrets written to KeyLogWriter")
				}
			})
		}
	})

	t.Run("ClientSessionCache", func(t *testing.T) {
		named := func(name string) tlsDial {
			return dials[slices.IndexFunc(dials, func(d tlsDial) bool { return d.name == name })]
		}

		for _, tt := range dials {
			t.Run(tt.name, func(t *testing.T) {
				cache := &countingSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(1)}
				cfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: cache}

				// TLS 1.3 tickets arrive after the handshake, so each dial
				// reads a response to receive them
				_ = dialAndGet(t, tt, addr, cfg)
				body := dialAndGet(t, tt, addr, cfg)

				if cache.gets.Load() == 0 {
					t.Fatal("ClientSessionCache never looked up")
				}
				if !tt.resumes {
					return
				}
				if cache.puts.Load() == 0 {
					t.Fatal("no session stored in ClientSessionCache")
				}
				if !strings.Contains(body, " resumed=true ") {
					t.Fatalf("second dial: server got %q, want a resumed session", body)
				}
			})
		}

		t.Run("shared", func(t *testing.T) {
			cfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(1)}

			// crypto/tls stores a TLS 1.3 session, which the custom
			// ClientHello can't resume without a pre_shared_key extension
			_ = dialAndGet(t, named("none"), addr, cfg)
			_ = dialAndGet(t, named("custom"), addr, cfg)
			if body := dialAndGet(t, named("custom-psk"), addr, cfg); !strings.Contains(body, " resumed=true ") {
				t.Fatalf("server got %q, want a resumed session", body)
			}
		})

		t.Run("RootCAs", func(t *testing.T) {
			trusted := x509.NewCertPool()
			trusted.AddCert(srv.Certificate())

			for _, tt := range dials {
				t.Run(tt.name, func(t *testing.T) {
					// the httptest certificate is valid for example.com
					cfg := &tls.Config{RootCAs: trusted, ServerName: "example.com", ClientSessionCache: tls.NewLRUClientSessionCache(1)}
					_ = dialAndGet(t, tt, addr, cfg)
					if body := dialAndGet(t, tt, addr, cfg); tt.resumes && !strings.Contains(body, " resumed=true ") {
						t.Fatalf("second dial: server got %q, want a resumed session", body)
					}

					// a session must not outlive the trust in its certificate
					conn, err := tt.dial(addr, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com", ClientSessionCache: cfg.ClientSessionCache})
					if err == nil {
						_ = conn.Close()
						t.Fatal("dial succeeded with RootCAs that don't trust the server")
					}
				})
			}
		})

		t.Run("identity session", func(t *testing.T) {
			// ja3.ParseWithRaw keeps the pre_shared_key of a captured
			// ClientHello in a FakePreSharedKeyExtension
			spec := utls.ClientHelloSpec(*pskIdentity(t))
			spec.Extensions = slices.Clone(spec.Extensions)
			i := slices.IndexFunc(spec.Extensions, func(ext utls.TLSExtension) bool {
				_, ok := ext.(*utls.UtlsPreSharedKeyExtension)
				return ok
			})
			spec.Extensions[i] = &utls.FakePreSharedKeyExtension{
				Identities: []utls.PskIdentity{{Label: []byte("captured"), ObfuscatedTicketAge: 1}},
				Binders:    [][]byte{make([]byte, 32)},
			}
			fake := tlsDial{name: "custom-fake-psk", dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
				return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, (*impersonate.Identity)(&spec))
			}}

			// the identity can't take the TLS 1.3 session that crypto/tls stores
			cfg := &tls.Config{InsecureSkipVerify: true, ClientSessionCache: tls.NewLRUClientSessionCache(1)}
			_ = dialAndGet(t, named("none"), addr, cfg)
			_ = dialAndGet(t, fake, addr, cfg)
		})
	})
}

func TestDialTLSWithConfigImpersonateHonorsNextProtos(t *testing.T) {
	addr := newALPNServer(t)

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	identity := ja3Identity(t)
	identityALPN := slices.Clone(alpnProtocols(identity))

	tests := []struct {
		name     string
		strategy impersonate.Strategy
		identity *impersonate.Identity
		// alwaysALPN is set when every ClientHello of the profile carries ALPN.
		alwaysALPN bool
	}{
		{"random", impersonate.Random, nil, false},
		{"chrome", impersonate.Chrome, nil, true},
		{"custom", impersonate.Custom, identity, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the profile keeps its own ALPN list when NextProtos is unset
			if tt.alwaysALPN {
				if got := negotiatedProtocol(t, d, addr, nil, tt.strategy, tt.identity); got != "h2" {
					t.Fatalf("NextProtos unset: negotiated %q, want %q", got, "h2")
				}
			}

			allowed := []string{"http/1.1"}
			if !tt.alwaysALPN {
				allowed = append(allowed, "")
			}
			// Random adds ALPN to some ClientHellos only, so dial repeatedly.
			for range 20 {
				if got := negotiatedProtocol(t, d, addr, []string{"http/1.1"}, tt.strategy, tt.identity); !slices.Contains(allowed, got) {
					t.Fatalf("NextProtos [http/1.1]: negotiated %q, want one of %q", got, allowed)
				}
			}
		})
	}

	// identities are shared across dials, so NextProtos must not leak into them
	if got := alpnProtocols(identity); !slices.Equal(got, identityALPN) {
		t.Fatalf("identity ALPN changed to %q, want %q", got, identityALPN)
	}
}

func TestRandomClientHelloPairsHybridKeyShare(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	sawHybrid := false
	for i := range 40 {
		uconn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true, ServerName: "example.com"}, randomClientHelloID())
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("hello %d: %v", i, err)
		}
		hello := uconn.HandshakeState.Hello
		if hello == nil {
			t.Fatalf("hello %d: missing client hello", i)
		}
		offered := slices.Contains(hello.SupportedCurves, utls.X25519MLKEM768)
		shared := false
		for _, share := range hello.KeyShares {
			if share.Group == utls.X25519MLKEM768 && len(share.Data) > 0 {
				shared = true
			}
		}
		if offered != shared {
			t.Fatalf("hello %d: hybrid curve %v, key share %v", i, offered, shared)
		}
		sawHybrid = sawHybrid || offered
	}
	if !sawHybrid {
		t.Fatal("no randomized hello offered X25519MLKEM768")
	}
}

package fastdialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
)

// newALPNServer starts a TLS server that prefers h2 over http/1.1.
func newALPNServer(t *testing.T) string {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

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

func TestDialTLSWithConfigImpersonateHonorsNextProtos(t *testing.T) {
	addr := newALPNServer(t)

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	// ECDHE-ECDSA and ECDHE-RSA AES-GCM suites, with ALPN (16) advertising
	// h2 and http/1.1.
	spec, err := ja3.ParseWithJa3("771,49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13,29-23-24,0")
	if err != nil {
		t.Fatalf("parse ja3: %v", err)
	}
	identity := (*impersonate.Identity)(spec)
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

type countingSessionCache struct {
	tls.ClientSessionCache
	gets atomic.Int32
	puts atomic.Int32
}

func (c *countingSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	c.gets.Add(1)
	return c.ClientSessionCache.Get(key)
}

func (c *countingSessionCache) Put(key string, cs *tls.ClientSessionState) {
	c.puts.Add(1)
	c.ClientSessionCache.Put(key, cs)
}

func TestDialTLSWithConfigImpersonateHonorsClientSessionCache(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, r.TLS.DidResume)
	}))
	srv.TLS = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()

	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	doRequest := func(dial func() (net.Conn, error)) (string, error) {
		conn, err := dial()
		if err != nil {
			return "", err
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
			return "", err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	t.Run("custom_with_session_ticket_and_next_protos_resumes", func(t *testing.T) {
		spec, err := ja3.ParseWithJa3("771,49195-49199-49196-49200,0-23-65281-10-11-35-16-5-13,29-23-24,0")
		if err != nil {
			t.Fatalf("parse ja3: %v", err)
		}
		identity := (*impersonate.Identity)(spec)

		cache := &countingSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			NextProtos:         []string{"http/1.1"},
		}

		resumed1, err := doRequest(func() (net.Conn, error) {
			return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, identity)
		})
		if err != nil {
			t.Fatalf("first dial failed: %v", err)
		}
		if resumed1 != "false" {
			t.Fatalf("first dial resumed = %q, want false", resumed1)
		}

		resumed2, err := doRequest(func() (net.Conn, error) {
			return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, identity)
		})
		if err != nil {
			t.Fatalf("second dial failed: %v", err)
		}
		if resumed2 != "true" {
			t.Fatalf("second dial resumed = %q, want true", resumed2)
		}
		if got := cache.gets.Load(); got != 2 {
			t.Fatalf("cache gets = %d, want 2", got)
		}
		if got := cache.puts.Load(); got < 1 {
			t.Fatalf("cache puts = %d, want >= 1", got)
		}
	})

	t.Run("custom_without_session_ticket_skips_resumption_cleanly", func(t *testing.T) {
		spec, err := ja3.ParseWithJa3("771,49195-49199-49196-49200,0-23-65281-10-11-16-5-13,29-23-24,0")
		if err != nil {
			t.Fatalf("parse ja3: %v", err)
		}
		identity := (*impersonate.Identity)(spec)

		cache := &countingSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			NextProtos:         []string{"http/1.1"},
		}

		for i := range 2 {
			if _, err := doRequest(func() (net.Conn, error) {
				return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, identity)
			}); err != nil {
				t.Fatalf("dial %d failed: %v", i+1, err)
			}
		}
	})

	t.Run("random_uses_cache_without_ems_mismatch_eof", func(t *testing.T) {
		cache := &countingSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			NextProtos:         []string{"http/1.1"},
		}

		for i := range 50 {
			if _, err := doRequest(func() (net.Conn, error) {
				return d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Random, nil)
			}); err != nil {
				t.Fatalf("random dial %d failed: %v", i+1, err)
			}
		}
		if got := cache.gets.Load(); got != 50 {
			t.Fatalf("cache gets = %d, want 50", got)
		}
		if got := cache.puts.Load(); got < 1 {
			t.Fatalf("cache puts = %d, want >= 1", got)
		}
	})
}


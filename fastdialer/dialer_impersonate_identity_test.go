package fastdialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer/ja3"
	"github.com/projectdiscovery/fastdialer/fastdialer/ja3/impersonate"
	utls "github.com/refraction-networking/utls"
)

// identitiesWithMutableExtensions returns identities with the extensions that
// utls writes to while it builds and sends a ClientHello.
func identitiesWithMutableExtensions(t *testing.T) map[string]*impersonate.Identity {
	t.Helper()

	chrome, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	// 21 is padding
	spec, err := ja3.ParseWithJa3("771,4865-49195-49199,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0")
	if err != nil {
		t.Fatalf("parse ja3: %v", err)
	}

	return map[string]*impersonate.Identity{
		"chrome":     (*impersonate.Identity)(&chrome),
		"ja3":        (*impersonate.Identity)(spec),
		"custom-psk": pskIdentity(t),
	}
}

// describeExtensions returns the contents of the extensions of identity.
func describeExtensions(identity *impersonate.Identity) []string {
	var out []string
	for _, ext := range identity.Extensions {
		out = append(out, fmt.Sprintf("%T%+v", ext, ext))
	}
	return out
}

// Dials must not write to the identity, which callers reuse across dials and
// goroutines (#609).
func TestDialTLSWithConfigImpersonateLeavesIdentityUnchanged(t *testing.T) {
	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	servers := map[string]string{
		"key share": newTLSServer(t, &tls.Config{CurvePreferences: impersonationCurves}).Listener.Addr().String(),
		// the identities send an X25519 key share, so the server asks for
		// another one
		"retry": newTLSServer(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}}).Listener.Addr().String(),
	}
	for name, identity := range identitiesWithMutableExtensions(t) {
		for server, addr := range servers {
			t.Run(name+"/"+server, func(t *testing.T) {
				before := describeExtensions(identity)
				for range 2 {
					cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"}
					conn, err := d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, identity)
					if err != nil {
						t.Fatalf("dial: %v", err)
					}
					_ = conn.Close()
				}
				if after := describeExtensions(identity); !slices.Equal(before, after) {
					for i := range before {
						if before[i] != after[i] {
							t.Errorf("extension %d changed:\n before %s\n after  %s", i, before[i], after[i])
						}
					}
				}
			})
		}
	}
}

// Concurrent dials may share an identity (#609). Run with -race.
func TestDialTLSWithConfigImpersonateSharesIdentity(t *testing.T) {
	addr := newTLSServer(t, &tls.Config{CurvePreferences: impersonationCurves}).Listener.Addr().String()
	d, err := NewDialer(DefaultOptions)
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}
	defer d.Close()

	for name, identity := range identitiesWithMutableExtensions(t) {
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					cfg := &tls.Config{InsecureSkipVerify: true}
					conn, err := d.DialTLSWithConfigImpersonate(context.Background(), "tcp", addr, cfg, impersonate.Custom, identity)
					if err != nil {
						t.Errorf("dial: %v", err)
						return
					}
					_ = conn.Close()
				})
			}
			wg.Wait()
		})
	}
}

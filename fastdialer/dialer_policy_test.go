package fastdialer

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/projectdiscovery/networkpolicy"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

type invalidTarget struct{ hostname, ip, port string }

// recordInvalid makes the dialer record the targets it rejects in got.
func recordInvalid(got *[]invalidTarget) func(*Options) {
	var mu sync.Mutex
	return func(opts *Options) {
		opts.OnInvalidTarget = func(hostname, ip, port string) {
			mu.Lock()
			defer mu.Unlock()
			*got = append(*got, invalidTarget{hostname, ip, port})
		}
	}
}

func allow(rules ...string) func(*Options) {
	return func(opts *Options) { opts.Allow = rules }
}

func TestDialHostnamePolicy(t *testing.T) {
	resolver, _, shutdown := startMockDNSServer(t, map[string]string{
		"blocked.test": "127.0.0.1",
		"ok.test":      "127.0.0.1",
		"other.test":   "127.0.0.1",
	})
	defer shutdown()

	port := listenBanner(t, "127.0.0.1", "0", "one")
	addr := func(host string) string { return net.JoinHostPort(host, port) }
	var direct proxy.Dialer = proxy.Direct
	viaProxy := func(opts *Options) { opts.ProxyDialer = &direct }

	tests := []struct {
		name      string
		configure []func(*Options)
		address   string
		allowed   bool
	}{
		{"hostname deny blocks the host", []func(*Options){deny(`^blocked\.test$`)}, addr("blocked.test"), false},
		{"hostname deny keeps other hosts", []func(*Options){deny(`^blocked\.test$`)}, addr("other.test"), true},
		{"hostname deny blocks a pinned dial", []func(*Options){deny(`^blocked\.test$`)}, addr("blocked.test") + ":127.0.0.1", false},
		{"hostname deny blocks over a proxy", []func(*Options){deny(`^blocked\.test$`), viaProxy}, addr("blocked.test"), false},
		{"hostname allow keeps the host", []func(*Options){allow(`^ok\.test$`)}, addr("ok.test"), true},
		{"hostname allow blocks other hosts", []func(*Options){allow(`^ok\.test$`)}, addr("other.test"), false},
		{"hostname allow blocks other hosts over a proxy", []func(*Options){allow(`^ok\.test$`), viaProxy}, addr("other.test"), false},
		{"cidr deny blocks the resolved ip", []func(*Options){deny("127.0.0.1/32")}, addr("other.test"), false},
		{"cidr deny blocks over a proxy", []func(*Options){deny("127.0.0.1/32"), viaProxy}, addr("other.test"), false},
		{"cidr allow keeps the resolved ip", []func(*Options){allow("127.0.0.0/8")}, addr("other.test"), true},
		{"cidr allow blocks other ips", []func(*Options){allow("10.0.0.0/8")}, addr("other.test"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fd := newPinTestDialer(t, resolver, test.configure...)
			conn, err := fd.Dial(context.Background(), "tcp", test.address)
			if test.allowed {
				require.NoError(t, err)
				require.Equal(t, "one", readBanner(t, conn))
				return
			}
			require.ErrorIs(t, err, NoAddressAllowedError)
		})
	}

	t.Run("hostname reject reports the host without an ip", func(t *testing.T) {
		var got []invalidTarget
		fd := newPinTestDialer(t, resolver, deny(`^blocked\.test$`), recordInvalid(&got))
		_, err := fd.Dial(context.Background(), "tcp", addr("blocked.test"))
		require.ErrorIs(t, err, NoAddressAllowedError)
		require.Equal(t, []invalidTarget{{"blocked.test", "", port}}, got)
	})

	t.Run("default network policy does not reject bare hostnames", func(t *testing.T) {
		var got []invalidTarget
		withDefaults := func(opts *Options) {
			defaults := networkpolicy.DefaultOptions
			opts.WithNetworkPolicyOptions = &defaults
		}
		fd := newPinTestDialer(t, resolver, withDefaults, recordInvalid(&got))
		// the default policy denies loopback, so the dial fails on the ip
		_, err := fd.Dial(context.Background(), "tcp", addr("other.test"))
		require.ErrorIs(t, err, NoAddressAllowedError)
		require.Equal(t, []invalidTarget{{"other.test", "127.0.0.1", port}}, got)
	})
}

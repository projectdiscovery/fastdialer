package fastdialer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newPinTestDialer returns a dialer that resolves names only through the given
// mock DNS server, so the tests never depend on the network.
func newPinTestDialer(t *testing.T, resolver string, configure ...func(*Options)) *Dialer {
	t.Helper()

	opts := DefaultOptions
	opts.BaseResolvers = []string{resolver}
	opts.HostsFile = false
	opts.ResolversFile = false
	opts.MaxRetries = 1
	opts.DialerTimeout = 5 * time.Second
	for _, apply := range configure {
		apply(&opts)
	}

	fd, err := NewDialer(opts)
	require.NoError(t, err)
	t.Cleanup(fd.Close)
	return fd
}

func deny(ips ...string) func(*Options) {
	return func(opts *Options) { opts.Deny = ips }
}

func withHistory(opts *Options) { opts.WithDialerHistory = true }

// listenBanner accepts connections on host:port and writes banner to each of
// them, and returns the port. It skips the test when the address cannot be
// bound (127.0.0.2 is not configured on macOS by default).
func listenBanner(t *testing.T, host, port, banner string) string {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", net.JoinHostPort(host, port), err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(banner))
			_ = conn.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port
}

func readBanner(t *testing.T, conn net.Conn) string {
	t.Helper()
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	return string(data)
}

func TestDialPinnedIP(t *testing.T) {
	resolver, _, shutdown := startMockDNSServer(t, map[string]string{
		"pinned.test": "127.0.0.3",
	})
	defer shutdown()

	t.Run("different pinned ips of one address are not served from cache", func(t *testing.T) {
		port := listenBanner(t, "127.0.0.1", "0", "one")
		listenBanner(t, "127.0.0.2", port, "two")

		fd := newPinTestDialer(t, resolver)
		target := net.JoinHostPort("pinned.test", port)

		conn, err := fd.Dial(context.WithValue(context.Background(), IP, "127.0.0.1"), "tcp", target)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))

		conn, err = fd.Dial(context.WithValue(context.Background(), IP, "127.0.0.2"), "tcp", target)
		require.NoError(t, err)
		require.Equal(t, "two", readBanner(t, conn))
	})

	t.Run("pinned ip is validated after another pin of the same address", func(t *testing.T) {
		port := listenBanner(t, "127.0.0.1", "0", "one")

		fd := newPinTestDialer(t, resolver, deny("127.0.0.2"))
		target := net.JoinHostPort("pinned.test", port)

		conn, err := fd.Dial(context.WithValue(context.Background(), IP, "127.0.0.1"), "tcp", target)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))

		_, err = fd.Dial(context.WithValue(context.Background(), IP, "127.0.0.2"), "tcp", target)
		require.ErrorIs(t, err, NoAddressAllowedError)
	})

	t.Run("pinned dial does not answer later unpinned dials", func(t *testing.T) {
		port := listenBanner(t, "127.0.0.1", "0", "one")

		// pinned.test resolves to 127.0.0.3, which is denied, so an unpinned
		// dial may only fail.
		fd := newPinTestDialer(t, resolver, deny("127.0.0.3"))
		target := net.JoinHostPort("pinned.test", port)

		conn, err := fd.Dial(context.WithValue(context.Background(), IP, "127.0.0.1"), "tcp", target)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))

		_, err = fd.Dial(context.Background(), "tcp", target)
		require.ErrorIs(t, err, NoAddressAllowedError)
	})
}

func TestDialResolveOverride(t *testing.T) {
	// pinned.test has no record, other.test resolves to the listener
	resolver, _, shutdown := startMockDNSServer(t, map[string]string{
		"other.test": "127.0.0.1",
	})
	defer shutdown()

	port := listenBanner(t, "127.0.0.1", "0", "one")
	pinned := net.JoinHostPort("pinned.test", port)
	other := net.JoinHostPort("other.test", port)

	// 127.0.0.3 is denied: a dial pinned to it fails with NoAddressAllowedError
	fd := newPinTestDialer(t, resolver, deny("127.0.0.3"))

	t.Run("pins the matching host", func(t *testing.T) {
		ctx := WithResolveOverride(context.Background(), "pinned.test", "127.0.0.1")
		conn, err := fd.Dial(ctx, "tcp", pinned)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))
	})

	t.Run("matches case-insensitively and without the trailing dot", func(t *testing.T) {
		ctx := WithResolveOverride(context.Background(), "PINNED.test.", "127.0.0.1")
		conn, err := fd.Dial(ctx, "tcp", pinned)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))
	})

	t.Run("resolves other hosts as usual", func(t *testing.T) {
		ctx := WithResolveOverride(context.Background(), "pinned.test", "127.0.0.3")
		conn, err := fd.Dial(ctx, "tcp", other)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))

		_, err = fd.Dial(ctx, "tcp", pinned)
		require.ErrorIs(t, err, NoAddressAllowedError)
	})

	t.Run("does not change the parent context", func(t *testing.T) {
		parent := WithResolveOverride(context.Background(), "pinned.test", "127.0.0.3")
		child := WithResolveOverride(parent, "pinned.test", "127.0.0.1")

		conn, err := fd.Dial(child, "tcp", pinned)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))

		_, err = fd.Dial(parent, "tcp", pinned)
		require.ErrorIs(t, err, NoAddressAllowedError)
	})

	t.Run("IP context option takes precedence", func(t *testing.T) {
		ctx := WithResolveOverride(context.Background(), "pinned.test", "127.0.0.3")
		ctx = context.WithValue(ctx, IP, "127.0.0.1")
		conn, err := fd.Dial(ctx, "tcp", pinned)
		require.NoError(t, err)
		require.Equal(t, "one", readBanner(t, conn))
	})
}

// listenTLS starts a TLS server with a self-signed certificate, records the
// server name each client sent, and returns its port.
func listenTLS(t *testing.T) (port string, serverNames func() []string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pinned.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"pinned.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	var mu sync.Mutex
	var names []string
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			names = append(names, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
			}(conn)
		}
	}()

	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

func TestDialTLSKeepsSNI(t *testing.T) {
	resolver, _, shutdown := startMockDNSServer(t, map[string]string{
		"xn--bcher-kva.test": "127.0.0.1",
	})
	defer shutdown()

	tests := []struct {
		name    string
		host    string
		pin     func(ctx context.Context, address string) (context.Context, string)
		wantSNI string
	}{
		{
			name: "host:port:ip address",
			host: "pinned.test",
			pin: func(ctx context.Context, address string) (context.Context, string) {
				return ctx, address + ":127.0.0.1"
			},
			wantSNI: "pinned.test",
		},
		{
			name: "resolve override",
			host: "pinned.test",
			pin: func(ctx context.Context, address string) (context.Context, string) {
				return WithResolveOverride(ctx, "pinned.test", "127.0.0.1"), address
			},
			wantSNI: "pinned.test",
		},
		{
			name: "internationalized hostname",
			host: "bücher.test",
			pin: func(ctx context.Context, address string) (context.Context, string) {
				return WithResolveOverride(ctx, "bücher.test", "127.0.0.1"), address
			},
			wantSNI: "xn--bcher-kva.test",
		},
		{
			name: "internationalized hostname, resolved",
			host: "bücher.test",
			pin: func(ctx context.Context, address string) (context.Context, string) {
				return ctx, address
			},
			wantSNI: "xn--bcher-kva.test",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port, serverNames := listenTLS(t)
			fd := newPinTestDialer(t, resolver, withHistory)
			ctx, address := test.pin(context.Background(), net.JoinHostPort(test.host, port))

			// the second dial is served from the dial cache
			for range 2 {
				conn, err := fd.DialTLS(ctx, "tcp", address)
				require.NoError(t, err)
				_ = conn.Close()
			}
			require.Equal(t, []string{test.wantSNI, test.wantSNI}, serverNames())
			require.Equal(t, "127.0.0.1", fd.GetDialedIP(test.host))
		})
	}
}

func TestDialIPv6Address(t *testing.T) {
	resolver, _, shutdown := startMockDNSServer(t, nil)
	defer shutdown()

	port := listenBanner(t, "::1", "0", "six")
	fd := newPinTestDialer(t, resolver, withHistory)

	// the second dial is served from the dial cache
	for range 2 {
		conn, err := fd.Dial(context.Background(), "tcp", net.JoinHostPort("::1", port))
		require.NoError(t, err)
		require.Equal(t, "six", readBanner(t, conn))
	}
	require.Equal(t, "::1", fd.GetDialedIP("::1"))
}

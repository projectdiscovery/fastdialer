package fastdialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCachedDialIsValidated(t *testing.T) {
	resolver, _, shutdown := startMockDNSServer(t, map[string]string{
		"cached.test": "127.0.0.1",
	})
	defer shutdown()

	port := listenBanner(t, "127.0.0.1", "0", "one")
	target := net.JoinHostPort("cached.test", port)

	var block atomic.Bool
	fd := newPinTestDialer(t, resolver, func(opts *Options) {
		opts.OnValidateTarget = func(hostname, ip, port string) error {
			if block.Load() {
				return errors.New("blocked")
			}
			return nil
		}
	})

	conn, err := fd.Dial(context.Background(), "tcp", target)
	require.NoError(t, err)
	require.Equal(t, "one", readBanner(t, conn))
	require.True(t, fd.dialCache.Has("tcp-"+target), "first dial is cached")

	block.Store(true)
	_, err = fd.Dial(context.Background(), "tcp", target)
	require.ErrorIs(t, err, NoAddressAllowedError)

	block.Store(false)
	conn, err = fd.Dial(context.Background(), "tcp", target)
	require.NoError(t, err)
	require.Equal(t, "one", readBanner(t, conn))
}

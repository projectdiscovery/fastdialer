package fastdialer

import (
	"context"
	"testing"
)

func TestDialer(t *testing.T) {
	options := DefaultOptions
	testDialer(t, options)

	// memory based
	options.CacheType = Memory
	options.CacheMemoryMaxItems = 100
	testDialer(t, options)

	// hybrid
	options.CacheType = Hybrid
	options.CacheMemoryMaxItems = 100
	testDialer(t, options)

	// disk
	options.CacheType = Hybrid
	options.CacheMemoryMaxItems = 100
	testDialer(t, options)

	// testDialerIpv6(t, options) not supported by GitHub VMs
}

func testDialer(t *testing.T, options Options) {
	// disk based
	fd, err := NewDialer(options)
	if err != nil {
		t.Errorf("couldn't create fastdialer instance: %s", err)
	}

	// valid resolution + cache
	ctx := context.Background()
	conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
	if err != nil || conn == nil {
		t.Errorf("couldn't connect to target: %s", err)
	}
	conn.Close()
	// retrieve cached data
	data, err := fd.GetDNSData("www.projectdiscovery.io")
	if err != nil || data == nil {
		t.Errorf("couldn't retrieve dns data: %s", err)
	}
	if len(data.A) == 0 {
		t.Error("no A results found")
	}
	// cleanup
	fd.Close()
}

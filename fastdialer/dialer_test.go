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

// nolint
func testDialerIpv6(t *testing.T, options Options) {
	// disk based
	fd, err := NewDialer(options)
	if err != nil {
		t.Fatalf("couldn't create fastdialer instance: %s", err)
	}

	// valid resolution + cache
	ctx := context.Background()
	conn, err := fd.Dial(ctx, "tcp", "ipv6.google.com:80")
	if err != nil || conn == nil {
		t.Fatalf("couldn't connect to target: %s", err)
	}
	conn.Close()
	// retrieve cached data
	data, err := fd.GetDNSData("ipv6.google.com")
	if err != nil || data == nil {
		t.Fatalf("couldn't retrieve dns data: %s", err)
	}
	if len(data.AAAA) == 0 {
		t.Error("no AAAA results found")
	}

	// test address pinning
	// this test passes, but will fail if the hard-coded ipv6 address changes
	// need to find a better way to test this
	/*
		    conn, err = fd.Dial(ctx, "tcp", "ipv6.google.com:80:[2607:f8b0:4006:807::200e]")
			if err != nil || conn == nil {
				t.Errorf("couldn't connect to target: %s", err)
			}
			conn.Close()
	*/

	// cleanup
	fd.Close()
}

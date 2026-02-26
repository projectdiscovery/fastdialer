package fastdialer

import (
	"context"
	"errors"
	"sync"
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
	options.CacheType = Disk
	options.CacheMemoryMaxItems = 100
	testDialer(t, options)

	// testDialerIpv6(t, options) not supported by GitHub VMs
}

func testDialer(t *testing.T, options Options) {
	// disk based
	fd, err := NewDialer(options)
	if err != nil {
		t.Errorf("couldn't create fastdialer instance: %s", err)
		return
	}
	defer fd.Close()

	// valid resolution + cache
	ctx := context.Background()
	conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
	if err != nil || conn == nil {
		t.Errorf("couldn't connect to target: %s", err)
		return
	}
	if err := conn.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
		return
	}
	// retrieve cached data
	data, err := fd.GetDNSData("www.projectdiscovery.io")
	if err != nil || data == nil {
		t.Errorf("couldn't retrieve dns data: %s", err)
		return
	}
	if len(data.A) == 0 {
		t.Error("no A results found")
	}
}

func TestDialerTargetValidation(t *testing.T) {
	t.Run("ValidTarget", func(t *testing.T) {
		options := DefaultOptions

		var validateCalled bool
		options.OnValidateTarget = func(hostname, ip, port string) error {
			validateCalled = true
			if hostname != "www.projectdiscovery.io" {
				return errors.New("invalid hostname")
			}
			return nil
		}

		var invalidCalled bool
		options.OnInvalidTarget = func(hostname, ip, port string) {
			invalidCalled = true
		}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if err != nil || conn == nil {
			t.Fatalf("couldn't connect to target: %s", err)
		}
		defer conn.Close()

		if !validateCalled {
			t.Error("OnValidateTarget was not called")
		}
		if invalidCalled {
			t.Error("OnInvalidTarget was called for a valid target")
		}
	})

	t.Run("InvalidTarget", func(t *testing.T) {
		options := DefaultOptions

		var validateCalled bool
		options.OnValidateTarget = func(hostname, ip, port string) error {
			validateCalled = true
			return errors.New("target rejected")
		}

		var invalidCalled bool
		var mu sync.Mutex
		options.OnInvalidTarget = func(hostname, ip, port string) {
			mu.Lock()
			invalidCalled = true
			mu.Unlock()
		}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if err != NoAddressAllowedError {
			if conn != nil {
				conn.Close()
			}
			t.Fatalf("expected NoAddressAllowedError, got: %v", err)
		}

		if !validateCalled {
			t.Error("OnValidateTarget was not called")
		}

		mu.Lock()
		called := invalidCalled
		mu.Unlock()
		if !called {
			t.Error("OnInvalidTarget was not called for an invalid target")
		}
	})
}

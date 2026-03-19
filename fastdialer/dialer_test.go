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

func TestDialerPortPolicy(t *testing.T) {
	t.Run("DenyPortBlocks", func(t *testing.T) {
		options := DefaultOptions
		options.DenyPortList = []int{80}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if conn != nil {
			_ = conn.Close()
		}
		if err != NoAddressAllowedError {
			t.Fatalf("expected NoAddressAllowedError for denied port, got: %v", err)
		}
	})

	t.Run("DenyPortAllowsOther", func(t *testing.T) {
		options := DefaultOptions
		options.DenyPortList = []int{8081}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if err != nil || conn == nil {
			t.Fatalf("expected connection to succeed on non-denied port, got: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("AllowPortPermits", func(t *testing.T) {
		options := DefaultOptions
		options.AllowPortList = []int{80, 443}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if err != nil || conn == nil {
			t.Fatalf("expected connection to succeed on allowed port, got: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("AllowPortBlocksOther", func(t *testing.T) {
		options := DefaultOptions
		options.AllowPortList = []int{443}

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if conn != nil {
			_ = conn.Close()
		}
		if err != NoAddressAllowedError {
			t.Fatalf("expected NoAddressAllowedError for non-allowed port, got: %v", err)
		}
	})

	t.Run("NoPortPolicyUnchanged", func(t *testing.T) {
		options := DefaultOptions

		fd, err := NewDialer(options)
		if err != nil {
			t.Fatalf("couldn't create fastdialer instance: %s", err)
		}
		defer fd.Close()

		ctx := context.Background()
		conn, err := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if err != nil || conn == nil {
			t.Fatalf("expected connection to succeed without port policy, got: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("DenyPortTriggersOnInvalidTarget", func(t *testing.T) {
		options := DefaultOptions
		options.DenyPortList = []int{80}

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
		conn, _ := fd.Dial(ctx, "tcp", "www.projectdiscovery.io:80")
		if conn != nil {
			_ = conn.Close()
		}

		mu.Lock()
		called := invalidCalled
		mu.Unlock()
		if !called {
			t.Error("OnInvalidTarget was not called for denied port")
		}
	})
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
		defer func() {
			_ = conn.Close()
		}()

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
				_ = conn.Close()
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

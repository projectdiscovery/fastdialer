package utils

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/errkit"
)

// TestDialAllParallel_DeadlineExceeded verifies that when all dials fail with
// context.DeadlineExceeded the error is NOT wrapped as ErrPortClosedOrFiltered.
// This prevents poisoning the dial cache with a permanent error when the real
// cause was a transient timeout.
func TestDialAllParallel_DeadlineExceeded(t *testing.T) {
	t.Parallel()

	// Use a very short deadline so all dials fail with DeadlineExceeded.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Let the deadline expire before dialing.
	time.Sleep(5 * time.Millisecond)

	dw, err := NewDialWrap(
		&net.Dialer{Timeout: 1 * time.Millisecond},
		[]string{"192.0.2.1"}, // RFC 5737 TEST-NET, will never connect
		"tcp",
		"192.0.2.1:12345",
		"12345",
	)
	if err != nil {
		t.Fatal(err)
	}

	_, dialErr := dw.dialAllParallel(ctx)
	if dialErr == nil {
		t.Fatal("expected an error from dialAllParallel with expired context, got nil")
	}

	if errkit.Is(dialErr, ErrPortClosedOrFiltered) {
		t.Fatalf("DeadlineExceeded must not be classified as ErrPortClosedOrFiltered, got: %v", dialErr)
	}
}

// TestDialAllParallel_ContextCanceled verifies that when all dials fail with
// context.Canceled the error is NOT wrapped as ErrPortClosedOrFiltered.
func TestDialAllParallel_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so all dials get context.Canceled.
	cancel()

	dw, err := NewDialWrap(
		&net.Dialer{Timeout: 1 * time.Millisecond},
		[]string{"192.0.2.1"},
		"tcp",
		"192.0.2.1:12345",
		"12345",
	)
	if err != nil {
		t.Fatal(err)
	}

	_, dialErr := dw.dialAllParallel(ctx)
	if dialErr == nil {
		t.Fatal("expected an error from dialAllParallel with canceled context, got nil")
	}

	if errkit.Is(dialErr, ErrPortClosedOrFiltered) {
		t.Fatalf("context.Canceled must not be classified as ErrPortClosedOrFiltered, got: %v", dialErr)
	}
}

// TestDialAllParallel_RealConnectionRefused verifies that a genuine
// connection-refused error IS still classified as ErrPortClosedOrFiltered.
func TestDialAllParallel_RealConnectionRefused(t *testing.T) {
	t.Parallel()

	// Bind a listener and immediately close it to guarantee a refused port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dw, err := NewDialWrap(
		&net.Dialer{Timeout: 2 * time.Second},
		[]string{"127.0.0.1"},
		"tcp",
		"127.0.0.1",
		fmt.Sprintf("%d", port),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, dialErr := dw.dialAllParallel(ctx)
	if dialErr == nil {
		t.Fatal("expected an error from dialAllParallel to a refused port, got nil")
	}

	if !errkit.Is(dialErr, ErrPortClosedOrFiltered) {
		t.Fatalf("connection refused should still be classified as ErrPortClosedOrFiltered, got: %v", dialErr)
	}
}

// TestDialContext_DeadlineExceededNotCached verifies that DialContext with a
// deadline-exceeded first connection does not permanently store the error
// as ErrPortClosedOrFiltered, so a subsequent caller is not poisoned.
func TestDialContext_DeadlineExceededNotCached(t *testing.T) {
	t.Parallel()

	// Start a listener that accepts but never responds (simulates slow host).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func(c net.Conn) {
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	dw, err := NewDialWrap(
		&net.Dialer{Timeout: 50 * time.Millisecond},
		[]string{"127.0.0.1"},
		"tcp",
		"127.0.0.1",
		fmt.Sprintf("%d", port),
	)
	if err != nil {
		t.Fatal(err)
	}

	// First call: use an already-expired context.
	expiredCtx, cancel1 := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel1()
	time.Sleep(5 * time.Millisecond)

	_, err1 := dw.DialContext(expiredCtx, "", "")
	if err1 == nil {
		t.Fatal("expected error from DialContext with expired context")
	}

	// The stored error must NOT be ErrPortClosedOrFiltered.
	dw.firstConnCond.L.Lock()
	storedErr := dw.err
	dw.firstConnCond.L.Unlock()

	if storedErr != nil && errkit.Is(storedErr, ErrPortClosedOrFiltered) {
		t.Fatalf("deadline-exceeded error must not be cached as ErrPortClosedOrFiltered: %v", storedErr)
	}
}
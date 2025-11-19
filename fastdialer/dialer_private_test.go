package fastdialer

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

type mockCloser struct {
	closedCount atomic.Int32
	ch          chan struct{}
	retErr      error
}

func newMockCloser(retErr error) *mockCloser {
	return &mockCloser{ch: make(chan struct{}, 1), retErr: retErr}
}

func (m *mockCloser) Close() error {
	if m.closedCount.Add(1) == 1 {
		select {
		case m.ch <- struct{}{}:
		default:
		}
	}
	return m.retErr
}

func waitClosed(t *testing.T, m *mockCloser, d time.Duration) bool {
	t.Helper()
	select {
	case <-m.ch:
		return true
	case <-time.After(d):
		return false
	}
}

// Removed generic behavior tests; keeping context-focused tests only.

func TestCloseAfterTimeout_RespectsDeadlineTiming(t *testing.T) {
	t.Parallel()
	m := newMockCloser(nil)
	deadline := 60 * time.Millisecond
	start := time.Now()
	ctxFuncDone := closeAfterTimeout(deadline, m)
	defer ctxFuncDone()

	if ok := waitClosed(t, m, 750*time.Millisecond); !ok {
		t.Fatalf("expected closer to be called before overall wait deadline")
	}
	elapsed := time.Since(start)
	// Allow some jitter, but ensure it didn't trigger too early (< 50% of deadline)
	if elapsed < deadline/2 {
		t.Fatalf("close triggered too early: elapsed=%v deadline=%v", elapsed, deadline)
	}
	// And also not excessively late (> 10x deadline)
	if elapsed > 10*deadline {
		t.Fatalf("close triggered too late: elapsed=%v deadline=%v", elapsed, deadline)
	}
	// Ensure internal timeout path invoked close exactly once
	if got := m.closedCount.Load(); got != 1 {
		t.Fatalf("expected close to be called once via internal timeout, got %d", got)
	}
}

func TestCloseAfterTimeout_ExternalCancelPreemptsTimeout(t *testing.T) {
	t.Parallel()
	m := newMockCloser(nil)
	deadline := 250 * time.Millisecond
	cancel := closeAfterTimeout(deadline, m)
	// Cancel well before the deadline
	time.Sleep(20 * time.Millisecond)
	cancel()
	// Wait well past the original deadline to ensure it would have fired
	if ok := waitClosed(t, m, 500*time.Millisecond); ok {
		t.Fatalf("did not expect closer to be called after external cancel")
	}
	if got := m.closedCount.Load(); got != 0 {
		t.Fatalf("expected zero close calls with external cancel, got %d", got)
	}
	// Re-check at the very end after additional wait to ensure it stays zero
	time.Sleep(100 * time.Millisecond)
	if got := m.closedCount.Load(); got != 0 {
		t.Fatalf("expected zero close calls at end of test, got %d", got)
	}
}

func TestDial(t *testing.T) {
	t.Run("ZTLSWithConfig", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to start listener: %v", err)
		}
		defer listener.Close()

		serverAddr := listener.Addr().String()

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}

				// hold conn w/o completing handshake
				time.Sleep(5 * time.Second)
				conn.Close()
			}
		}()

		options := DefaultOptions
		options.DialerTimeout = 100 * time.Millisecond

		dialer, err := NewDialer(options)
		if err != nil {
			t.Fatalf("Failed to create dialer: %v", err)
		}
		defer dialer.Close()

		ztlsConfig := &ztls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		}

		_, err = dialer.DialZTLSWithConfig(context.Background(), "tcp", serverAddr, ztlsConfig)
		if err == nil {
			t.Fatal("Expected an error due to timeout, got nil")
		}
	})

	t.Run("TLSWithConfigFallback", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to start listener: %v", err)
		}
		defer listener.Close()

		serverAddr := listener.Addr().String()

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				time.Sleep(5 * time.Second)
				conn.Close()
			}
		}()

		options := DefaultOptions
		options.DialerTimeout = 100 * time.Millisecond
		options.DisableZtlsFallback = false

		dialer, err := NewDialer(options)
		if err != nil {
			t.Fatalf("Failed to create dialer: %v", err)
		}
		defer dialer.Close()

		_, err = dialer.DialTLSWithConfig(context.Background(), "tcp", serverAddr, DefaultTLSConfig)

		if err == nil {
			t.Fatal("Expected an error due to timeout, got nil")
		}
	})
}

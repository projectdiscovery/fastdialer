package fastdialer

import (
	"sync/atomic"
	"testing"
	"time"
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

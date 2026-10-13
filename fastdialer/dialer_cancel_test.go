package fastdialer

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestCloseAfterTimeout_ImmediateCancelKeepsConnectionOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const attempts = 256
		m := newMockCloser(nil)
		for range attempts {
			cancel := closeAfterTimeout(time.Hour, m)
			// A successful handshake may cancel before the watchdog runs.
			// Do not sleep first: that hides the two-ready-cases race.
			cancel()
			cancel() // Cancellation must remain idempotent.
		}
		synctest.Wait()
		if got := m.closedCount.Load(); got != 0 {
			t.Fatalf("successful completion closed the connection %d/%d times", got, attempts)
		}
		// Also ensure cancelled watchdogs cannot close it at the old deadline.
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if got := m.closedCount.Load(); got != 0 {
			t.Fatalf("cancelled watchdog closed the connection after its deadline: %d", got)
		}
	})
}

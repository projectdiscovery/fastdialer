package utils

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ExtendibleContext is a context that allows deadline extension and ignores parent deadline
type ExtendibleContext struct {
	parent      context.Context
	mu          sync.Mutex
	done        chan struct{}
	err         error
	deadline    time.Time
	hasDeadline bool
}

// NewExtendibleContext creates a new ExtendibleContext
func NewExtendibleContext(parent context.Context) *ExtendibleContext {
	ctx := &ExtendibleContext{
		parent: parent,
		done:   make(chan struct{}),
	}

	if parent != nil {
		go ctx.watchParent()
	}

	return ctx
}

func (c *ExtendibleContext) watchParent() {
	select {
	case <-c.parent.Done():
		id := fmt.Sprint(c.Value("id"))
		deadline, ok := c.parent.Deadline()
		err := c.parent.Err()
		AppendLog(id, fmt.Sprintf(`parent ctx
		deadline,ok: %v %v
		err: %v`, deadline, ok, err))
		c.cancel(c.parent.Err())
	case <-c.Done():
	}
}

func (c *ExtendibleContext) cancel(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err == nil {
		c.err = err
		close(c.done)
	}
}

// Deadline returns the deadline and whether it has been set
func (c *ExtendibleContext) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, c.hasDeadline
}

// Done returns a channel that is closed when the context is cancelled
func (c *ExtendibleContext) Done() <-chan struct{} {
	return c.done
}

// Err returns the error that caused the context to be cancelled
func (c *ExtendibleContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Value returns the value associated with key or nil if none
func (c *ExtendibleContext) Value(key interface{}) interface{} {
	return c.parent.Value(key)
}

// SetDeadline sets or updates the context's deadline
func (c *ExtendibleContext) SetDeadline(d time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.deadline = d
	c.hasDeadline = true

	if c.err == nil && !d.IsZero() {
		go c.waitForDeadline(d)
	}
}

func (c *ExtendibleContext) waitForDeadline(deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case <-timer.C:
		c.cancel(context.DeadlineExceeded)
	case <-c.Done():
	}
}

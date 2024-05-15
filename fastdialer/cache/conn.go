package cache

import (
	"sync"
	"errors"
)

var (
	// ErrNoItemsInBag is returned when no items are in the bag
	ErrNoItemsInBag = errors.New("no items in bag")
)

// Closer is an interface implemented by types that can be closed
type Closer interface {
	// Close closes a resource
	Close()
}

// Bag is a generic bag of items with a max size
// when bag is full it closes any new items when added
// instead of storing them
type Bag[T Closer] struct {
	items []T
	mu sync.Mutex
	maxSize int
}

// NewBag creates a new bag
func NewBag[T Closer](maxSize int) *Bag[T] {
	if maxSize == 0 {
		panic("maxSize cannot be 0")
	}
	return &Bag[T]{
		mu: sync.Mutex{},
		maxSize: maxSize,
	}
}

// Add adds an item to the bag
func (b *Bag[T]) Put(item T) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.maxSize {
		// when bag is full the item is closed instead of being added
		// to bag
		item.Close()
		return
	}
	b.items = append(b.items, item)
}

// Get gets an item from the bag
func (b *Bag[T]) Get() (T, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		var zero T
		return zero, ErrNoItemsInBag
	}
	if len(b.items) == 1 {
		item := b.items[0]
		b.items = []T{}
		return item, nil
	}
	item := b.items[0]
	b.items = b.items[1:]
	return item, nil
}

// Size returns the size of the bag
func (b *Bag[T]) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

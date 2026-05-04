package cache

import (
	"container/list"
	"sync"
)

var _ Cache[string] = (*LRUCache[string])(nil)

// lruEntry represents the value stored in the cache and the linked list node.
type lruEntry[K comparable] struct {
	key   K
	value any
	// expiry time.Time field removed
}

// LRUCache is a concurrent, fixed-size cache with an LRU eviction policy.
type LRUCache[K comparable] struct {
	capacity int
	mu       sync.Mutex

	// list is a doubly linked list used for tracking access order.
	// Front is Most Recently Used (MRU), Back is Least Recently Used (LRU).
	list *list.List

	// cache maps the key to the list element (*list.Element) which holds the lruEntry.
	cache map[K]*list.Element

	onInvalidate func(key K, value any)
}

// NewLRUCache creates a new LRU Cache instance.
// Capacity must be greater than zero.
func NewLRUCache[K comparable](
	capacity int,
	onInvalidate func(key K, value any),
) Cache[K] {
	if capacity <= 0 {
		// Default to a sensible minimum capacity if input is invalid
		capacity = 100
	}
	return &LRUCache[K]{
		capacity:     capacity,
		list:         list.New(),
		cache:        make(map[K]*list.Element, capacity),
		onInvalidate: onInvalidate,
	}
}

// evictOldest removes the least recently used item from the cache.
func (c *LRUCache[K]) evictOldest() {
	// Element is at the back of the list (LRU)
	tail := c.list.Back()
	if tail != nil {
		c.removeByElement(tail)
	}
}

// removeByElement removes a specific list element from both the list and the map.
func (c *LRUCache[K]) removeByElement(e *list.Element) {
	c.list.Remove(e)
	entry := e.Value.(*lruEntry[K])
	delete(c.cache, entry.key)
	if c.onInvalidate != nil {
		c.onInvalidate(entry.key, entry.value)
	}
}

// Get retrieves a value from the cache.
// If found, the item is promoted to Most Recently Used (MRU).
func (c *LRUCache[K]) Get(key K) (any, bool) {
	// Use Lock since MoveToFront modifies the linked list
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key exists in the map
	if element, ok := c.cache[key]; ok {
		// No TTL check needed.

		// Promote to Most Recently Used (MRU)
		c.list.MoveToFront(element)

		entry := element.Value.(*lruEntry[K])
		return entry.value, true
	}

	return nil, false
}

// Set adds a value to the cache, applying any provided options.
func (c *LRUCache[K]) Set(key K, value any, opts *options) bool {
	// Use Write Lock for modification operations
	c.mu.Lock()
	defer c.mu.Unlock()

	if opts == nil {
		opts = Options()
	}

	element, ok := c.cache[key]
	if ok && opts.skipExisting {
		return false
	}

	if !ok && opts.updateExistingOnly {
		return false
	}

	if ok { // Key already exists
		entry := element.Value.(*lruEntry[K])
		if c.onInvalidate != nil {
			// Invoke onInvalidate to ensure associated resources are properly released.
			c.onInvalidate(entry.key, entry.value)
		}
		entry.value = value

		c.list.MoveToFront(element)
		return true
	}

	// Key is new: Create a new entry
	entry := &lruEntry[K]{
		key:   key,
		value: value,
	}

	// Add new entry to the front of the list (MRU) and to the map
	element = c.list.PushFront(entry)
	c.cache[key] = element

	// Check for eviction if capacity is exceeded
	if c.list.Len() > c.capacity {
		c.evictOldest()
	}

	return true
}

// ForEach iterates over the cache items.
func (c *LRUCache[K]) ForEach(f func(key K, value any) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var next *list.Element
	for e := c.list.Front(); e != nil; e = next {
		next = e.Next()
		entry := e.Value.(*lruEntry[K])
		if err := f(entry.key, entry.value); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes an item from the cache.
func (c *LRUCache[K]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.cache[key]; ok {
		c.removeByElement(element)
	}
}

// Has checks if an item exists in the cache without moving its MRU status.
func (c *LRUCache[K]) Has(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.cache[key]
	return ok
}

// Size returns the number of items in the cache.
func (c *LRUCache[K]) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list.Len()
}

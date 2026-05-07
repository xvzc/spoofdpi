package cache

import (
	"container/list"
	"sync"
)

var _ Cache[string, any] = (*LRUCache[string, any])(nil)

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

type LRUCache[K comparable, V any] struct {
	capacity     int
	mu           sync.Mutex
	list         *list.List
	cache        map[K]*list.Element
	onInvalidate func(key K, value V)
}

func NewLRUCache[K comparable, V any](
	capacity int,
	onInvalidate func(key K, value V),
) Cache[K, V] {
	if capacity <= 0 {
		capacity = 100
	}
	return &LRUCache[K, V]{
		capacity:     capacity,
		list:         list.New(),
		cache:        make(map[K]*list.Element, capacity),
		onInvalidate: onInvalidate,
	}
}

func (c *LRUCache[K, V]) evictOldest() {
	tail := c.list.Back()
	if tail != nil {
		c.removeByElement(tail)
	}
}

func (c *LRUCache[K, V]) removeByElement(e *list.Element) {
	c.list.Remove(e)
	entry := e.Value.(*lruEntry[K, V])
	delete(c.cache, entry.key)
	if c.onInvalidate != nil {
		c.onInvalidate(entry.key, entry.value)
	}
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.cache[key]; ok {
		c.list.MoveToFront(element)
		entry := element.Value.(*lruEntry[K, V])
		return entry.value, true
	}

	var zero V
	return zero, false
}

func (c *LRUCache[K, V]) Set(key K, value V, opts *options) bool {
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

	if ok {
		entry := element.Value.(*lruEntry[K, V])
		if c.onInvalidate != nil {
			c.onInvalidate(entry.key, entry.value)
		}
		entry.value = value
		c.list.MoveToFront(element)
		return true
	}

	entry := &lruEntry[K, V]{
		key:   key,
		value: value,
	}

	element = c.list.PushFront(entry)
	c.cache[key] = element

	if c.list.Len() > c.capacity {
		c.evictOldest()
	}

	return true
}

func (c *LRUCache[K, V]) ForEach(f func(key K, value V) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var next *list.Element
	for e := c.list.Front(); e != nil; e = next {
		next = e.Next()
		entry := e.Value.(*lruEntry[K, V])
		if err := f(entry.key, entry.value); err != nil {
			return err
		}
	}
	return nil
}

func (c *LRUCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, ok := c.cache[key]; ok {
		c.removeByElement(element)
	}
}

func (c *LRUCache[K, V]) Has(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.cache[key]
	return ok
}

func (c *LRUCache[K, V]) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list.Len()
}

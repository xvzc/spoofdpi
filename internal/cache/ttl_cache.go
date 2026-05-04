package cache

import (
	"fmt"
	"hash/fnv" // FNV-1a: A fast, non-cryptographic hash function
	"sync"
	"time"
)

var _ Cache[string] = (*TTLCache[string])(nil)

// ttlCacheItem represents a single cached item using generics.
type ttlCacheItem[K comparable] struct {
	value     any       // The cached data of type T.
	expiresAt time.Time // The time when the item expires.
}

// isExpired checks if the item has expired.
func (i ttlCacheItem[K]) isExpired() bool {
	if i.expiresAt.IsZero() {
		// zero time means no expiration.
		return false
	}
	return time.Now().After(i.expiresAt)
}

// ttlCacheShard represents a single, thread-safe shard of the cache.
type ttlCacheShard[K comparable] struct {
	items map[K]ttlCacheItem[K] // items holds the cache data for this shard.
	mu    sync.RWMutex
}

type TTLCacheAttrs struct {
	NumOfShards     uint8
	CleanupInterval time.Duration
	HashFunc        func(key any) uint64
}

// TTLCache is a high-performance, sharded, generic TTL cache.
type TTLCache[K comparable] struct {
	shards   []*ttlCacheShard[K] // A slice of cache shards.
	hashFunc func(key any) uint64
}

// NewTTLCache creates a new sharded TTL cache with a background janitor goroutine.
// numShards specifies the number of shards to create and must be greater than 0.
// cleanupInterval specifies how often the janitor should run.
func NewTTLCache[K comparable](
	attrs TTLCacheAttrs,
) *TTLCache[K] {
	if attrs.NumOfShards == 0 {
		panic(
			fmt.Errorf("number of shards must be greater than 0, got %d", attrs.NumOfShards),
		)
	}

	c := &TTLCache[K]{
		shards:   make([]*ttlCacheShard[K], attrs.NumOfShards),
		hashFunc: attrs.HashFunc,
	}

	for i := range attrs.NumOfShards {
		c.shards[i] = &ttlCacheShard[K]{
			items: make(map[K]ttlCacheItem[K]),
		}
	}

	// Start the background janitor goroutine.
	// This goroutine is self-managing and terminates when the program exits.
	go c.janitor(attrs.CleanupInterval)

	return c
}

// janitor runs the cleanup goroutine, calling ForceCleanup at the specified interval.
func (c *TTLCache[K]) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		c.ForceCleanup()
	}
}

// getShard maps a key to its corresponding cache shard using a hash function.
func (c *TTLCache[K]) getShard(key K) *ttlCacheShard[K] {
	if c.hashFunc != nil {
		hash := c.hashFunc(key)
		return c.shards[hash%uint64(len(c.shards))]
	}

	hasher := fnv.New64a()
	// Optimally hash the memory without string allocation
	switch v := any(key).(type) {
	case string:
		hasher.Write([]byte(v))
	case []byte:
		hasher.Write(v)
	default:
		_, _ = fmt.Fprint(hasher, key)
	}
	hash := hasher.Sum64()
	return c.shards[hash%uint64(len(c.shards))]
}

// ┌─────────────┐
// │ PUBLIC APIs │
// └─────────────┘
// Set adds an item to the cache, replacing any existing item.
// If ttl is 0 or negative, the item will never expire (passive-only).
func (c *TTLCache[K]) Set(key K, value any, opts *options) bool {
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if opts == nil {
		opts = Options()
	}

	if opts.ttl == 0 {
		return false
	}

	_, ok := shard.items[key]
	if ok && opts.skipExisting {
		return false
	}

	if !ok && opts.updateExistingOnly {
		return false
	}

	expiresAt := time.Now().Add(opts.ttl)
	newItem := ttlCacheItem[K]{
		value:     value,
		expiresAt: expiresAt,
	}
	shard.items[key] = newItem

	return true
}

// Get retrieves an item from the cache.
// It returns the item (of type T) and true if found and not expired.
// Otherwise, it returns the zero value of T and false.
func (c *TTLCache[K]) Get(key K) (any, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	i, ok := shard.items[key]
	shard.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Passive expiration: item found but is expired.
	if i.isExpired() {
		// Item is expired, so acquire a write lock to delete it.
		shard.mu.Lock()
		// Double-check: ensure the item hasn't been replaced
		// by another goroutine while we were waiting for the write lock.
		if currentItem, ok := shard.items[key]; ok {
			if time.Time.Equal(currentItem.expiresAt, i.expiresAt) {
				delete(shard.items, key)
			}
		}

		shard.mu.Unlock()
		return nil, false // Return as expired.
	}

	// Cache hit.
	return i.value, true
}

// Delete removes an item from the cache.
func (c *TTLCache[K]) Delete(key K) {
	shard := c.getShard(key)
	shard.mu.Lock()
	delete(shard.items, key)
	shard.mu.Unlock()
}

// Has checks if an item exists in the cache and is not expired.
func (c *TTLCache[K]) Has(key K) bool {
	shard := c.getShard(key)
	shard.mu.RLock()
	i, ok := shard.items[key]
	shard.mu.RUnlock()

	if !ok {
		return false
	}

	return !i.isExpired()
}

// ForceCleanup actively scans all shards and deletes expired items.
// This is called periodically by the janitor but can also be called manually.
func (c *TTLCache[K]) ForceCleanup() {
	now := time.Now()
	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, i := range shard.items {
			if !i.expiresAt.IsZero() && now.After(i.expiresAt) {
				delete(shard.items, key)
			}
		}
		shard.mu.Unlock()
	}
}

// ForEach iterates over the cache items.
func (c *TTLCache[K]) ForEach(f func(key K, value any) error) error {
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, i := range shard.items { // Pre-allocate values to avoid holding RLock unnecessarily? For now, keep simple.
			if err := f(key, i.value); err != nil {
				shard.mu.RUnlock()
				return err
			}
		}
		shard.mu.RUnlock()
	}
	return nil
}

// Size returns the total number of items across all shards.
func (c *TTLCache[K]) Size() int {
	total := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		total += len(shard.items)
		shard.mu.RUnlock()
	}
	return total
}

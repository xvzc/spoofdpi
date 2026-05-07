package cache

import (
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

var _ Cache[string, any] = (*TTLCache[string, any])(nil)

// ttlCacheItem represents a single cached item.
// expiresAt is stored as UnixNano (int64) to avoid the *time.Location pointer
// that time.Time carries, which would make every map entry GC-scannable.
// Zero means no expiration.
type ttlCacheItem[V any] struct {
	value     V
	expiresAt int64
}

func (i ttlCacheItem[V]) isExpired() bool {
	return i.expiresAt != 0 && time.Now().UnixNano() > i.expiresAt
}

type ttlCacheShard[K comparable, V any] struct {
	items map[K]ttlCacheItem[V]
	mu    sync.RWMutex
}

type TTLCacheAttrs struct {
	NumOfShards     uint8
	CleanupInterval time.Duration
	HashFunc        func(key any) uint64
}

type TTLCache[K comparable, V any] struct {
	shards   []*ttlCacheShard[K, V]
	hashFunc func(key any) uint64
}

func NewTTLCache[K comparable, V any](
	attrs TTLCacheAttrs,
) *TTLCache[K, V] {
	if attrs.NumOfShards == 0 {
		panic(
			fmt.Errorf("number of shards must be greater than 0, got %d", attrs.NumOfShards),
		)
	}

	c := &TTLCache[K, V]{
		shards:   make([]*ttlCacheShard[K, V], attrs.NumOfShards),
		hashFunc: attrs.HashFunc,
	}

	for i := range attrs.NumOfShards {
		c.shards[i] = &ttlCacheShard[K, V]{
			items: make(map[K]ttlCacheItem[V]),
		}
	}

	go c.janitor(attrs.CleanupInterval)

	return c
}

func (c *TTLCache[K, V]) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		c.ForceCleanup()
	}
}

// getShard maps a key to its shard using an inline FNV-1a hash for string/[]byte
// keys, avoiding heap allocation from fnv.New64a() on the hot path.
func (c *TTLCache[K, V]) getShard(key K) *ttlCacheShard[K, V] {
	if c.hashFunc != nil {
		hash := c.hashFunc(key)
		return c.shards[hash%uint64(len(c.shards))]
	}

	var hash uint64
	switch v := any(key).(type) {
	case string:
		hash = fnv1aString(v)
	case []byte:
		hash = fnv1aBytes(v)
	default:
		h := fnv.New64a()
		_, _ = fmt.Fprint(h, key)
		hash = h.Sum64()
	}
	return c.shards[hash%uint64(len(c.shards))]
}

const (
	fnvOffset64 = uint64(14695981039346656037)
	fnvPrime64  = uint64(1099511628211)
)

func fnv1aString(s string) uint64 {
	h := fnvOffset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime64
	}
	return h
}

func fnv1aBytes(b []byte) uint64 {
	h := fnvOffset64
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

// ┌─────────────┐
// │ PUBLIC APIs │
// └─────────────┘

func (c *TTLCache[K, V]) Set(key K, value V, opts *options) bool {
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

	shard.items[key] = ttlCacheItem[V]{
		value:     value,
		expiresAt: time.Now().Add(opts.ttl).UnixNano(),
	}

	return true
}

func (c *TTLCache[K, V]) Get(key K) (V, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	i, ok := shard.items[key]
	shard.mu.RUnlock()

	if !ok {
		var zero V
		return zero, false
	}

	if i.isExpired() {
		shard.mu.Lock()
		if current, ok := shard.items[key]; ok && current.expiresAt == i.expiresAt {
			delete(shard.items, key)
		}
		shard.mu.Unlock()
		var zero V
		return zero, false
	}

	return i.value, true
}

func (c *TTLCache[K, V]) Delete(key K) {
	shard := c.getShard(key)
	shard.mu.Lock()
	delete(shard.items, key)
	shard.mu.Unlock()
}

func (c *TTLCache[K, V]) Has(key K) bool {
	shard := c.getShard(key)
	shard.mu.RLock()
	i, ok := shard.items[key]
	shard.mu.RUnlock()

	return ok && !i.isExpired()
}

func (c *TTLCache[K, V]) ForceCleanup() {
	now := time.Now().UnixNano()
	for _, shard := range c.shards {
		shard.mu.Lock()
		for key, i := range shard.items {
			if i.expiresAt != 0 && now > i.expiresAt {
				delete(shard.items, key)
			}
		}
		shard.mu.Unlock()
	}
}

func (c *TTLCache[K, V]) ForEach(f func(key K, value V) error) error {
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, i := range shard.items {
			if err := f(key, i.value); err != nil {
				shard.mu.RUnlock()
				return err
			}
		}
		shard.mu.RUnlock()
	}
	return nil
}

func (c *TTLCache[K, V]) Size() int {
	total := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		total += len(shard.items)
		shard.mu.RUnlock()
	}
	return total
}

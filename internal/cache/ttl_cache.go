package cache

import (
	"sync"
	"time"
)

type ttlCacheItem[V any] struct {
	value     V
	expiresAt int64
}

func (i ttlCacheItem[V]) isExpired() bool {
	return i.expiresAt != 0 && time.Now().UnixNano() > i.expiresAt
}

type ttlCacheShard[K Key, V any] struct {
	items map[K]ttlCacheItem[V]
	mu    sync.RWMutex
}

type TTLCacheAttrs struct {
	NumOfShards     uint8
	CleanupInterval time.Duration
}

type TTLCache[K Key, V any] struct {
	shards []*ttlCacheShard[K, V]
}

func NewTTLCache[K Key, V any](
	attrs TTLCacheAttrs,
) *TTLCache[K, V] {
	if attrs.NumOfShards == 0 {
		panic("number of shards must be greater than 0")
	}

	c := &TTLCache[K, V]{
		shards: make([]*ttlCacheShard[K, V], attrs.NumOfShards),
	}

	for i := range attrs.NumOfShards {
		c.shards[i] = &ttlCacheShard[K, V]{
			items: make(map[K]ttlCacheItem[V]),
		}
	}

	go c.janitor(attrs.CleanupInterval)

	return c
}

func (c *TTLCache[K, V]) getShard(key K) *ttlCacheShard[K, V] {
	hash := fnv1aBytes(key.Bytes())
	return c.shards[hash%uint64(len(c.shards))]
}

func (c *TTLCache[K, V]) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		c.ForceCleanup()
	}
}

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

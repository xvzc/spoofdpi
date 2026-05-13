package cache

import (
	"container/list"
	"sync"
)

type lruEntry[K Key, V any] struct {
	key   K
	value V
}

type lruShardNode[K Key, V any] struct {
	mu       sync.Mutex
	items    map[K]*list.Element
	list     *list.List
	capacity int
}

type LRUCache[K Key, V any] struct {
	shards       []*lruShardNode[K, V]
	mask         uint64
	onInvalidate func(K, V)
}

func NewLRUCache[K Key, V any](
	numShards int,
	totalCapacity int,
	onInvalidate func(K, V),
) Cache[K, V] {
	if numShards <= 0 || numShards&(numShards-1) != 0 {
		panic("numShards must be a power of 2")
	}
	capPerShard := totalCapacity / numShards
	if capPerShard <= 0 {
		capPerShard = 1
	}
	shards := make([]*lruShardNode[K, V], numShards)
	for i := range shards {
		shards[i] = &lruShardNode[K, V]{
			items:    make(map[K]*list.Element, capPerShard),
			list:     list.New(),
			capacity: capPerShard,
		}
	}
	return &LRUCache[K, V]{
		shards:       shards,
		mask:         uint64(numShards - 1),
		onInvalidate: onInvalidate,
	}
}

func (c *LRUCache[K, V]) shard(key K) *lruShardNode[K, V] {
	return c.shards[fnv1aBytes(key.Bytes())&c.mask]
}

func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem, ok := s.items[key]; ok {
		s.list.MoveToFront(elem)
		return elem.Value.(*lruEntry[K, V]).value, true
	}
	var zero V
	return zero, false
}

func (c *LRUCache[K, V]) Set(key K, value V, opts *options) bool {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	if opts == nil {
		opts = Options()
	}

	elem, ok := s.items[key]
	if ok && opts.skipExisting {
		return false
	}
	if !ok && opts.updateExistingOnly {
		return false
	}

	if ok {
		entry := elem.Value.(*lruEntry[K, V])
		if c.onInvalidate != nil {
			c.onInvalidate(entry.key, entry.value)
		}
		entry.value = value
		s.list.MoveToFront(elem)
		return true
	}

	entry := &lruEntry[K, V]{key: key, value: value}
	elem = s.list.PushFront(entry)
	s.items[key] = elem

	if s.list.Len() > s.capacity {
		tail := s.list.Back()
		if tail != nil {
			e := tail.Value.(*lruEntry[K, V])
			s.list.Remove(tail)
			delete(s.items, e.key)
			if c.onInvalidate != nil {
				c.onInvalidate(e.key, e.value)
			}
		}
	}

	return true
}

func (c *LRUCache[K, V]) Delete(key K) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if elem, ok := s.items[key]; ok {
		e := elem.Value.(*lruEntry[K, V])
		s.list.Remove(elem)
		delete(s.items, e.key)
		if c.onInvalidate != nil {
			c.onInvalidate(e.key, e.value)
		}
	}
}

func (c *LRUCache[K, V]) Has(key K) bool {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[key]
	return ok
}

func (c *LRUCache[K, V]) ForEach(f func(key K, value V) error) error {
	for _, s := range c.shards {
		s.mu.Lock()
		for _, elem := range s.items {
			entry := elem.Value.(*lruEntry[K, V])
			if err := f(entry.key, entry.value); err != nil {
				s.mu.Unlock()
				return err
			}
		}
		s.mu.Unlock()
	}
	return nil
}

func (c *LRUCache[K, V]) Size() int {
	total := 0
	for _, s := range c.shards {
		s.mu.Lock()
		total += s.list.Len()
		s.mu.Unlock()
	}
	return total
}

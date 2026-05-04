package netutil

import (
	"context"
	"net"
	"time"

	"github.com/xvzc/spoofdpi/internal/cache"
)

// ConnRegistry manages UDP connections with LRU eviction policy and idle timeout.
type ConnRegistry[K comparable] struct {
	storage cache.Cache[K]
	timeout time.Duration
}

// NewConnRegistry creates a new pool with the specified capacity and timeout.
func NewConnRegistry[K comparable](
	capacity int,
	timeout time.Duration,
) *ConnRegistry[K] {
	p := &ConnRegistry[K]{
		timeout: timeout,
	}

	onInvalidate := func(k K, v any) {
		if conn, ok := v.(*IdleTimeoutConn); ok {
			_ = conn.Conn.Close()
		}
	}

	p.storage = cache.NewLRUCache(capacity, onInvalidate)

	return p
}

// RunCleanupLoop runs the background cleanup goroutine.
// It exits when appctx is cancelled, closing all remaining cached connections.
func (p *ConnRegistry[K]) RunCleanupLoop(appctx context.Context) {
	// Cleanup interval: half of timeout, min 10s, max 60s
	cleanupInterval := p.timeout / 2
	cleanupInterval = max(cleanupInterval, 10*time.Second)
	cleanupInterval = min(cleanupInterval, 60*time.Second)

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-appctx.Done():
				p.CloseAll()
				return
			case <-ticker.C:
				p.evictExpired()
			}
		}
	}()
}

// Store adds a connection to the cache and returns the wrapped connection.
// If the key already exists, the old connection is closed and evicted first.
// If capacity is full, evicts the least recently used connection.
func (p *ConnRegistry[K]) Store(key K, rawConn net.Conn) *IdleTimeoutConn {
	wrapper := NewIdleTimeoutConn(rawConn, p.timeout)
	wrapper.Key = key

	wrapper.onActivity = func() {
		p.storage.Get(key)
	}

	wrapper.onClose = func() {
		p.Evict(key)
	}

	p.storage.Set(key, wrapper, nil)

	return wrapper
}

// Fetch retrieves a connection from the pool, refreshing its LRU status.
func (p *ConnRegistry[K]) Fetch(key K) (*IdleTimeoutConn, bool) {
	if val, ok := p.storage.Get(key); ok {
		return val.(*IdleTimeoutConn), true
	}
	return nil, false
}

// Evict closes and removes the connection from the pool.
func (p *ConnRegistry[K]) Evict(key K) {
	p.storage.Delete(key)
}

// Has checks if the connection exists in the cache.
func (p *ConnRegistry[K]) Has(key K) bool {
	return p.storage.Has(key)
}

// Size returns the number of connections in the pool.
func (p *ConnRegistry[K]) Size() int {
	return p.storage.Size()
}

// CloseAll closes all connections in the pool.
func (p *ConnRegistry[K]) CloseAll() {
	var toRemove []K
	_ = p.storage.ForEach(func(key K, value any) error {
		toRemove = append(toRemove, key)
		return nil
	})
	for _, k := range toRemove {
		p.Evict(k) // safely removes without deadlocking
	}
}

func (p *ConnRegistry[K]) evictExpired() {
	now := time.Now()
	var toRemove []K
	_ = p.storage.ForEach(func(key K, value any) error {
		if conn, ok := value.(*IdleTimeoutConn); ok {
			if conn.IsExpired(now) {
				toRemove = append(toRemove, key)
			}
		}
		return nil
	})
	for _, k := range toRemove {
		p.Evict(k)
	}
}

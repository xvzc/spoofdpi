package netutil

import (
	"context"
	"net"
	"time"

	"github.com/xvzc/spoofdpi/internal/cache"
)

// ConnRegistry manages UDP connections with LRU eviction policy and idle timeout.
type ConnRegistry[K cache.Key] struct {
	storage cache.Cache[K, *IdleTimeoutConn]
	timeout time.Duration
}

// NewConnRegistry creates a new pool with the specified capacity and timeout.
func NewConnRegistry[K cache.Key](
	capacity int,
	timeout time.Duration,
) *ConnRegistry[K] {
	p := &ConnRegistry[K]{
		timeout: timeout,
	}

	onInvalidate := func(_ K, v *IdleTimeoutConn) {
		_ = v.Conn.Close()
	}

	p.storage = cache.NewLRUCache[K, *IdleTimeoutConn](16, capacity, onInvalidate)

	return p
}

// RunCleanupLoop runs the background cleanup goroutine.
// It exits when appctx is cancelled, closing all remaining cached connections.
func (p *ConnRegistry[K]) RunCleanupLoop(appctx context.Context) {
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
	return p.storage.Get(key)
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
	_ = p.storage.ForEach(func(key K, _ *IdleTimeoutConn) error {
		toRemove = append(toRemove, key)
		return nil
	})
	for _, k := range toRemove {
		p.Evict(k)
	}
}

func (p *ConnRegistry[K]) evictExpired() {
	now := time.Now()
	var toRemove []K
	_ = p.storage.ForEach(func(key K, conn *IdleTimeoutConn) error {
		if conn.IsExpired(now) {
			toRemove = append(toRemove, key)
		}
		return nil
	})
	for _, k := range toRemove {
		p.Evict(k)
	}
}

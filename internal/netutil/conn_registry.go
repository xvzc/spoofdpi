package netutil

import (
	"context"
	"net"
	"time"

	"github.com/xvzc/spoofdpi/internal/cache"
)

// connRegistryCleanupInterval is how often RunCleanupLoop sweeps for
// expired connections. Each connection carries its own idle timeout, so the
// sweep can't be derived from one; it only backs up the readers, which
// evict a connection as soon as its read deadline passes.
const connRegistryCleanupInterval = 10 * time.Second

// ConnRegistry manages UDP connections with LRU eviction policy and a
// per-connection idle timeout.
type ConnRegistry[K cache.Key] struct {
	storage cache.Cache[K, *IdleTimeoutConn]
}

// NewConnRegistry creates a new pool with the specified capacity.
func NewConnRegistry[K cache.Key](capacity int) *ConnRegistry[K] {
	p := &ConnRegistry[K]{}

	onInvalidate := func(_ K, v *IdleTimeoutConn) {
		_ = v.Conn.Close()
	}

	p.storage = cache.NewLRUCache[K, *IdleTimeoutConn](16, capacity, onInvalidate)

	return p
}

// RunCleanupLoop runs the background cleanup goroutine.
// It exits when appctx is cancelled, closing all remaining cached connections.
func (p *ConnRegistry[K]) RunCleanupLoop(appctx context.Context) {
	go func() {
		ticker := time.NewTicker(connRegistryCleanupInterval)
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

// Store adds a connection to the cache and returns the wrapped connection,
// which expires after timeout without reads or writes (never when timeout
// is 0). If capacity is full, evicts the least recently used connection.
func (p *ConnRegistry[K]) Store(
	key K,
	rawConn net.Conn,
	timeout time.Duration,
) *IdleTimeoutConn {
	wrapper := NewIdleTimeoutConn(rawConn, timeout)
	wrapper.Key = key

	wrapper.onActivity = func() {
		p.storage.Get(key)
	}

	wrapper.onClose = func() {
		p.EvictFunc(key, func(v *IdleTimeoutConn) bool { return v == wrapper })
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

// EvictFunc closes and removes the connection stored under key if evict
// reports true for it, and reports whether it did. Comparing the stored
// connection with one's own keeps a replaced connection from evicting its
// replacement. evict runs under the pool's lock and must not call back into
// the pool.
func (p *ConnRegistry[K]) EvictFunc(key K, evict func(*IdleTimeoutConn) bool) bool {
	return p.storage.DeleteFunc(key, evict)
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
	toRemove := make(map[K]*IdleTimeoutConn)
	_ = p.storage.ForEach(func(key K, conn *IdleTimeoutConn) error {
		if conn.IsExpired(now) {
			toRemove[key] = conn
		}
		return nil
	})
	for k, conn := range toRemove {
		p.evictIfExpired(k, conn)
	}
}

// evictIfExpired evicts conn from key unless it was replaced or refreshed
// by activity since it was found expired.
func (p *ConnRegistry[K]) evictIfExpired(key K, conn *IdleTimeoutConn) bool {
	return p.EvictFunc(key, func(v *IdleTimeoutConn) bool {
		return v == conn && v.IsExpired(time.Now())
	})
}

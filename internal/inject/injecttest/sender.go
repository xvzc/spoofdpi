// Package injecttest provides an in-memory inject.Sender for tests.
package injecttest

import (
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/xvzc/spoofdpi/internal/inject"
)

// Sender records the packets it is given instead of sending them. It is
// safe for concurrent use. The zero value is ready to use.
type Sender struct {
	mu      sync.Mutex
	packets []inject.Packet
	err     error
	closed  bool
}

var _ inject.Sender = (*Sender)(nil)

// Send records a copy of p, or fails without recording it: with the error
// set with SetErr, or with net.ErrClosed after Close. Like a real Sender,
// it returns failures as an *inject.SendError for p.Dst; an error that
// already is one is returned as is.
func (s *Sender) Send(p inject.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return inject.NewSendError(p.Dst, net.ErrClosed)
	}
	if s.err != nil {
		var sendErr *inject.SendError
		if errors.As(s.err, &sendErr) {
			return s.err
		}
		return inject.NewSendError(p.Dst, s.err)
	}
	p.L4 = slices.Clone(p.L4)
	s.packets = append(s.packets, p)
	return nil
}

// Close marks the sender closed.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// SetErr makes every following Send fail with err; nil makes them succeed
// again.
func (s *Sender) SetErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Packets returns the packets sent so far, in order.
func (s *Sender) Packets() []inject.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.packets)
}

// Closed reports whether Close was called.
func (s *Sender) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

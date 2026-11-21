//go:build !linux

package capture

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/pcap"
)

var _ Handle = (*DefaultHandle)(nil)

type DefaultHandle struct {
	*pcap.Handle
}

func NewHandle(iface *net.Interface) (Handle, error) {
	return openHandle(iface, 0)
}

// NewHandleWithReadTimeout is like NewHandle, but ReadPacketData returns an
// error for which IsReadTimeout is true when no packet arrives within d.
// d must be positive.
func NewHandleWithReadTimeout(iface *net.Interface, d time.Duration) (Handle, error) {
	if d <= 0 {
		return nil, fmt.Errorf("read timeout must be positive, got %v", d)
	}
	return openHandle(iface, d)
}

// IsReadTimeout reports whether err is the error ReadPacketData returns
// when the read timeout of a handle from NewHandleWithReadTimeout expires.
func IsReadTimeout(err error) bool {
	return errors.Is(err, pcap.NextErrorTimeoutExpired)
}

// openHandle opens a pcap handle on iface; readTimeout 0 means reads block
// until a packet arrives.
func openHandle(iface *net.Interface, readTimeout time.Duration) (Handle, error) {
	iHandle, err := pcap.NewInactiveHandle(iface.Name)
	if err != nil {
		return nil, err
	}
	// CleanUp closes the pcap handle on every failure path. A successful
	// Activate hands the pcap handle over to the active Handle, which makes
	// the deferred CleanUp a no-op.
	defer iHandle.CleanUp()

	// max bytes per packet to capture
	err = iHandle.SetSnapLen(3200)
	if err != nil {
		return nil, err
	}

	// in immediate mode, packets are delivered to the application
	// as soon as they arrive. In other words, this overrides SetTimeout.
	err = iHandle.SetImmediateMode(true)
	if err != nil {
		return nil, err
	}

	// gopacket still applies the timeout in immediate mode: it polls the
	// handle for at most readTimeout before ReadPacketData gives up.
	if readTimeout > 0 {
		err = iHandle.SetTimeout(readTimeout)
		if err != nil {
			return nil, err
		}
	}

	// create a pcap handle
	handle, err := iHandle.Activate()
	if err != nil {
		return nil, err
	}

	return &DefaultHandle{handle}, nil
}

func (h *DefaultHandle) ClearBPF() error {
	return h.SetBPFFilter("")
}

func (h *DefaultHandle) SetBPFRawInstructionFilter(
	inst []BPFInstruction,
) error {
	var converted []pcap.BPFInstruction
	for _, v := range inst {
		converted = append(converted, pcap.BPFInstruction{
			Code: v.Op, Jt: v.Jt, Jf: v.Jf, K: v.K,
		})
	}

	return h.SetBPFInstructionFilter(converted)
}

//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// LinuxHandle uses standard syscalls (via x/sys/unix) to capture/inject packets.
// This ensures compatibility across all Linux architectures (including 386/MIPS).
type LinuxHandle struct {
	fd      int
	ifIndex int
	buf     []byte
}

// NewHandle opens a raw socket using unix package.
func NewHandle(iface *net.Interface) (Handle, error) {
	// 1. Protocol Setup (Network Byte Order)
	proto := htons(unix.ETH_P_ALL)

	// 2. Open Raw Socket (AF_PACKET, SOCK_RAW)
	// unix.Socket handles architecture differences (like socketcall on 386)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("failed to open raw socket: %w", err)
	}

	// 3. Bind to Interface
	// Handle "any" interface logic (index 0)
	bindIndex := 0
	if iface != nil && iface.Name != "any" {
		bindIndex = iface.Index
	}

	sll := &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  bindIndex,
	}

	if err := unix.Bind(fd, sll); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to bind raw socket: %w", err)
	}

	h := &LinuxHandle{
		fd:      fd,
		ifIndex: bindIndex,
		buf:     make([]byte, 65535),
	}

	return h, nil
}

// NewWriteHandle opens a raw socket that only writes frames to iface. Its
// protocol is 0, so the kernel delivers it no packets: it costs nothing
// while unread. ReadPacketData on it never returns.
func NewWriteHandle(iface *net.Interface) (Handle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw socket: %w", err)
	}
	return &LinuxHandle{fd: fd, ifIndex: iface.Index}, nil
}

// NewHandleWithReadTimeout is like NewHandle, but ReadPacketData returns an
// error for which IsReadTimeout is true when no packet arrives within d.
// d must be positive.
func NewHandleWithReadTimeout(iface *net.Interface, d time.Duration) (Handle, error) {
	if d <= 0 {
		return nil, fmt.Errorf("read timeout must be positive, got %v", d)
	}

	h, err := NewHandle(iface)
	if err != nil {
		return nil, err
	}

	tv := unix.NsecToTimeval(d.Nanoseconds())
	lh := h.(*LinuxHandle)
	if err := unix.SetsockoptTimeval(
		lh.fd,
		unix.SOL_SOCKET,
		unix.SO_RCVTIMEO,
		&tv,
	); err != nil {
		lh.Close()
		return nil, fmt.Errorf("failed to set read timeout: %w", err)
	}

	return lh, nil
}

// IsReadTimeout reports whether err is the error ReadPacketData returns
// when the read timeout of a handle from NewHandleWithReadTimeout expires.
func IsReadTimeout(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

// ReadPacketData reads using unix.Recvfrom
func (h *LinuxHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var n int
	for {
		var err error
		n, _, err = unix.Recvfrom(h.fd, h.buf, 0)
		// With SO_RCVTIMEO set, recvfrom can fail with EINTR on a signal
		// even under SA_RESTART; that is not a read failure.
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		break
	}

	data := make([]byte, n)
	copy(data, h.buf[:n])

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}

	return data, ci, nil
}

// WritePacketData injects packet using unix.Sendto
func (h *LinuxHandle) WritePacketData(data []byte) error {
	addr := &unix.SockaddrLinklayer{
		Ifindex: h.ifIndex,
	}
	return unix.Sendto(h.fd, data, 0, addr)
}

func (h *LinuxHandle) LinkType() layers.LinkType {
	// 1. "Any" device (tcpdump -i any) uses Linux SLL (Cooked Mode)
	if h.ifIndex == 0 {
		return layers.LinkTypeLinuxSLL
	}

	// 2. Get interface information by Index
	iface, err := net.InterfaceByIndex(h.ifIndex)
	if err != nil {
		// If fails to find interface, fallback to Ethernet
		return layers.LinkTypeEthernet
	}

	// 3. Check for VPN / TUN characteristics
	// - Case A: No Hardware Address (MAC) -> Typical for TUN devices
	// - Case B: Point-to-Point Flag -> Typical for VPN tunnels (WireGuard, OpenVPN)
	if len(iface.HardwareAddr) == 0 || iface.Flags&net.FlagPointToPoint != 0 {
		// Linux TUN devices provide Raw IP packets (No Link Header)
		// This corresponds to DLT_RAW (12) or DLT_IPV4/IPV6 (101)
		return layers.LinkTypeRaw
	}

	// 4. Default to Ethernet
	return layers.LinkTypeEthernet
}

func (h *LinuxHandle) Close() {
	_ = unix.Close(h.fd)
}

// SetBPFRawInstructionFilter attaches BPF using unix helper
func (h *LinuxHandle) SetBPFRawInstructionFilter(raw []BPFInstruction) error {
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{
			Code: r.Op,
			Jt:   r.Jt,
			Jf:   r.Jf,
			K:    r.K,
		}
	}

	fprog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// unix package handles the syscall number correctly for all archs
	err := unix.SetsockoptSockFprog(h.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
	if err != nil {
		return err
	}

	return nil
}

// ClearBPF detaches the filter
func (h *LinuxHandle) ClearBPF() error {
	// Dummy value 0 is sufficient
	return unix.SetsockoptInt(h.fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
}

// --- Endian Utils ---
func determineNativeEndian() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian
	default:
		panic("could not determine native endianness")
	}
}

func htons(v uint16) uint16 {
	if determineNativeEndian() == binary.LittleEndian {
		return (v << 8) | (v >> 8)
	}
	return v
}

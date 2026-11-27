//go:build darwin || freebsd

package netif

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifreqAddr is struct ifreq with an IPv4 address in ifr_addr. The layout
// is the same on darwin and FreeBSD.
type ifreqAddr struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

// AddAddr4 adds the IPv4 address of local, with the netmask of local, to
// the interface name, as `ifconfig name inet local dst` does. If the
// interface already has the address, the kernel replaces it.
//
// dst is the other end of a point-to-point interface; the zero Addr leaves
// it out. The kernel keeps dst in the same field as the broadcast address,
// so on a broadcast interface it reads dst as the broadcast address, and
// without dst it derives one from the netmask.
func AddAddr4(name string, local netip.Prefix, dst netip.Addr) error {
	if !local.IsValid() || !local.Addr().Is4() {
		return fmt.Errorf("add address to %s: %s is not an IPv4 prefix", name, local)
	}
	if dst.IsValid() && !dst.Is4() {
		return fmt.Errorf("add address to %s: %s is not an IPv4 address", name, dst)
	}
	ifName, err := interfaceName(name)
	if err != nil {
		return err
	}

	req := inAliasreq{
		Name: ifName,
		Addr: sockaddrInet4(local.Addr()),
		Mask: sockaddrInet4(netmask4(local.Bits())),
	}
	if dst.IsValid() {
		req.Dstaddr = sockaddrInet4(dst)
	}
	if err := ioctl(siocAIFADDR, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("add address %s to %s: %w", local, name, err)
	}
	return nil
}

// DelAddr4 deletes the IPv4 address addr from the interface name, as
// `ifconfig name inet addr delete` does. It fails with EADDRNOTAVAIL when
// the interface does not have addr.
func DelAddr4(name string, addr netip.Addr) error {
	if !addr.Is4() {
		return fmt.Errorf("delete address from %s: %s is not an IPv4 address", name, addr)
	}
	ifName, err := interfaceName(name)
	if err != nil {
		return err
	}

	req := ifreqAddr{Name: ifName, Addr: sockaddrInet4(addr)}
	if err := ioctl(unix.SIOCDIFADDR, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("delete address %s from %s: %w", addr, name, err)
	}
	return nil
}

// Flags returns the flags of the interface name, such as unix.IFF_UP.
func Flags(name string) (uint32, error) {
	ifName, err := interfaceName(name)
	if err != nil {
		return 0, err
	}

	req := ifreqFlags{Name: ifName}
	if err := ioctl(unix.SIOCGIFFLAGS, unsafe.Pointer(&req)); err != nil {
		return 0, fmt.Errorf("get flags of %s: %w", name, err)
	}
	return req.flags(), nil
}

// SetFlags sets the flags of the interface name. The kernel ignores the
// flags that only it may change, such as unix.IFF_RUNNING.
func SetFlags(name string, flags uint32) error {
	ifName, err := interfaceName(name)
	if err != nil {
		return err
	}

	req := ifreqFlags{Name: ifName}
	if err := req.setFlags(flags); err != nil {
		return fmt.Errorf("set flags of %s: %w", name, err)
	}
	if err := ioctl(unix.SIOCSIFFLAGS, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("set flags of %s: %w", name, err)
	}
	return nil
}

// SetUp brings the interface name up, as `ifconfig name up` does.
func SetUp(name string) error {
	flags, err := Flags(name)
	if err != nil {
		return err
	}
	return SetFlags(name, flags|unix.IFF_UP)
}

// SetDown brings the interface name down, as `ifconfig name down` does.
func SetDown(name string) error {
	flags, err := Flags(name)
	if err != nil {
		return err
	}
	return SetFlags(name, flags&^unix.IFF_UP)
}

// interfaceName returns name as the NUL-terminated array of an ifreq.
func interfaceName(name string) ([unix.IFNAMSIZ]byte, error) {
	var b [unix.IFNAMSIZ]byte
	if name == "" || len(name) >= unix.IFNAMSIZ || strings.IndexByte(name, 0) >= 0 {
		return b, fmt.Errorf("invalid interface name %q", name)
	}
	copy(b[:], name)
	return b, nil
}

func sockaddrInet4(addr netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   addr.As4(),
	}
}

// netmask4 returns the IPv4 netmask of a prefix of bits bits.
func netmask4(bits int) netip.Addr {
	var mask [4]byte
	binary.BigEndian.PutUint32(mask[:], ^uint32(0)<<(32-bits))
	return netip.AddrFrom4(mask)
}

// ioctl runs the interface ioctl req with arg on a new AF_INET socket.
func ioctl(req uint, arg unsafe.Pointer) error {
	fd, err := ioctlSocket()
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	// x/sys/unix wants libSystem wrappers on darwin, but it exports none
	// that takes an arbitrary ioctl argument, so the call goes through
	// syscall(2) there.
	//nolint:staticcheck // SA1019: no exported libSystem ioctl for a struct
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

package netif

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// siocAIFADDR is SIOCAIFADDR of <sys/sockio.h>, _IOW('i', 43, struct
// in_aliasreq). unix.SIOCAIFADDR is OSIOCAIFADDR, the FreeBSD 9 form
// without ifra_vhid that the kernel keeps for compatibility.
const siocAIFADDR = 0x8044692b

// inAliasreq is struct in_aliasreq of <netinet/in_var.h>.
type inAliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	// Dstaddr is ifra_broadaddr, which ifra_dstaddr names too.
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
	Vhid    int32
}

// ifreqFlags is struct ifreq with the flags in ifr_flags (low 16 bits)
// and ifr_flagshigh (high 16 bits).
type ifreqFlags struct {
	Name      [unix.IFNAMSIZ]byte
	Flags     uint16
	FlagsHigh uint16
	_         [12]byte
}

func (r *ifreqFlags) flags() uint32 {
	return uint32(r.Flags) | uint32(r.FlagsHigh)<<16
}

func (r *ifreqFlags) setFlags(flags uint32) error {
	r.Flags = uint16(flags)
	r.FlagsHigh = uint16(flags >> 16)
	return nil
}

// ifreqName is struct ifreq with only ifr_name set.
type ifreqName struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

// ifstat is struct ifstat of <net/if.h>.
type ifstat struct {
	Name  [unix.IFNAMSIZ]byte
	ASCII [801]byte
}

// Destroy destroys the cloned interface name, such as a tun, as
// `ifconfig name destroy` does. It fails with ENXIO when the interface does
// not exist.
//
// The kernel destroys a tun only after every process has closed it, and
// until then Destroy blocks. Once blocked, it cannot be cancelled or timed
// out: the kernel waits interruptibly, but the Go runtime installs its
// signal handlers with SA_RESTART, so the ioctl restarts after a signal.
// Check TunOpened first, and treat its answer as best-effort: a process can
// open the tun between TunOpened and Destroy.
func Destroy(name string) error {
	ifName, err := interfaceName(name)
	if err != nil {
		return err
	}

	req := ifreqName{Name: ifName}
	if err := ioctl(unix.SIOCIFDESTROY, unsafe.Pointer(&req)); err != nil {
		return fmt.Errorf("destroy %s: %w", name, err)
	}
	return nil
}

// TunOpened reports whether a process holds the tun interface name open.
// The result means nothing for an interface of another kind.
//
// It reads the interface status that ifconfig prints as "Opened by PID n".
// The tun driver writes it only while the device is open: tunopen sets the
// owner PID and tundtor, on the last close, clears it (sys/net/if_tuntap.c).
// Reading it needs no privilege and changes nothing. Opening /dev/name to
// see EBUSY would instead change the link state up and down and, on close,
// bring the interface down and purge its addresses.
func TunOpened(name string) (bool, error) {
	ifName, err := interfaceName(name)
	if err != nil {
		return false, err
	}

	req := ifstat{Name: ifName}
	if err := ioctl(unix.SIOCGIFSTATUS, unsafe.Pointer(&req)); err != nil {
		return false, fmt.Errorf("get status of %s: %w", name, err)
	}
	return req.ASCII[0] != 0, nil
}

func ioctlSocket() (int, error) {
	return unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
}

package netif

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// siocAIFADDR adds an address with a struct in_aliasreq.
const siocAIFADDR = unix.SIOCAIFADDR

// inAliasreq is struct in_aliasreq of <netinet/in_var.h>.
type inAliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	// Dstaddr is ifra_broadaddr, which ifra_dstaddr names too.
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

// ifreqFlags is struct ifreq with the flags in ifr_flags, a short.
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [14]byte
}

func (r *ifreqFlags) flags() uint32 {
	return uint32(r.Flags)
}

// setFlags fails when flags do not fit in ifr_flags.
func (r *ifreqFlags) setFlags(flags uint32) error {
	if flags > 0xffff {
		return fmt.Errorf("flags %#x do not fit in 16 bits", flags)
	}
	r.Flags = uint16(flags)
	return nil
}

func ioctlSocket() (int, error) {
	// darwin has no SOCK_CLOEXEC, so the fork lock keeps a concurrent fork
	// from inheriting the socket before it is marked close-on-exec.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

package desync

import (
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
)

// OpenIPv4Sender opens the sender that IPv4 fake packets leave through: a
// raw IP socket with opts applied, which TUN mode uses to pin it to the
// physical interface. The kernel routes the packets and resolves the next
// hop. It returns inject.ErrNeedsRoot, wrapped, without root.
func OpenIPv4Sender(opts inject.Options) (inject.Sender, error) {
	return inject.Open(netutil.FamilyV4, opts)
}

package desync

import (
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
)

// OpenSender opens the sender that the fake packets of fam leave through:
// a raw IP socket with opts applied, which TUN mode uses to pin it to the
// physical interface. The kernel routes the packets and resolves the next
// hop. It returns inject.ErrNeedsRoot, wrapped, without root.
func OpenSender(fam netutil.Family, opts inject.Options) (inject.Sender, error) {
	return inject.Open(fam, opts)
}

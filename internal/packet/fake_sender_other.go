//go:build !linux

package packet

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// OpenIPv4Sender opens the sender that IPv4 fake packets leave through. On
// darwin and FreeBSD it is a raw IP socket with opts applied, which TUN
// mode uses to pin it to the physical interface: the kernel routes the
// packets and resolves the next hop, so neither route nor ARP is needed.
// It returns inject.ErrNeedsRoot, wrapped, without root.
func OpenIPv4Sender(
	_ context.Context,
	_ zerolog.Logger,
	_ *netutil.Route,
	opts inject.Options,
) (inject.Sender, error) {
	return inject.Open(netutil.FamilyV4, opts)
}

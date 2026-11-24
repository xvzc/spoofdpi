//go:build linux

package packet

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/inject"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// gatewayResolveTimeout bounds the ARP lookup of the gateway's MAC address
// that fake packets are sent to.
const gatewayResolveTimeout = 10 * time.Second

// OpenIPv4Sender opens the sender that IPv4 fake packets leave through. On
// Linux it writes Ethernet frames on route's interface to the gateway's
// MAC address, which it resolves with ARP first and logs to logger. opts
// is not used: writing on route's interface already pins the frames to
// it. It returns inject.ErrNeedsRoot, wrapped, without the privileges to
// open its packet sockets.
func OpenIPv4Sender(
	ctx context.Context,
	logger zerolog.Logger,
	route *netutil.Route,
	_ inject.Options,
) (inject.Sender, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, gatewayResolveTimeout)
	defer cancel()
	gatewayMAC, err := ResolveGatewayMAC(
		resolveCtx,
		&route.Iface,
		route.LocalIP,
		route.Gateway,
	)
	if err != nil {
		return nil, l2SenderError(route, err)
	}
	logger.Info().
		Str("mac", gatewayMAC.String()).
		Msg(" gateway")
	sender, err := OpenL2Sender(&route.Iface, gatewayMAC)
	if err != nil {
		return nil, l2SenderError(route, err)
	}
	return sender, nil
}

// l2SenderError names route's interface in err, a failure to open the L2
// sender on it, and marks a lack of privileges with inject.ErrNeedsRoot.
func l2SenderError(route *netutil.Route, err error) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("on %s: %w: %w", route.Iface.Name, inject.ErrNeedsRoot, err)
	}
	return fmt.Errorf("on %s: %w", route.Iface.Name, err)
}

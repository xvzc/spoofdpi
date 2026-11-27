package netutil

import (
	"strings"
	"syscall"

	"github.com/rs/zerolog"
)

// SocketControl configures a socket before it is bound or connected, like
// net.Dialer.Control.
type SocketControl = func(network, address string, c syscall.RawConn) error

// ChainControls returns a control that runs first and then second, and
// stops at the first error. A nil control is skipped; it returns nil when
// both are nil.
func ChainControls(first, second SocketControl) SocketControl {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return func(network, address string, c syscall.RawConn) error {
		if err := first(network, address, c); err != nil {
			return err
		}
		return second(network, address, c)
	}
}

// NoAutoFlowLabelControl returns a control that turns the kernel's
// automatic flow label off on an IPv6 socket, as DisableAutoFlowLabel
// does. A failure is logged to logger at debug level and leaves the socket
// as it is, without failing it.
func NoAutoFlowLabelControl(logger zerolog.Logger) SocketControl {
	return func(network, address string, c syscall.RawConn) error {
		if err := DisableAutoFlowLabel(network, c); err != nil {
			logger.Debug().
				Err(err).
				Str("network", network).
				Str("addr", address).
				Msg("failed to turn the automatic IPv6 flow label off")
		}
		return nil
	}
}

// isIPv6Socket reports whether network, as a socket control gets it, such
// as "tcp6", "udp4" or "ip6:tcp", names an IPv6 socket. Go names a
// dual-stack socket by its AF_INET6 family, as "tcp6".
func isIPv6Socket(network string) bool {
	network, _, _ = strings.Cut(network, ":")
	return strings.HasSuffix(network, "6")
}

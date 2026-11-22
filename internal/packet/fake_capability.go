package packet

import "net"

// FakeCapability reports which destinations fake packets can be sent to.
type FakeCapability interface {
	// CanFake reports whether fake packets can be sent to dst.
	CanFake(dst net.IP) bool
}

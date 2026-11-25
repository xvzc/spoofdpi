package desync

import (
	"errors"
	"fmt"
	"net"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// FakeCapability reports which destinations fake packets can be sent to.
type FakeCapability interface {
	// CanFake returns nil when fake packets can be sent to dst, and an error
	// that says why they cannot otherwise.
	CanFake(dst net.IP) error
}

// Kinds of FakesOffError. Each names one cause, whatever destination or
// interface it is reported for.
const (
	// FakesOffIPv6Unsupported: fake packets are not sent over IPv6.
	FakesOffIPv6Unsupported = "ipv6-unsupported"
	// FakesOffVPNAtStartup: a full-tunnel VPN carried the traffic at
	// startup.
	FakesOffVPNAtStartup = "vpn-at-startup"
	// FakesOffDstViaVPN: the route to the destination goes through a VPN.
	FakesOffDstViaVPN = "dst-via-vpn"
)

// FakesOffError says that fake packets are off for an address family, or
// for a destination of it, and why.
type FakesOffError struct {
	Family netutil.Family
	// Kind names the cause, such as FakesOffDstViaVPN. Unlike Reason, it
	// does not depend on the destination, so it is, with Family and
	// Interface, a key for logging each cause once.
	Kind string
	// Interface is the name of the interface the cause is found on, or
	// empty when there is none.
	Interface string
	Reason    string
}

func (e *FakesOffError) Error() string {
	return fmt.Sprintf("fake packets are off for %s: %s", e.Family, e.Reason)
}

// StaticGate is a FakeCapability that answers by the address family of the
// destination alone.
type StaticGate struct {
	v4 error
	v6 error
}

var _ FakeCapability = (*StaticGate)(nil)

// NewStaticGate returns a gate that answers v4 for IPv4 destinations and v6
// for IPv6 ones. A nil error allows fake packets to that family.
func NewStaticGate(v4, v6 error) *StaticGate {
	return &StaticGate{v4: v4, v6: v6}
}

// CanFake returns the error of the family of dst. An IPv4-mapped IPv6 address
// is an IPv4 destination. A nil or invalid dst is an error.
func (g *StaticGate) CanFake(dst net.IP) error {
	if dst.To4() != nil {
		return g.v4
	}
	if len(dst) == net.IPv6len {
		return g.v6
	}
	return errors.New("fake packets need a valid destination address")
}

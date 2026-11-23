package netutil

// Family is an IP address family.
type Family uint8

const (
	FamilyV4 Family = iota + 1
	FamilyV6
)

func (f Family) String() string {
	switch f {
	case FamilyV4:
		return "ipv4"
	case FamilyV6:
		return "ipv6"
	default:
		return "unknown"
	}
}

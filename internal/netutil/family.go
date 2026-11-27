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

// FamilySet is a set of IP address families. The zero value is empty.
type FamilySet uint8

// NewFamilySet returns the set of fams.
func NewFamilySet(fams ...Family) FamilySet {
	var s FamilySet
	for _, f := range fams {
		s |= 1 << f
	}
	return s
}

// Has reports whether f is in s.
func (s FamilySet) Has(f Family) bool {
	return s&(1<<f) != 0
}

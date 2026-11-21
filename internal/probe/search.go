package probe

// maxOffset is the largest offset magnitude the offset searches try:
// mod 2^32, an offset of -2^31 is as far from the connection's own
// sequence numbers as an offset can be.
const maxOffset int64 = 1 << 31

// pointSide is how the attempt at one magnitude of an offset search came
// out.
type pointSide int

const (
	// sideBefore: the outcome of the small magnitudes, such as the DPI
	// fooled, or the server breaking.
	sideBefore pointSide = iota
	// sideAfter: the other outcome.
	sideAfter
	// sideUnknown: the attempt failed on this host.
	sideUnknown
)

// searchPoint is the result of the attempt at one magnitude. detail is
// the reason of sideUnknown, or what sideBefore found, such as how the
// server broke.
type searchPoint struct {
	side   pointSide
	detail string
}

// searchProbe makes the attempt at magnitude m, for the offset -m. ok is
// false when ctx ended.
type searchProbe func(m int64) (p searchPoint, ok bool)

// offsetSearch is the result of an offset search.
type offsetSearch struct {
	// unstable is set when the outcome flipped back past the flip.
	unstable bool
	// reason, if set, is why the search has no result: the attempt at a
	// magnitude failed on this host.
	reason string
	// lastBefore is the largest magnitude tried whose outcome is
	// sideBefore, 0 if none, and firstAfter the smallest tried whose
	// outcome is sideAfter, 0 if none; when both are set, firstAfter is
	// twice lastBefore.
	lastBefore, firstAfter int64
	// beforeDetail is the detail of the point at lastBefore.
	beforeDetail string
}

// searchOffset finds the power of two, from 1 to maxOffset, where the
// outcome of probe flips from sideBefore to sideAfter. It tries 1, 2, 4
// and so on up to maxOffset until a magnitude m is sideAfter, then 2m, if
// it is not past maxOffset, which must be sideAfter too. The search ends
// at the first magnitude that is unknown, or when the outcome flips back
// at 2m. ok is false when ctx ended.
func searchOffset(probe searchProbe) (s offsetSearch, ok bool) {
	for m := int64(1); ; m *= 2 {
		p, ok := probe(m)
		switch {
		case !ok:
			return offsetSearch{}, false
		case p.side == sideUnknown:
			return offsetSearch{reason: p.detail}, true
		case p.side == sideAfter:
			s.firstAfter = m
		default:
			s.lastBefore, s.beforeDetail = m, p.detail
		}
		if s.firstAfter != 0 || m == maxOffset {
			break
		}
	}
	if s.firstAfter == 0 {
		return s, true
	}

	// The outcome must hold past the flip: a DPI or server whose outcome
	// does not depend on the offset alone has no boundary to find.
	next := 2 * s.firstAfter
	if next > maxOffset {
		return s, true
	}
	p, ok := probe(next)
	switch {
	case !ok:
		return offsetSearch{}, false
	case p.side == sideUnknown:
		return offsetSearch{reason: p.detail}, true
	case p.side != sideAfter:
		return offsetSearch{unstable: true}, true
	}
	return s, true
}

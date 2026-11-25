package route

import (
	"fmt"
	"net/netip"
)

// rejectRouteError is the no-route error of a route prefix lookup that
// matched a reject or blackhole route whose prefix the kernel reported.
// It unwraps to the error of errNoRoute.
type rejectRouteError struct {
	prefix netip.Prefix
	err    error
}

func (e *rejectRouteError) Error() string {
	return fmt.Sprintf("%v (reject route %s)", e.err, e.prefix)
}

func (e *rejectRouteError) Unwrap() error { return e.err }

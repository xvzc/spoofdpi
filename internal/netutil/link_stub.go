//go:build !darwin && !freebsd

package netutil

import "runtime"

// linkInfo reports every link as unknown where the OS cannot be asked.
func linkInfo(index int) (LinkInfo, error) {
	return LinkInfo{
		Index:  index,
		Kind:   LinkUnknown,
		Detail: "link kinds are not supported on " + runtime.GOOS,
	}, nil
}

// defaultLinks reports no default routes where the OS cannot be asked.
func defaultLinks(Family) ([]LinkInfo, error) {
	return nil, nil
}

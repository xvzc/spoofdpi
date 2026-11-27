//go:build !darwin && !freebsd && !linux

package route

import "runtime"

// linkInfo reports every link as unknown where the OS cannot be asked.
func linkInfo(index int) (LinkInfo, error) {
	return LinkInfo{
		Index:  index,
		Kind:   LinkUnknown,
		Detail: "link kinds are not supported on " + runtime.GOOS,
	}, nil
}

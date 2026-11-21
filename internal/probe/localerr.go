package probe

import (
	"errors"
	"slices"
	"syscall"
)

// localErrnos are the errors of a socket call that fail on this host,
// for lack of resources or of a usable local address, without a packet
// reaching the network.
var localErrnos = []syscall.Errno{
	syscall.EMFILE,
	syscall.ENFILE,
	syscall.ENOBUFS,
	syscall.ENOMEM,
	syscall.EADDRNOTAVAIL,
	syscall.EADDRINUSE,
}

// localError returns the local error err is, if it is one. An attempt
// that fails with it says nothing about the path to the server.
func localError(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	return errno, slices.Contains(localErrnos, errno)
}

// localErrorReason is the reason given for a local error, such as
// "local error: too many open files".
func localErrorReason(errno syscall.Errno) string {
	return "local error: " + errno.Error()
}

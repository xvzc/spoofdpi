//go:build darwin || linux || freebsd

package server

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Seams for tests.
var (
	// effectiveUID is replaced because tests do not run as root.
	effectiveUID = os.Geteuid
	// beforeStateFileOpen runs between the Lstat check and the open, so tests
	// can swap the file there.
	beforeStateFileOpen = func(path string) {}
)

// openStateFile opens the state file at path for reading, refusing a file
// that another user could have planted: it must be a regular file owned by
// the effective user and writable by no one else. With requireSingleLink it
// must also have no other hard link, which refuses a stale state file that
// is still linked elsewhere. This narrows, but does not close, replay on
// macOS and FreeBSD: another user can link a live state file into a
// directory of their own and rename it back after the run, which leaves a
// single link. Removing the state files closes it. A refusal wraps
// errUntrustedState. The file is opened without following symlinks and
// checked again through the opened descriptor, so a swap after the first
// check cannot slip a different file in.
func openStateFile(path string, requireSingleLink bool) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkStateFileInfo(info, requireSingleLink); err != nil {
		return nil, err
	}
	beforeStateFileOpen(path)
	// O_NONBLOCK keeps a FIFO swapped in after the Lstat from blocking the
	// open; the check below rejects it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// FreeBSD reports EMLINK for a symlink under O_NOFOLLOW.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("%w: it is a symlink", errUntrustedState)
		}
		return nil, err
	}
	info, err = f.Stat()
	if err == nil {
		err = checkStateFileInfo(info, requireSingleLink)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func checkStateFileInfo(info fs.FileInfo, requireSingleLink bool) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: it is not a regular file", errUntrustedState)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: its owner is unknown", errUntrustedState)
	}
	if uid := effectiveUID(); int(st.Uid) != uid {
		return fmt.Errorf(
			"%w: it is owned by uid %d, not %d", errUntrustedState, st.Uid, uid,
		)
	}
	if requireSingleLink && uint64(st.Nlink) != 1 {
		return fmt.Errorf(
			"%w: it has %d hard links", errUntrustedState, uint64(st.Nlink),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"%w: it is writable by group or others (mode %04o)",
			errUntrustedState, info.Mode().Perm(),
		)
	}
	return nil
}

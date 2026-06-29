//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package privatefile

import (
	"os"

	"golang.org/x/sys/unix"
)

func openExistingRegularNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil // #nosec G115 -- unix.Open returns a valid file descriptor and os.NewFile requires uintptr.
}

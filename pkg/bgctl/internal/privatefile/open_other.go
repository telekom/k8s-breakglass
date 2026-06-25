//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package privatefile

import (
	"errors"
	"os"
)

func openExistingRegularNoFollow(path string) (*os.File, error) {
	return nil, errors.New("secure in-place private file rewrite is unsupported on this platform")
}

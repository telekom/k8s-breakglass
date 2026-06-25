//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package privatefile

func supportsSecureInPlaceRewrite() bool {
	return false
}

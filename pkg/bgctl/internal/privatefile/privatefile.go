package privatefile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CreateNew creates path for secret-bearing content readable only by the
// current user (mode 0600, or a protected owner-only DACL on Windows). It never
// replaces an existing file: an existing path fails with os.ErrExist.
func CreateNew(path string) (*os.File, error) {
	return createPrivateNew(path)
}

// Write stores secret-bearing local state with owner-only permissions.
func Write(path string, content []byte) (err error) {
	dir := filepath.Dir(path)
	file, err := createTempPrivate(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		if shouldWriteInPlace(path, err) {
			return writeInPlace(path, content)
		}
		return err
	}
	tmpPath := file.Name()
	closed := false
	defer func() {
		if !closed && err != nil {
			_ = file.Close()
		} else if !closed {
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(file, content); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return os.Rename(tmpPath, path)
}

func shouldWriteInPlace(path string, writeErr error) bool {
	if !supportsSecureInPlaceRewrite() {
		return false
	}
	if !os.IsPermission(writeErr) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func writeInPlace(path string, content []byte) (err error) {
	file, err := openExistingRegularNoFollow(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("target is not a regular file: %s", path)
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := secureFile(file); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return writeAll(file, content)
}

func writeAll(file *os.File, content []byte) error {
	for len(content) > 0 {
		n, err := file.Write(content)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		content = content[n:]
	}
	return nil
}

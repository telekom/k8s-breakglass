// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// diagnostic-artifact-safe-copy copies one coredump without allowing the
// caller to choose either filesystem root.  It intentionally has no command
// dispatch, environment-controlled paths, or shell escape hatch.
package main

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

const (
	sourceRootName = "/host-coredumps"
	outputRootName = "/output"
	maxPathBytes   = 512
	maxCopyBytes   = int64(503316480)

	destinationMode os.FileMode = 0600
)

var errCopyRejected = errors.New("copy rejected")

const sanitizedError = "diagnostic-artifact-safe-copy: copy failed\n"

// copyHook is only used by package tests.  Keeping the hook below the public
// entry point permits deterministic mutation tests without adding any runtime
// input or behavior to the image binary.
type copyHook func()

type fileMetadata struct {
	dev     uint64
	ino     uint64
	nlink   uint64
	size    int64
	modTime time.Time
}

func main() {
	if len(os.Args) != 2 || !validRelativePath(os.Args[1]) {
		_, _ = io.WriteString(os.Stderr, sanitizedError)
		os.Exit(2)
	}
	if err := copyFromFixedRoots(os.Args[1]); err != nil {
		// Do not print the path or an underlying filesystem error.  The caller
		// gets only the fixed exit status and the collector's generic failure.
		_, _ = io.WriteString(os.Stderr, sanitizedError)
		os.Exit(2)
	}
}

func copyFromFixedRoots(relativePath string) error {
	if !validRelativePath(relativePath) {
		return errCopyRejected
	}

	sourceRoot, err := os.OpenRoot(sourceRootName)
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = sourceRoot.Close() }()

	outputRoot, err := os.OpenRoot(outputRootName)
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = outputRoot.Close() }()

	stageRoot, err := openOnlyStage(outputRoot)
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = stageRoot.Close() }()

	filesRoot, err := openDirectory(stageRoot, "files")
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = filesRoot.Close() }()
	coredumpsRoot, err := openDirectory(filesRoot, "coredumps")
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = coredumpsRoot.Close() }()

	return copyOne(sourceRoot, coredumpsRoot, relativePath, nil)
}

func validRelativePath(name string) bool {
	if name == "" || len(name) > maxPathBytes || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return false
		}
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// openOnlyStage resolves the one private staging directory created by the
// collector.  ReadDir is rooted at an output directory descriptor, and the
// subsequent OpenRoot repeats all no-follow checks in the kernel.
func openOnlyStage(outputRoot *os.Root) (*os.Root, error) {
	entries, err := fs.ReadDir(outputRoot.FS(), ".")
	if err != nil {
		return nil, errCopyRejected
	}
	stageName := ""
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".staging.") || len(name) == len(".staging.") || !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if stageName != "" {
			return nil, errCopyRejected
		}
		stageName = name
	}
	if stageName == "" {
		return nil, errCopyRejected
	}
	return openDirectory(outputRoot, stageName)
}

func openDirectory(root *os.Root, name string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errCopyRejected
	}
	opened, err := root.OpenRoot(name)
	if err != nil {
		return nil, errCopyRejected
	}
	openedInfo, err := fs.Stat(opened.FS(), ".")
	if err != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = opened.Close()
		return nil, errCopyRejected
	}
	return opened, nil
}

func metadata(info os.FileInfo) (fileMetadata, bool) {
	if info == nil {
		return fileMetadata{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMetadata{}, false
	}
	return fileMetadata{
		dev:     uint64(stat.Dev),
		ino:     stat.Ino,
		nlink:   uint64(stat.Nlink),
		size:    info.Size(),
		modTime: info.ModTime(),
	}, true
}

func sameMetadata(a, b fileMetadata) bool {
	return a.dev == b.dev && a.ino == b.ino && a.size == b.size && a.modTime.Equal(b.modTime)
}

func regularSingleLink(info os.FileInfo, m fileMetadata) bool {
	return info.Mode().IsRegular() && m.nlink == 1
}

// copyOne opens both paths with descriptor-relative, no-follow operations.
// The destination is created exclusively before any source bytes are read;
// created tracks ownership so failure cleanup cannot remove a pre-existing
// collision.
func copyOne(sourceRoot, destinationRoot *os.Root, relativePath string, hook copyHook) error {
	return copyOneWithLimit(sourceRoot, destinationRoot, relativePath, maxCopyBytes, hook)
}

func copyOneWithLimit(sourceRoot, destinationRoot *os.Root, relativePath string, limit int64, hook copyHook) error {
	if !validRelativePath(relativePath) {
		return errCopyRejected
	}
	if limit < 0 || limit > maxCopyBytes {
		return errCopyRejected
	}

	sourceParent, err := openExistingParent(sourceRoot, path.Dir(relativePath))
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = sourceParent.Close() }()
	sourceLeaf := path.Base(relativePath)
	// Lstat gives a clear leaf-symlink rejection, while O_NOFOLLOW closes the
	// race between this check and opening the source descriptor.
	linkInfo, err := sourceParent.Lstat(sourceLeaf)
	if err != nil {
		return errCopyRejected
	}
	linkMetadata, metadataOK := metadata(linkInfo)
	if !metadataOK || linkInfo.Mode()&os.ModeSymlink != 0 || !regularSingleLink(linkInfo, linkMetadata) || linkMetadata.size < 0 || linkMetadata.size > limit {
		return errCopyRejected
	}
	source, err := sourceParent.OpenFile(sourceLeaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = source.Close() }()

	sourceInfo, err := source.Stat()
	if err != nil {
		return errCopyRejected
	}
	before, ok := metadata(sourceInfo)
	if !ok || !regularSingleLink(sourceInfo, before) || before.size < 0 || before.size > limit {
		return errCopyRejected
	}
	pathBeforeInfo, err := sourceParent.Stat(sourceLeaf)
	if err != nil {
		return errCopyRejected
	}
	pathBefore, ok := metadata(pathBeforeInfo)
	if !ok || !sameMetadata(before, pathBefore) || pathBefore.nlink != 1 {
		return errCopyRejected
	}

	parent, leaf := path.Dir(relativePath), path.Base(relativePath)
	destinationParent, err := openDestinationParent(destinationRoot, parent)
	if err != nil {
		return errCopyRejected
	}
	defer func() { _ = destinationParent.Close() }()

	destination, err := destinationParent.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL, destinationMode)
	if err != nil {
		return errCopyRejected
	}
	created := true
	defer func() {
		if created {
			// Remove is descriptor-relative and removes a symlink itself if a
			// hostile replacement happened; it cannot follow it outside root.
			_ = destinationParent.Remove(leaf)
		}
	}()

	firstHash, copied, err := copyAndHash(source, destination, limit)
	if err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	if hook != nil {
		hook()
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	secondHash, rehashed, err := hashBounded(source, limit)
	if err != nil || copied != rehashed || !sameHash(firstHash, secondHash) {
		_ = destination.Close()
		return errCopyRejected
	}

	// Check both the original descriptor and the path now visible beneath the
	// fixed source root.  This catches replacement, truncation, growth, and
	// same-size in-place mutation (the latter through the hash comparison).
	sourceAfterInfo, err := source.Stat()
	if err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	after, ok := metadata(sourceAfterInfo)
	if !ok || !regularSingleLink(sourceAfterInfo, after) || !sameMetadata(before, after) {
		_ = destination.Close()
		return errCopyRejected
	}
	pathAfterInfo, err := sourceParent.Stat(sourceLeaf)
	if err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	pathAfter, ok := metadata(pathAfterInfo)
	if !ok || !regularSingleLink(pathAfterInfo, pathAfter) || !sameMetadata(before, pathAfter) {
		_ = destination.Close()
		return errCopyRejected
	}
	originalPathAfterInfo, err := sourceRoot.Lstat(relativePath)
	if err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	originalPathAfter, ok := metadata(originalPathAfterInfo)
	if !ok || !regularSingleLink(originalPathAfterInfo, originalPathAfter) || !sameMetadata(before, originalPathAfter) {
		_ = destination.Close()
		return errCopyRejected
	}
	destinationInfo, err := destination.Stat()
	if err != nil || destinationInfo.Size() != copied || copied > limit || destination.Chmod(destinationMode) != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		return errCopyRejected
	}
	if err := destination.Close(); err != nil {
		return errCopyRejected
	}
	created = false
	return nil
}

func openExistingParent(root *os.Root, parent string) (*os.Root, error) {
	if parent == "." {
		return root.OpenRoot(".")
	}
	current := root
	for _, part := range strings.Split(parent, "/") {
		if part == "" || part == "." || part == ".." {
			if current != root {
				_ = current.Close()
			}
			return nil, errCopyRejected
		}
		info, err := current.Lstat(part)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if current != root {
				_ = current.Close()
			}
			return nil, errCopyRejected
		}
		next, err := current.OpenRoot(part)
		if current != root {
			_ = current.Close()
		}
		if err != nil {
			return nil, errCopyRejected
		}
		openedInfo, statErr := fs.Stat(next.FS(), ".")
		if statErr != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			return nil, errCopyRejected
		}
		current = next
	}
	return current, nil
}

func openDestinationParent(root *os.Root, parent string) (*os.Root, error) {
	if parent == "." {
		return root.OpenRoot(".")
	}
	current := root
	parts := strings.Split(parent, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			if current != root {
				_ = current.Close()
			}
			return nil, errCopyRejected
		}
		info, err := current.Lstat(part)
		if errors.Is(err, fs.ErrNotExist) {
			if err := current.Mkdir(part, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
				if current != root {
					_ = current.Close()
				}
				return nil, errCopyRejected
			}
			info, err = current.Lstat(part)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if current != root {
				_ = current.Close()
			}
			return nil, errCopyRejected
		}
		next, err := current.OpenRoot(part)
		if current != root {
			_ = current.Close()
		}
		if err != nil {
			return nil, errCopyRejected
		}
		openedInfo, statErr := fs.Stat(next.FS(), ".")
		if statErr != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			return nil, errCopyRejected
		}
		current = next
	}
	return current, nil
}

func copyAndHash(source, destination *os.File, limit int64) ([sha256.Size]byte, int64, error) {
	hash := sha256.New()
	buf := make([]byte, 64*1024)
	var copied int64
	for {
		read, readErr := source.Read(buf)
		if read > 0 {
			if read > int(limit-copied) {
				return [sha256.Size]byte{}, copied, errCopyRejected
			}
			if _, err := hash.Write(buf[:read]); err != nil {
				return [sha256.Size]byte{}, copied, errCopyRejected
			}
			written, err := destination.Write(buf[:read])
			if err != nil || written != read {
				return [sha256.Size]byte{}, copied, errCopyRejected
			}
			copied += int64(read)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [sha256.Size]byte{}, copied, errCopyRejected
		}
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum, copied, nil
}

func hashBounded(source *os.File, limit int64) ([sha256.Size]byte, int64, error) {
	hash := sha256.New()
	buf := make([]byte, 64*1024)
	var count int64
	for {
		read, readErr := source.Read(buf)
		if read > 0 {
			if read > int(limit-count) {
				return [sha256.Size]byte{}, count, errCopyRejected
			}
			if _, err := hash.Write(buf[:read]); err != nil {
				return [sha256.Size]byte{}, count, errCopyRejected
			}
			count += int64(read)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return [sha256.Size]byte{}, count, errCopyRejected
		}
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum, count, nil
}

func sameHash(a, b [sha256.Size]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

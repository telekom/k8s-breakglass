//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ProvisionResult reports what Provision did to the volume.
type ProvisionResult string

const (
	// Provisioned means both roots were empty and now carry the sentinels.
	Provisioned ProvisionResult = "provisioned"
	// AlreadyProvisioned means both roots already carry this instance's
	// sentinels; nothing was changed.
	AlreadyProvisioned ProvisionResult = "already provisioned"
)

// Provision is the administrator-initiated provisioning step for a fresh
// volume. It creates missing roots as private directories owned by the calling
// process and writes both sentinels, but only when both roots are empty. A
// volume that already carries this instance's sentinels is left untouched.
// Non-empty roots without a sentinel, foreign sentinels, partially provisioned
// volumes and unsafe ownership or modes are refused. Open still never
// provisions, so a repointed volume keeps failing closed until an
// administrator runs this step again.
func Provision(config Config) (ProvisionResult, error) {
	validated, err := config.validate()
	if err != nil {
		return "", err
	}
	for _, root := range []string{validated.ArtifactRoot, validated.StagingRoot} {
		if err := createPrivateRoot(root); err != nil {
			return "", fmt.Errorf("create local artifact root %s: %w", root, err)
		}
	}
	return provisionRoots(validated)
}

func provisionRoots(config Config) (result ProvisionResult, resultErr error) {
	artifactRoot, artifactStat, err := openRoot(config.ArtifactRoot, config)
	if err != nil {
		return "", fmt.Errorf("open local artifact root for provisioning: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, artifactRoot.Close()) }()
	stagingRoot, stagingStat, err := openRoot(config.StagingRoot, config)
	if err != nil {
		return "", fmt.Errorf("open local staging root for provisioning: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, stagingRoot.Close()) }()
	if artifactStat.Dev != stagingStat.Dev {
		return "", errors.New("local artifact and staging roots are not on the same filesystem")
	}
	roots := []*os.File{artifactRoot, stagingRoot}
	provisioned := 0
	for _, root := range roots {
		hasSentinel, err := provisionState(root, config)
		if err != nil {
			return "", err
		}
		if hasSentinel {
			provisioned++
		}
	}
	switch provisioned {
	case len(roots):
		return AlreadyProvisioned, nil
	case 0:
	default:
		return "", errors.New("local artifact volume is partially provisioned; refusing to provision")
	}
	for _, root := range roots {
		if err := provisionSentinel(root, config); err != nil {
			return "", err
		}
	}
	return Provisioned, nil
}

// provisionState reports whether root carries this instance's sentinel. A root
// without a sentinel must be empty.
func provisionState(root *os.File, config Config) (bool, error) {
	if _, err := statNameNoFollow(root, sentinelName); err == nil {
		if err := verifySentinel(root, config); err != nil {
			return false, fmt.Errorf("verify local artifact sentinel in %s: %w", root.Name(), err)
		}
		return true, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return false, fmt.Errorf("inspect local artifact sentinel in %s: %w", root.Name(), err)
	}
	if _, err := root.Readdirnames(1); !errors.Is(err, io.EOF) {
		if err != nil {
			return false, fmt.Errorf("list local artifact root %s: %w", root.Name(), err)
		}
		return false, fmt.Errorf("local artifact root %s is not empty and has no sentinel; refusing to provision", root.Name())
	}
	return false, nil
}

// createPrivateRoot creates a missing root as a 0700 directory. An existing
// entry is left for openRoot to verify.
func createPrivateRoot(path string) (result error) {
	parent, _, err := openDirectoryNoFollow(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer func() { result = errors.Join(result, parent.Close()) }()
	parentFD, err := fileDescriptor(parent)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	if err := unix.Mkdirat(parentFD, name, rootMode); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return err
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	created, err := fileFromDescriptor(fd, path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, created.Close()) }()
	// mkdir honours the umask and inherits the set-group-ID bit of fsGroup
	// volume roots; Open requires exactly 0700.
	if err := unix.Fchmod(fd, rootMode); err != nil {
		return fmt.Errorf("set root mode: %w", err)
	}
	return syncDirectory(parent)
}

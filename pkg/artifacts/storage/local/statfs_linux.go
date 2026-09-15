//go:build linux

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"os"

	"golang.org/x/sys/unix"
)

func availableBytes(directory *os.File) (int64, error) {
	fd, err := fileDescriptor(directory)
	if err != nil {
		return 0, err
	}
	var stats unix.Statfs_t
	if err := unix.Fstatfs(fd, &stats); err != nil {
		return 0, err
	}
	if stats.Bsize < 0 {
		return 0, unix.EINVAL
	}
	return availableCapacity(uint64(stats.Bsize), stats.Bavail)
}

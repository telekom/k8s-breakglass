// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
	"syscall"
)

func metadata(info os.FileInfo) (fileMetadata, bool) {
	if info == nil {
		return fileMetadata{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMetadata{}, false
	}
	return fileMetadata{
		// Darwin exposes st_dev as a signed int32. Preserve its exact native
		// representation for identity comparison rather than widening a
		// potentially negative value to an unrelated uint64 device number.
		dev:     strconv.FormatInt(int64(stat.Dev), 10),
		ino:     stat.Ino,
		nlink:   uint64(stat.Nlink),
		size:    info.Size(),
		modTime: info.ModTime(),
	}, true
}

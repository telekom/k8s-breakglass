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
		dev:     strconv.FormatUint(stat.Dev, 10),
		ino:     stat.Ino,
		nlink:   stat.Nlink,
		size:    info.Size(),
		modTime: info.ModTime(),
	}, true
}

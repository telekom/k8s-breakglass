//go:build linux

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameNoReplace(oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
	oldFD, err := fileDescriptor(oldRoot)
	if err != nil {
		return err
	}
	newFD, err := fileDescriptor(newRoot)
	if err != nil {
		return err
	}
	return unix.Renameat2(oldFD, oldName, newFD, newName, unix.RENAME_NOREPLACE)
}

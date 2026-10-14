// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHostOpenRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "kernel")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, err := (hostSystem{}).open(link); err == nil {
		file.Close()
		t.Fatal("open followed a symlink")
	}
}

func TestHostSnapshotIsSealedAgainstWrites(t *testing.T) {
	snapshot, err := (hostSystem{}).snapshot("kernel")
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if _, err := snapshot.Write([]byte("kernel-image")); err != nil {
		t.Fatal(err)
	}
	if err := (hostSystem{}).seal(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.WriteAt([]byte("x"), 0); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("write after seal = %v, want EPERM", err)
	}
}

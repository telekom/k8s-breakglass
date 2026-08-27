// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRequireCapabilitiesFailsClosedInStableOrder(t *testing.T) {
	t.Parallel()
	status := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(status, []byte("CapEff:\t0000000000000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := requireCapabilities(status)
	if err == nil || !strings.Contains(err.Error(), "NET_RAW") {
		t.Fatalf("first missing capability error = %v, want NET_RAW", err)
	}
	mask := (uint64(1) << 13) | (uint64(1) << 19) | (uint64(1) << 21)
	if err := os.WriteFile(status, []byte("CapEff:\t"+strconv.FormatUint(mask, 16)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireCapabilities(status); err != nil {
		t.Fatalf("required capabilities rejected: %v", err)
	}
}

func TestRunCaptureFailsBeforeProcScanWithoutRequiredCapabilities(t *testing.T) {
	// The pinned builder deliberately lacks SYS_ADMIN/SYS_PTRACE. This executes
	// the real entry path and proves it rejects the privilege boundary before
	// examining a caller-selected target.
	err := runCapture(options{podUID: testUID, interfaceName: "any", duration: 1, count: 1, snaplen: 64, output: "capture.pcap"})
	if err == nil || !strings.Contains(err.Error(), "required capability") {
		t.Fatalf("unprivileged runCapture error = %v", err)
	}
}

func TestSetCaptureFileLimit(t *testing.T) {
	// One GiB remains far above all test and coverage artifacts while exercising
	// the same hard-limit syscall used for the <=2.8 MiB production bound.
	if err := setCaptureFileLimit(1 << 30); err != nil {
		t.Fatalf("setCaptureFileLimit() error = %v", err)
	}
}

func TestSecureOutputIsExclusiveAndCleanupIsInodeOwned(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	file, path, err := createSecureOutput(root, "capture.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := createSecureOutput(root, "capture.pcap"); err == nil {
		t.Fatal("existing output was overwritten")
	}
	if err := verifyOwnedOutput(file, path); err != nil {
		t.Fatalf("owned output rejected: %v", err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("not owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnedOutput(file, path); err == nil {
		t.Fatal("replaced output path was accepted")
	}
	removeOwnedOutput(file, path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cleanup removed a replaced output path: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceFileIdentityAndCallerIsolation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	selfNamespace := filepath.Join(root, "thread-self", "ns", "net")
	initNamespace := filepath.Join(root, "1", "ns", "net")
	writeFixtureFile(t, selfNamespace, "self")
	writeFixtureFile(t, initNamespace, "init")
	if err := requireIsolatedCallerNetns(root); err != nil {
		t.Fatalf("isolated caller rejected: %v", err)
	}
	file, err := os.Open(selfNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	opened, err := statOpenFile(file)
	if err != nil {
		t.Fatal(err)
	}
	fromPath, err := statNamespace(selfNamespace)
	if err != nil || opened != fromPath {
		t.Fatalf("open namespace identity = %#v, path = %#v, err = %v", opened, fromPath, err)
	}
	if err := os.Remove(initNamespace); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(selfNamespace, initNamespace); err != nil {
		t.Fatal(err)
	}
	if err := requireIsolatedCallerNetns(root); err == nil || !strings.Contains(err.Error(), "hostNetwork=false") {
		t.Fatalf("host-network caller error = %v", err)
	}
}

func TestSecureOutputRejectsWritableOrSymlinkDirectory(t *testing.T) {
	t.Parallel()
	writable := filepath.Join(t.TempDir(), "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createSecureOutput(writable, "capture.pcap"); err == nil {
		t.Fatal("group/world-writable output directory was accepted")
	}
	realDirectory := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDirectory, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := createSecureOutput(symlink, "capture.pcap"); err == nil {
		t.Fatal("symlink output directory was accepted")
	}
}

func TestRejectRuntimeSockets(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	socketClue := filepath.Join(root, "containerd.sock")
	if err := os.WriteFile(socketClue, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectRuntimeSockets([]string{filepath.Join(root, "absent")}); err != nil {
		t.Fatalf("absent runtime socket rejected: %v", err)
	}
	if err := rejectRuntimeSockets([]string{socketClue}); err == nil || !strings.Contains(err.Error(), "must not be mounted") {
		t.Fatalf("visible runtime socket clue accepted: %v", err)
	}
}

func TestStopProcessGracefulAndForced(t *testing.T) {
	graceful := exec.Command("/bin/sleep", "30")
	if err := graceful.Start(); err != nil {
		t.Fatal(err)
	}
	gracefulWait := make(chan error, 1)
	go func() { gracefulWait <- graceful.Wait() }()
	err := stopProcess(graceful.Process, gracefulWait)
	if !expectedTcpdumpStop(err) {
		t.Fatalf("SIGINT stop was not recognized: %v", err)
	}

	forced := exec.Command(os.Args[0], "-test.run=TestSignalIgnoringHelperProcess")
	forced.Env = append(os.Environ(), "POD_CAPTURE_SIGNAL_HELPER=1")
	if err := forced.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	forcedWait := make(chan error, 1)
	go func() { forcedWait <- forced.Wait() }()
	if err := stopProcess(forced.Process, forcedWait); !errors.Is(err, errForcedTcpdumpKill) {
		t.Fatalf("forced stop error = %v, want %v", err, errForcedTcpdumpKill)
	}
}

func TestSignalIgnoringHelperProcess(t *testing.T) {
	if os.Getenv("POD_CAPTURE_SIGNAL_HELPER") != "1" {
		return
	}
	signal.Ignore(syscall.SIGINT)
	time.Sleep(30 * time.Second)
}

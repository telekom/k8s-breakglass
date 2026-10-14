// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testBootID = "0f0e0d0c-0b0a-4908-8706-050403020100"

var testDeadline = time.Unix(2000000000, 0)

type fakeSystem struct {
	dir         string
	files       map[string]string
	loaded      string
	loadErr     error
	rebootErr   error
	calls       []string
	loadCmdline []byte
	// expireAfter makes the clock pass the deadline once this call happened.
	expireAfter string
}

func (f *fakeSystem) readFile(path string) ([]byte, error) {
	if path == kexecLoadedPath {
		return []byte(f.loaded), nil
	}
	if path == bootIDPath {
		return []byte(testBootID + "\n"), nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeSystem) open(path string) (*os.File, error) {
	f.calls = append(f.calls, "open "+path)
	return os.Open(f.files[path])
}

func (f *fakeSystem) snapshot(string) (*os.File, error) { return os.CreateTemp(f.dir, "snapshot") }
func (f *fakeSystem) seal(*os.File) error               { f.calls = append(f.calls, "seal"); return nil }

func (f *fakeSystem) kexecFileLoad(kernelFD, initrdFD int, cmdline []byte) error {
	f.calls = append(f.calls, "load")
	f.loadCmdline = append([]byte(nil), cmdline...)
	if f.loadErr == nil {
		f.loaded = "1\n"
	}
	return f.loadErr
}

func (f *fakeSystem) kexecUnload() error { f.calls = append(f.calls, "unload"); return nil }
func (f *fakeSystem) sync()              { f.calls = append(f.calls, "sync") }
func (f *fakeSystem) ignoreTermination() { f.calls = append(f.calls, "ignore-signals") }
func (f *fakeSystem) rebootKexec() error { f.calls = append(f.calls, "reboot"); return f.rebootErr }

func (f *fakeSystem) now() time.Time {
	for _, call := range f.calls {
		if call == f.expireAfter {
			return testDeadline
		}
	}
	return testDeadline.Add(-time.Hour)
}

func newFixture(t *testing.T, cmdline string) (*fakeSystem, request) {
	t.Helper()
	dir := t.TempDir()
	contents := map[string]string{kernelPath: "kernel-image", initrdPath: "initrd-image", cmdlinePath: cmdline}
	files := map[string]string{}
	for path, content := range contents {
		local := filepath.Join(dir, filepath.Base(path))
		if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		files[path] = local
	}
	req := request{bootID: testBootID, kernelSHA256: sha256Hex([]byte("kernel-image")),
		initrdSHA256: sha256Hex([]byte("initrd-image")), cmdlineSHA256: sha256Hex([]byte(cmdline)), deadline: testDeadline}
	return &fakeSystem{dir: dir, files: files, loaded: "0\n"}, req
}

func TestRunLoadsVerifiedKernelThenSyncsAndReboots(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0 root=/dev/vda1\n")
	sys.rebootErr = errors.New("still running")
	err := run(sys, req, io.Discard)
	if err == nil {
		t.Fatal("a returning reboot must fail")
	}
	want := []string{"open " + kernelPath, "seal", "open " + initrdPath, "seal", "open " + cmdlinePath, "seal", "ignore-signals", "load", "sync", "reboot", "unload"}
	if !reflect.DeepEqual(sys.calls, want) {
		t.Fatalf("calls = %q, want %q", sys.calls, want)
	}
	if string(sys.loadCmdline) != "console=ttyS0 root=/dev/vda1\x00" {
		t.Fatalf("cmdline = %q", sys.loadCmdline)
	}
}

func TestRunNeverLoadsOrRebootsOnDigestMismatch(t *testing.T) {
	for _, field := range []string{"kernel", "initrd", "cmdline"} {
		t.Run(field, func(t *testing.T) {
			sys, req := newFixture(t, "console=ttyS0")
			switch field {
			case "kernel":
				req.kernelSHA256 = strings.Repeat("0", 64)
			case "initrd":
				req.initrdSHA256 = strings.Repeat("0", 64)
			case "cmdline":
				req.cmdlineSHA256 = strings.Repeat("0", 64)
			}
			if err := run(sys, req, io.Discard); err == nil || !strings.Contains(err.Error(), "approved SHA-256") {
				t.Fatalf("run() = %v, want digest mismatch", err)
			}
			for _, call := range sys.calls {
				if call == "load" || call == "reboot" || call == "sync" {
					t.Fatalf("mismatch reached %q", call)
				}
			}
		})
	}
}

func TestVerifiedKernelIgnoresLaterWritesToTheSource(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0")
	kernel, err := openVerified(sys, kernelPath, req.kernelSHA256, kernelMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer kernel.Close()
	if err := os.WriteFile(sys.files[kernelPath], []byte("other-image!"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := io.ReadAll(kernel)
	if err != nil || string(loaded) != "kernel-image" {
		t.Fatalf("loaded %q (%v), want the verified bytes", loaded, err)
	}
}

func TestRunNeverLoadsAfterTheDeadlinePassedDuringVerification(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0")
	sys.expireAfter = "open " + cmdlinePath
	if err := run(sys, req, io.Discard); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("run() = %v, want a deadline refusal", err)
	}
	for _, call := range sys.calls {
		if call == "load" || call == "reboot" {
			t.Fatalf("an expired approval reached %q", call)
		}
	}
}

func TestRunUnloadsInsteadOfRebootingAfterTheDeadline(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0")
	sys.expireAfter = "sync"
	if err := run(sys, req, io.Discard); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("run() = %v, want a deadline refusal", err)
	}
	want := []string{"open " + kernelPath, "seal", "open " + initrdPath, "seal", "open " + cmdlinePath, "seal", "ignore-signals", "load", "sync", "unload"}
	if !reflect.DeepEqual(sys.calls, want) {
		t.Fatalf("calls = %q, want %q", sys.calls, want)
	}
}

func TestRunRefusesAChangedBootID(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0")
	req.bootID = "11111111-2222-4333-8444-555555555555"
	if err := run(sys, req, io.Discard); err == nil || len(sys.calls) != 0 {
		t.Fatalf("run() = %v with calls %q, want refusal before any open", err, sys.calls)
	}
}

func TestRunUnloadsWhenTheKernelIsNotReportedLoaded(t *testing.T) {
	sys, req := newFixture(t, "console=ttyS0")
	fake := &notLoadedSystem{fakeSystem: sys}
	if err := run(fake, req, io.Discard); err == nil {
		t.Fatal("an unreported load must fail")
	}
	if got := fake.calls[len(fake.calls)-1]; got != "unload" {
		t.Fatalf("last call = %q, want unload", got)
	}
	for _, call := range fake.calls {
		if call == "reboot" {
			t.Fatal("an unreported load must never reboot")
		}
	}
}

// notLoadedSystem accepts the load call but leaves kexec_loaded at 0.
type notLoadedSystem struct{ *fakeSystem }

func (n *notLoadedSystem) kexecFileLoad(int, int, []byte) error {
	n.calls = append(n.calls, "load")
	return nil
}

func TestRunRejectsUnsafeCommandLines(t *testing.T) {
	for name, cmdline := range map[string]string{"two lines": "console=ttyS0\ninit=/bin/sh", "control": "console=ttyS0\x1b"} {
		t.Run(name, func(t *testing.T) {
			sys, req := newFixture(t, cmdline)
			if err := run(sys, req, io.Discard); err == nil {
				t.Fatal("unsafe cmdline accepted")
			}
			for _, call := range sys.calls {
				if call == "load" {
					t.Fatal("unsafe cmdline reached kexec_file_load")
				}
			}
		})
	}
}

func TestParseRequestAcceptsOnlyFixedShape(t *testing.T) {
	digest := strings.Repeat("a", 64)
	req, err := parseRequest([]string{testBootID, digest, digest, digest, "2000000000"})
	if err != nil || !req.deadline.Equal(testDeadline) {
		t.Fatalf("parseRequest() = %v, %v", req.deadline, err)
	}
	for name, args := range map[string][]string{
		"missing deadline": {testBootID, digest, digest, digest},
		"extra path":       {testBootID, digest, digest, digest, "2000000000", "/host/boot/vmlinuz"},
		"path deadline":    {testBootID, digest, digest, digest, "/host/boot/vmlinuz"},
		"signed deadline":  {testBootID, digest, digest, digest, "-1"},
		"long deadline":    {testBootID, digest, digest, digest, "999999999999"},
		"uppercase digest": {testBootID, strings.ToUpper(digest), digest, digest, "2000000000"},
		"prefixed digest":  {testBootID, "sha256:" + digest[7:], digest, digest, "2000000000"},
		"bad boot ID":      {"not-a-uuid", digest, digest, digest, "2000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRequest(args); err == nil {
				t.Fatalf("parseRequest(%q) succeeded", args)
			}
		})
	}
}

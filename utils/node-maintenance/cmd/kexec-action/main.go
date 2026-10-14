// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// kexec-action loads one digest-verified recovery kernel from the fixed
// read-only /recovery mount and reboots into it. It accepts no paths, no
// command line and no flags from the caller.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	kernelPath      = "/recovery/kernel"
	initrdPath      = "/recovery/initrd"
	cmdlinePath     = "/recovery/cmdline"
	bootIDPath      = "/proc/sys/kernel/random/boot_id"
	kexecLoadedPath = "/sys/kernel/kexec_loaded"

	kernelMaxBytes  = 256 << 20
	initrdMaxBytes  = 512 << 20
	cmdlineMaxBytes = 4096
)

var (
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	bootIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	unixPattern   = regexp.MustCompile(`^[1-9][0-9]{0,10}$`)
)

type request struct {
	bootID, kernelSHA256, initrdSHA256, cmdlineSHA256 string
	// deadline is the approved action deadline; nothing is loaded or
	// rebooted at or after it.
	deadline time.Time
}

// system isolates every host interaction so the fail-safe ordering is testable.
type system interface {
	readFile(path string) ([]byte, error)
	open(path string) (*os.File, error)
	// snapshot returns an anonymous file that no other process can open.
	snapshot(name string) (*os.File, error)
	// seal makes a snapshot immutable before the kernel reads it.
	seal(file *os.File) error
	// ignoreTermination makes SIGTERM, SIGINT and SIGHUP inert, so from the
	// kernel load on only SIGKILL can interrupt load, sync and reboot.
	ignoreTermination()
	kexecFileLoad(kernelFD, initrdFD int, cmdline []byte) error
	kexecUnload() error
	sync()
	rebootKexec() error
	now() time.Time
}

func main() {
	req, err := parseRequest(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "kexec-action: %v\n", err)
		os.Exit(2)
	}
	if err := run(hostSystem{}, req, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "kexec-action: %v\n", err)
		os.Exit(1)
	}
}

func parseRequest(args []string) (request, error) {
	if len(args) != 5 {
		return request{}, errors.New("requires exactly BOOT_ID KERNEL_SHA256 INITRD_SHA256 CMDLINE_SHA256 DEADLINE_UNIX")
	}
	req := request{bootID: args[0], kernelSHA256: args[1], initrdSHA256: args[2], cmdlineSHA256: args[3]}
	if !unixPattern.MatchString(args[4]) {
		return request{}, errors.New("deadline must be an exact Unix timestamp")
	}
	deadline, err := strconv.ParseInt(args[4], 10, 64)
	if err != nil {
		return request{}, errors.New("deadline must be an exact Unix timestamp")
	}
	req.deadline = time.Unix(deadline, 0)
	if !bootIDPattern.MatchString(req.bootID) {
		return request{}, errors.New("boot ID must be an exact lowercase UUID")
	}
	for _, digest := range []string{req.kernelSHA256, req.initrdSHA256, req.cmdlineSHA256} {
		if !sha256Pattern.MatchString(digest) {
			return request{}, errors.New("digests must be exact lowercase SHA-256 values")
		}
	}
	return req, nil
}

// run never reboots unless the Node incarnation, all three digests, the
// approved deadline and the kernel load are proven. A loaded kernel is
// unloaded on every later failure.
func run(sys system, req request, out io.Writer) error {
	bootID, err := sys.readFile(bootIDPath)
	if err != nil {
		return fmt.Errorf("read boot ID: %w", err)
	}
	if strings.TrimSpace(string(bootID)) != req.bootID {
		return errors.New("node boot ID changed since approval; refusing to load a kernel")
	}
	kernel, err := openVerified(sys, kernelPath, req.kernelSHA256, kernelMaxBytes)
	if err != nil {
		return err
	}
	defer func() { _ = kernel.Close() }()
	initrd, err := openVerified(sys, initrdPath, req.initrdSHA256, initrdMaxBytes)
	if err != nil {
		return err
	}
	defer func() { _ = initrd.Close() }()
	cmdline, err := readCmdline(sys, req.cmdlineSHA256)
	if err != nil {
		return err
	}
	// Copying and hashing up to 768 MiB takes time, so the deadline is
	// re-checked immediately before each mutation.
	if !sys.now().Before(req.deadline) {
		return errors.New("approved action deadline expired; no kernel was loaded")
	}
	// A termination signal after the load would leave a loaded kernel and an
	// unknown outcome; before the load it is harmless.
	sys.ignoreTermination()
	if err := sys.kexecFileLoad(int(kernel.Fd()), int(initrd.Fd()), cmdline); err != nil {
		return fmt.Errorf("kexec_file_load: %w", err)
	}
	loaded, err := sys.readFile(kexecLoadedPath)
	if err != nil || strings.TrimSpace(string(loaded)) != "1" {
		return errors.Join(errors.New("kernel did not report a loaded kexec image"), err, sys.kexecUnload())
	}
	_, _ = fmt.Fprintf(out, "kexec_loaded=1 kernel_sha256=%s initrd_sha256=%s cmdline_sha256=%s\n", req.kernelSHA256, req.initrdSHA256, req.cmdlineSHA256)
	sys.sync()
	if !sys.now().Before(req.deadline) {
		return errors.Join(errors.New("approved action deadline expired before reboot"), sys.kexecUnload())
	}
	if err := sys.rebootKexec(); err != nil {
		return errors.Join(fmt.Errorf("reboot into loaded kernel: %w", err), sys.kexecUnload())
	}
	return errors.Join(errors.New("reboot returned without executing the loaded kernel"), sys.kexecUnload())
}

// openVerified copies the source into a sealed private snapshot and hashes
// exactly the copied bytes, so a later in-place write to the host file cannot
// change what the kernel loads.
func openVerified(sys system, path, expected string, maxBytes int64) (*os.File, error) {
	source, err := sys.open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("%s must be a non-empty regular file within its size limit", path)
	}
	snapshot, err := sys.snapshot(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", path, err)
	}
	hash := sha256.New()
	copied, err := io.Copy(io.MultiWriter(snapshot, hash), io.LimitReader(source, maxBytes+1))
	if err != nil || copied > maxBytes {
		_ = snapshot.Close()
		return nil, errors.Join(fmt.Errorf("copy %s within its size limit", path), err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		_ = snapshot.Close()
		return nil, fmt.Errorf("%s does not match its approved SHA-256", path)
	}
	if err := sys.seal(snapshot); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("seal %s: %w", path, err)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		_ = snapshot.Close()
		return nil, fmt.Errorf("rewind %s: %w", path, err)
	}
	return snapshot, nil
}

// readCmdline returns the verified command line with one optional trailing
// newline removed and a NUL terminator, as kexec_file_load expects.
func readCmdline(sys system, expected string) ([]byte, error) {
	file, err := openVerified(sys, cmdlinePath, expected, cmdlineMaxBytes)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, cmdlineMaxBytes+1))
	if err != nil || len(content) > cmdlineMaxBytes || sha256Hex(content) != expected {
		return nil, fmt.Errorf("%s changed while it was read", cmdlinePath)
	}
	content = bytes.TrimSuffix(content, []byte("\n"))
	for _, b := range content {
		if b < 0x20 || b == 0x7f {
			return nil, fmt.Errorf("%s may contain only one printable line", cmdlinePath)
		}
	}
	return append(content, 0), nil
}

func sha256Hex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const cloneNewnet = 0x40000000

var errForcedTcpdumpKill = errors.New("tcpdump did not stop after SIGINT")

var prohibitedRuntimeSockets = []string{
	"/run/containerd/containerd.sock",
	"/var/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/var/run/docker.sock",
}

func main() {
	opts, err := parseOptions(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		usage(os.Stdout)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pod-netns-capture: %s\n", stableError(err))
		usage(os.Stderr)
		os.Exit(2)
	}
	if err := runCapture(opts); err != nil {
		fmt.Fprintf(os.Stderr, "pod-netns-capture: %s\n", stableError(err))
		os.Exit(1)
	}
}

func runCapture(opts options) (returnErr error) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	if err := requireCapabilities(filepath.Join(procRoot, "self", "status")); err != nil {
		return err
	}
	if err := requireIsolatedCallerNetns(procRoot); err != nil {
		return err
	}
	if err := rejectRuntimeSockets(prohibitedRuntimeSockets); err != nil {
		return err
	}
	if info, err := os.Stat(tcpdumpPath); err != nil || info.Mode()&0o111 == 0 {
		return fmt.Errorf("fixed tcpdump executable is unavailable")
	}

	scanner := procScanner{root: procRoot}
	target, err := scanner.scanTarget(opts.podUID)
	if err != nil {
		return err
	}
	anchor := target.processes[0]
	namespaceFile, err := os.Open(filepath.Join(procRoot, strconv.Itoa(anchor.pid), "ns", "net"))
	if err != nil {
		return fmt.Errorf("open target network namespace: %w", err)
	}
	defer namespaceFile.Close()
	openedNamespace, err := statOpenFile(namespaceFile)
	if err != nil {
		return err
	}
	if openedNamespace != target.namespace {
		return fmt.Errorf("target network namespace changed while opening it")
	}
	outputFile, outputPath, err := createSecureOutput(workRoot, opts.output)
	if err != nil {
		return err
	}
	keepOutput := false
	defer func() {
		if !keepOutput {
			removeOwnedOutput(outputFile, outputPath)
		}
		_ = outputFile.Close()
	}()
	if err := setCaptureFileLimit(captureSizeBound(opts.count, opts.snaplen)); err != nil {
		return err
	}
	// Open the namespace first, then perform the final cgroup/start-time scan
	// immediately before namespace entry. This ordering is the PID-reuse
	// boundary; do not move caller-controlled work into this gap.
	if err := scanner.revalidate(anchor, opts.podUID, openedNamespace); err != nil {
		return err
	}
	select {
	case <-signals:
		return fmt.Errorf("capture interrupted")
	default:
	}

	// setns is deliberately called exactly once. Locking the goroutine keeps
	// the Go runtime from reusing a thread whose namespace has changed. The
	// tcpdump fork/exec inherits this thread's target network namespace.
	runtime.LockOSThread()
	if _, _, errno := syscall.RawSyscall(setnsSyscallNumber, namespaceFile.Fd(), cloneNewnet, 0); errno != 0 {
		return fmt.Errorf("enter target network namespace: %w", errno)
	}
	currentNamespace, err := statNamespace(filepath.Join(procRoot, "thread-self", "ns", "net"))
	if err != nil || currentNamespace != openedNamespace {
		return fmt.Errorf("network namespace entry could not be verified")
	}
	args := []string{"-p", "-n", "-i", opts.interfaceName, "-s", strconv.Itoa(opts.snaplen), "-c", strconv.Itoa(opts.count), "-w", "/proc/self/fd/3"}
	if opts.filter != "" {
		args = append(args, "--", opts.filter)
	}
	command := exec.Command(tcpdumpPath, args...)
	command.ExtraFiles = []*os.File{outputFile}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start fixed tcpdump command: %w", err)
	}

	interrupted := false
	waitResult := make(chan error, 1)
	go func() { waitResult <- command.Wait() }()
	timer := time.NewTimer(waitBound(opts.duration))
	defer timer.Stop()
	var waitErr error
	select {
	case waitErr = <-waitResult:
	case <-timer.C:
		waitErr = stopProcess(command.Process, waitResult)
	case <-signals:
		interrupted = true
		waitErr = stopProcess(command.Process, waitResult)
	}
	if interrupted {
		return fmt.Errorf("capture interrupted")
	}
	if errors.Is(waitErr, errForcedTcpdumpKill) {
		return waitErr
	}
	if waitErr != nil && !expectedTcpdumpStop(waitErr) {
		return fmt.Errorf("tcpdump capture failed")
	}
	if err := outputFile.Sync(); err != nil {
		return fmt.Errorf("sync capture output: %w", err)
	}
	if err := verifyOwnedOutput(outputFile, outputPath); err != nil {
		return err
	}
	packets, size, hash, err := hashAndInspectCapture(outputFile, opts)
	if err != nil {
		return err
	}
	if err := outputFile.Chmod(0o600); err != nil {
		return fmt.Errorf("protect capture output: %w", err)
	}
	if err := outputSummary(os.Stdout, opts, packets, size, hash); err != nil {
		return fmt.Errorf("write capture summary: %w", err)
	}
	keepOutput = true
	return nil
}

func statOpenFile(file *os.File) (namespaceID, error) {
	info, err := file.Stat()
	if err != nil {
		return namespaceID{}, fmt.Errorf("stat opened network namespace: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return namespaceID{}, fmt.Errorf("opened network namespace does not expose an inode")
	}
	return namespaceID{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func requireCapabilities(statusPath string) error {
	contents, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Errorf("read effective capabilities: %w", err)
	}
	capabilities := []struct {
		bit  int
		name string
	}{{bit: 13, name: "NET_RAW"}, {bit: 19, name: "SYS_PTRACE"}, {bit: 21, name: "SYS_ADMIN"}}
	var effective uint64
	found := false
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "CapEff:" {
			parsed, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil {
				return fmt.Errorf("effective capability mask is malformed")
			}
			effective = parsed
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("effective capability mask is unavailable")
	}
	for _, capability := range capabilities {
		if effective&(uint64(1)<<capability.bit) == 0 {
			return fmt.Errorf("required capability %s is unavailable", capability.name)
		}
	}
	return nil
}

func requireIsolatedCallerNetns(root string) error {
	selfNamespace, err := statNamespace(filepath.Join(root, "thread-self", "ns", "net"))
	if err != nil {
		return fmt.Errorf("inspect caller network namespace: %w", err)
	}
	initNamespace, err := statNamespace(filepath.Join(root, "1", "ns", "net"))
	if err != nil {
		return fmt.Errorf("inspect host network namespace: %w", err)
	}
	if selfNamespace == initNamespace {
		return fmt.Errorf("caller must use hostPID=true with hostNetwork=false")
	}
	return nil
}

func rejectRuntimeSockets(paths []string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("CRI/runtime sockets must not be mounted")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect prohibited runtime socket path: %w", err)
		}
	}
	return nil
}

func createSecureOutput(root, name string) (*os.File, string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, "", fmt.Errorf("inspect output directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return nil, "", fmt.Errorf("/work must be a non-symlink directory not writable by group or other")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != uint32(os.Geteuid()) {
		return nil, "", fmt.Errorf("/work must be owned by the capture helper user")
	}
	path := filepath.Join(root, name)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create exclusive capture output: %w", err)
	}
	return file, path, nil
}

func verifyOwnedOutput(file *os.File, path string) error {
	openInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open capture output: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openInfo, pathInfo) {
		return fmt.Errorf("capture output path changed during execution")
	}
	return nil
}

func removeOwnedOutput(file *os.File, path string) {
	openInfo, openErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if openErr == nil && pathErr == nil && pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(openInfo, pathInfo) {
		_ = os.Remove(path)
	}
}

func setCaptureFileLimit(size int64) error {
	limit := syscall.Rlimit{Cur: uint64(size), Max: uint64(size)}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		return fmt.Errorf("set capture output-size limit: %w", err)
	}
	return nil
}

func stopProcess(process *os.Process, waitResult <-chan error) error {
	_ = process.Signal(syscall.SIGINT)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-waitResult:
		return err
	case <-timer.C:
		_ = process.Kill()
		<-waitResult
		return errForcedTcpdumpKill
	}
}

func expectedTcpdumpStop(err error) bool {
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return false
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGINT
}

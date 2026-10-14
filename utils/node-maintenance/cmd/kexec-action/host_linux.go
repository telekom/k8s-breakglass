// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

// The image builds the helper with the standard library only.
const (
	kexecFileUnload = 0x1

	mfdCloexec       = 0x1
	mfdAllowSealing  = 0x2
	fcntlAddSeals    = 1033
	sealSeal         = 0x1
	sealShrink       = 0x2
	sealGrow         = 0x4
	sealWrite        = 0x8
	sealAllForKernel = sealSeal | sealShrink | sealGrow | sealWrite
)

type hostSystem struct{}

func (hostSystem) readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// open refuses a final-component symlink and never follows it.
func (hostSystem) open(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

func (hostSystem) snapshot(name string) (*os.File, error) {
	label := []byte("kexec-recovery\x00")
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(&label[0])), mfdCloexec|mfdAllowSealing, 0) // #nosec G103 -- memfd_create requires the address of the NUL-terminated label, which stays live through the call.
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, name), nil
}

func (hostSystem) seal(file *os.File) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), fcntlAddSeals, sealAllForKernel); errno != 0 {
		return errno
	}
	return nil
}

func (hostSystem) kexecFileLoad(kernelFD, initrdFD int, cmdline []byte) error {
	return kexecFileLoadSyscall(kernelFD, initrdFD, cmdline, 0)
}

func (hostSystem) kexecUnload() error { return kexecFileLoadSyscall(-1, -1, nil, kexecFileUnload) }

func (hostSystem) sync() { syscall.Sync() }

func (hostSystem) ignoreTermination() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
}

func (hostSystem) rebootKexec() error { return syscall.Reboot(syscall.LINUX_REBOOT_CMD_KEXEC) }

func (hostSystem) now() time.Time { return time.Now() }

func kexecFileLoadSyscall(kernelFD, initrdFD int, cmdline []byte, flags uintptr) error {
	var pointer unsafe.Pointer
	if len(cmdline) > 0 {
		pointer = unsafe.Pointer(&cmdline[0]) // #nosec G103 -- kexec_file_load requires the address of the NUL-terminated command line, which stays live through the call.
	}
	_, _, errno := syscall.Syscall6(sysKexecFileLoad, uintptr(kernelFD), uintptr(initrdFD),
		uintptr(len(cmdline)), uintptr(pointer), flags, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

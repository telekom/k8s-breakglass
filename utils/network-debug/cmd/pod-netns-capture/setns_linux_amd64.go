// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

// SYS_setns from Linux arch/x86/entry/syscalls/syscall_64.tbl.
const setnsSyscallNumber = 308

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build linux && arm64

package main

// __NR_setns from Linux include/uapi/asm-generic/unistd.h.
const setnsSyscallNumber = 268

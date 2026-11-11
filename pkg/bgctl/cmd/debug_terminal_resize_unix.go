// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyResize(signals chan<- os.Signal) { signal.Notify(signals, syscall.SIGWINCH) }

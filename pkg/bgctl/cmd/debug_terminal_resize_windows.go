// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

import "os"

// Windows consoles have no SIGWINCH; the initial size is still sent.
func notifyResize(chan<- os.Signal) {}

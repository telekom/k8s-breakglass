// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package privatefile

import "os"

func secureFile(_ *os.File) error { return nil }

func createTempPrivate(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern+"*") }

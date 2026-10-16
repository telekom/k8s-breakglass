// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "errors"

func run(request, string) error {
	return errors.New("service-action requires Linux and systemd's private socket")
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "errors"

func execute(actionRequest) error {
	return errors.New("kernel network actions require Linux")
}

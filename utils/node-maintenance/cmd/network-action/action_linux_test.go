// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"testing"
	"unsafe"
)

func TestEthtoolABIShape(t *testing.T) {
	t.Parallel()

	if got, want := unsafe.Sizeof(ethtoolValue{}), uintptr(8); got != want {
		t.Fatalf("ethtoolValue size = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(ethtoolValue{}.data), uintptr(4); got != want {
		t.Fatalf("ethtoolValue.data offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(ifreqData{}.data), uintptr(16); got != want {
		t.Fatalf("ifreqData.data offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(ifreqData{}), uintptr(40); got != want {
		t.Fatalf("ifreqData size = %d, want %d", got, want)
	}
}

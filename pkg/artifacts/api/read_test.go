// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

func TestNewReadControllerRequiresLiveBindingResolver(t *testing.T) {
	if controller, err := NewReadController(nil, nil); err == nil || controller != nil {
		t.Fatal("nil service accepted")
	}
}

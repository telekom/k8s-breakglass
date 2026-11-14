// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
)

// TestMain fails the package when an audit event captured by its test doubles
// violates the versioned audit event schema.
func TestMain(m *testing.M) {
	os.Exit(audittest.Main(m))
}

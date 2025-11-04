// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionVariables(t *testing.T) {
	// Test that version variables exist and have expected default values
	assert.Equal(t, "0.0.0-dev", Version)
	assert.Equal(t, "", Commit)
}

func TestVersionVariablesCanBeModified(t *testing.T) {
	// Test that version variables can be modified (useful for build-time injection)
	originalVersion := Version
	originalCommit := Commit

	// Modify the variables
	Version = "1.0.0"
	Commit = "abc123"

	assert.Equal(t, "1.0.0", Version)
	assert.Equal(t, "abc123", Commit)

	// Restore original values
	Version = originalVersion
	Commit = originalCommit

	assert.Equal(t, "0.0.0-dev", Version)
	assert.Equal(t, "", Commit)
}

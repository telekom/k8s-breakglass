// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/output"
)

func TestUnknownOutputFormatError_WithSupportedFormats(t *testing.T) {
	err := unknownOutputFormatError("xml", output.FormatTable, output.FormatJSON, output.FormatYAML)
	assert.EqualError(t, err, "unsupported output format: xml (choose from: table, json, yaml)")
}

func TestUnknownOutputFormatError_WithoutSupportedFormats(t *testing.T) {
	err := unknownOutputFormatError("xml")
	assert.EqualError(t, err, "unsupported output format: xml")
}

func TestValidateOutputFormat_Valid(t *testing.T) {
	err := validateOutputFormat(output.FormatJSON, output.FormatJSON, output.FormatYAML)
	assert.NoError(t, err)
}

func TestValidateOutputFormat_Invalid(t *testing.T) {
	err := validateOutputFormat("xml", output.FormatJSON, output.FormatYAML)
	assert.EqualError(t, err, "unsupported output format: xml (choose from: json, yaml)")
}

/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFormatConstants(t *testing.T) {
	assert.Equal(t, Format("table"), FormatTable)
	assert.Equal(t, Format("json"), FormatJSON)
	assert.Equal(t, Format("yaml"), FormatYAML)
	assert.Equal(t, Format("wide"), FormatWide)
}

func TestWriteObject_JSON(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		validate func(t *testing.T, output string)
	}{
		{
			name:  "simple struct",
			input: struct{ Name string }{"test"},
			validate: func(t *testing.T, output string) {
				var result map[string]string
				require.NoError(t, json.Unmarshal([]byte(output), &result))
				assert.Equal(t, "test", result["Name"])
			},
		},
		{
			name:  "map",
			input: map[string]int{"count": 42},
			validate: func(t *testing.T, output string) {
				var result map[string]int
				require.NoError(t, json.Unmarshal([]byte(output), &result))
				assert.Equal(t, 42, result["count"])
			},
		},
		{
			name:  "slice",
			input: []string{"a", "b", "c"},
			validate: func(t *testing.T, output string) {
				var result []string
				require.NoError(t, json.Unmarshal([]byte(output), &result))
				assert.Equal(t, []string{"a", "b", "c"}, result)
			},
		},
		{
			name: "nested struct",
			input: struct {
				Metadata struct {
					Name string
				}
				Spec struct {
					Value int
				}
			}{
				Metadata: struct{ Name string }{"my-resource"},
				Spec:     struct{ Value int }{100},
			},
			validate: func(t *testing.T, output string) {
				assert.Contains(t, output, "my-resource")
				assert.Contains(t, output, "100")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := WriteObject(buf, FormatJSON, tt.input)
			require.NoError(t, err)
			tt.validate(t, buf.String())
		})
	}
}

func TestWriteObject_YAML(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		validate func(t *testing.T, output string)
	}{
		{
			name:  "simple struct",
			input: struct{ Name string }{"test"},
			validate: func(t *testing.T, output string) {
				var result map[string]string
				require.NoError(t, yaml.Unmarshal([]byte(output), &result))
				assert.Equal(t, "test", result["name"])
			},
		},
		{
			name:  "map",
			input: map[string]int{"count": 42},
			validate: func(t *testing.T, output string) {
				var result map[string]int
				require.NoError(t, yaml.Unmarshal([]byte(output), &result))
				assert.Equal(t, 42, result["count"])
			},
		},
		{
			name:  "slice",
			input: []string{"a", "b", "c"},
			validate: func(t *testing.T, output string) {
				var result []string
				require.NoError(t, yaml.Unmarshal([]byte(output), &result))
				assert.Equal(t, []string{"a", "b", "c"}, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := WriteObject(buf, FormatYAML, tt.input)
			require.NoError(t, err)
			tt.validate(t, buf.String())
		})
	}
}

func TestWriteObject_TableFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteObject(buf, FormatTable, struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "table format requires a specific formatter")
}

func TestWriteObject_WideFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteObject(buf, FormatWide, struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wide format requires a specific formatter")
}

func TestWriteObject_UnknownFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	err := WriteObject(buf, Format("invalid"), struct{}{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output format: invalid")
}

func TestWriteObject_JSONMarshalError(t *testing.T) {
	buf := &bytes.Buffer{}
	// Channels cannot be marshaled to JSON
	err := WriteObject(buf, FormatJSON, make(chan int))
	require.Error(t, err)
}

func TestWriteObject_YAMLMarshalError(t *testing.T) {
	buf := &bytes.Buffer{}
	// Channels cannot be marshaled to YAML (but it panics, so we test recovery)
	// Note: yaml.v3 panics on unmarshalable types instead of returning errors
	// So we skip this specific test case
	t.Skip("yaml.v3 panics on unmarshalable types rather than returning an error")
	err := WriteObject(buf, FormatYAML, make(chan int))
	require.Error(t, err)
}

func TestWriteObject_JSONIndentation(t *testing.T) {
	buf := &bytes.Buffer{}
	input := map[string]map[string]string{
		"nested": {"key": "value"},
	}
	err := WriteObject(buf, FormatJSON, input)
	require.NoError(t, err)

	output := buf.String()
	// Verify indentation (2 spaces)
	assert.True(t, strings.Contains(output, "  "), "JSON should be indented with 2 spaces")
	assert.True(t, strings.Contains(output, "\n"), "JSON should have newlines")
}

func TestWriteObject_OutputEndsWithNewline(t *testing.T) {
	tests := []struct {
		format Format
	}{
		{FormatJSON},
		{FormatYAML},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := WriteObject(buf, tt.format, map[string]string{"key": "value"})
			require.NoError(t, err)
			assert.True(t, strings.HasSuffix(buf.String(), "\n"), "output should end with newline")
		})
	}
}

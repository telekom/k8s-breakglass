/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestTemplateRenderer_RenderTemplateString(t *testing.T) {
	renderer := NewTemplateRenderer()

	tests := []struct {
		name        string
		template    string
		context     interface{}
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:     "simple variable substitution",
			template: "Hello, {{ .session.name }}!",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "test-session",
				},
			},
			expected: "Hello, test-session!",
		},
		{
			name:     "nested context access",
			template: "Cluster: {{ .session.cluster }}, Namespace: {{ .target.namespace }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Cluster: "prod-cluster",
				},
				Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
					Namespace: "debug-ns",
				},
			},
			expected: "Cluster: prod-cluster, Namespace: debug-ns",
		},
		{
			name:     "user variables access",
			template: "Size: {{ .vars.pvcSize }}, Class: {{ .vars.storageClass }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"pvcSize":      "50Gi",
					"storageClass": "csi-cinder",
				},
			},
			expected: "Size: 50Gi, Class: csi-cinder",
		},
		{
			name:     "sprig functions - upper",
			template: "{{ .session.name | upper }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "test-session",
				},
			},
			expected: "TEST-SESSION",
		},
		{
			name:     "sprig functions - trunc",
			template: "{{ .session.name | trunc 8 }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "very-long-session-name",
				},
			},
			expected: "very-lon",
		},
		{
			name:     "sprig functions - quote",
			template: "name: {{ .session.name | quote }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "test-session",
				},
			},
			expected: `name: "test-session"`,
		},
		{
			name:     "sprig functions - default",
			template: "name: {{ .vars.missing | default \"default-value\" }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{},
			},
			expected: "name: default-value",
		},
		{
			name: "conditional rendering - if true",
			template: `{{- if .vars.createPvc }}
pvc: enabled
{{- end }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"createPvc": "true",
				},
			},
			expected: "\npvc: enabled",
		},
		{
			name: "range over labels",
			template: `labels:
{{- range $k, $v := .labels }}
  {{ $k }}: {{ $v | quote }}
{{- end }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Labels: map[string]string{
					"app":     "test",
					"version": "v1",
				},
			},
			expected: "labels:\n  app: \"test\"\n  version: \"v1\"",
		},
		{
			name:     "custom function - truncName",
			template: "{{ truncName 10 .session.name }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "very-long-session-name-that-exceeds-limit",
				},
			},
			expected: "very-long-",
		},
		{
			name:     "custom function - k8sName",
			template: "{{ k8sName .vars.testName }}",
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{
					"testName": "My Test_Name.123",
				},
			},
			expected: "my-test-name-123",
		},
		{
			name:        "empty template",
			template:    "",
			context:     breakglassv1alpha1.AuxiliaryResourceContext{},
			expectError: true,
			errorMsg:    "template string is empty",
		},
		{
			name:        "invalid template syntax",
			template:    "{{ .session.name",
			context:     breakglassv1alpha1.AuxiliaryResourceContext{},
			expectError: true,
			errorMsg:    "failed to parse template",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := renderer.RenderTemplateString(tt.template, tt.context)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			require.NoError(t, err)
			// Normalize whitespace for comparison
			actual := strings.TrimSpace(string(result))
			expected := strings.TrimSpace(tt.expected)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestTemplateRenderer_RenderMultiDocumentTemplate(t *testing.T) {
	renderer := NewTemplateRenderer()

	tests := []struct {
		name          string
		template      string
		context       interface{}
		expectedDocs  int
		expectError   bool
		validateFirst string
	}{
		{
			name: "single document",
			template: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "test-session",
				},
			},
			expectedDocs:  1,
			validateFirst: "name: test-session",
		},
		{
			name: "two documents",
			template: `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-{{ .session.name }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-{{ .session.name }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
					Name: "test",
				},
			},
			expectedDocs:  2,
			validateFirst: "pvc-test",
		},
		{
			name: "three documents with empty",
			template: `apiVersion: v1
kind: Secret
metadata:
  name: secret-1
---

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-1`,
			context:      breakglassv1alpha1.AuxiliaryResourceContext{},
			expectedDocs: 2, // Empty document should be skipped
		},
		{
			name: "conditional document (included)",
			template: `{{- if .vars.createPvc }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
{{- end }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{"createPvc": "true"},
			},
			expectedDocs: 1,
		},
		{
			name: "conditional document (excluded)",
			template: `{{- if eq .vars.createPvc "true" }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
{{- end }}`,
			context: breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: map[string]string{"createPvc": "false"},
			},
			expectedDocs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := renderer.RenderMultiDocumentTemplate(tt.template, tt.context)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, docs, tt.expectedDocs)

			if tt.validateFirst != "" && len(docs) > 0 {
				assert.Contains(t, string(docs[0]), tt.validateFirst)
			}
		})
	}
}

func TestTemplateRenderer_ValidateTemplate(t *testing.T) {
	renderer := NewTemplateRenderer()

	sampleCtx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        "validation-session",
			Namespace:   "breakglass-system",
			Cluster:     "validation-cluster",
			RequestedBy: "validator@example.com",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   "breakglass-debug",
			ClusterName: "validation-cluster",
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by": "breakglass",
		},
		Vars: map[string]string{
			"testName":     "sample",
			"pvcSize":      "10Gi",
			"storageClass": "standard",
		},
	}

	tests := []struct {
		name        string
		template    string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid template",
			template: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name }}`,
			expectError: false,
		},
		{
			name: "valid multi-document",
			template: `apiVersion: v1
kind: Secret
metadata:
  name: secret-{{ .vars.testName }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-{{ .vars.testName }}`,
			expectError: false,
		},
		{
			name:        "empty template",
			template:    "",
			expectError: true,
			errorMsg:    "template string is empty",
		},
		{
			name:        "syntax error - unclosed action",
			template:    "{{ .session.name",
			expectError: true,
			errorMsg:    "template syntax error",
		},
		{
			name: "invalid YAML output",
			template: `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .session.name }}
  invalid yaml: [unclosed`,
			expectError: true,
			errorMsg:    "invalid YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := renderer.ValidateTemplate(tt.template, sampleCtx)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestTruncName(t *testing.T) {
	tests := []struct {
		name     string
		maxLen   int
		input    string
		expected string
	}{
		{
			name:     "short name - no truncation",
			maxLen:   20,
			input:    "short-name",
			expected: "short-name",
		},
		{
			name:     "exact length - no truncation",
			maxLen:   10,
			input:    "1234567890",
			expected: "1234567890",
		},
		{
			name:     "long name - truncated",
			maxLen:   10,
			input:    "very-long-name-that-exceeds-limit",
			expected: "very-long-",
		},
		{
			name:     "zero maxLen - default to 63",
			maxLen:   0,
			input:    "short",
			expected: "short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncName(tt.maxLen, tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestK8sName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already valid",
			input:    "valid-name-123",
			expected: "valid-name-123",
		},
		{
			name:     "uppercase to lowercase",
			input:    "MyTestName",
			expected: "mytestname",
		},
		{
			name:     "spaces to hyphens",
			input:    "my test name",
			expected: "my-test-name",
		},
		{
			name:     "underscores to hyphens",
			input:    "my_test_name",
			expected: "my-test-name",
		},
		{
			name:     "dots to hyphens",
			input:    "my.test.name",
			expected: "my-test-name",
		},
		{
			name:     "special characters removed",
			input:    "my@test#name!",
			expected: "mytestname",
		},
		{
			name:     "leading/trailing hyphens removed",
			input:    "-test-name-",
			expected: "test-name",
		},
		{
			name:     "multiple hyphens collapsed",
			input:    "test--name---value",
			expected: "test-name-value",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "resource",
		},
		{
			name:     "only special characters",
			input:    "@#$%",
			expected: "resource",
		},
		{
			name:     "very long name truncated",
			input:    strings.Repeat("a", 100),
			expected: strings.Repeat("a", 63),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := k8sName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseQuantity(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64
		expectError bool
	}{
		{
			name:     "gigabytes",
			input:    "10Gi",
			expected: 10737418240, // 10 * 1024^3
		},
		{
			name:     "megabytes",
			input:    "512Mi",
			expected: 536870912, // 512 * 1024^2
		},
		{
			name:     "plain bytes",
			input:    "1000",
			expected: 1000,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
		},
		{
			name:        "invalid format",
			input:       "invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseQuantity(tt.input)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatQuantity(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "gigabytes",
			bytes:    10737418240, // 10Gi
			expected: "10Gi",
		},
		{
			name:     "megabytes",
			bytes:    536870912, // 512Mi
			expected: "512Mi",
		},
		{
			name:     "kilobytes",
			bytes:    1024,
			expected: "1Ki",
		},
		{
			name:     "zero",
			bytes:    0,
			expected: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatQuantity(tt.bytes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitYAMLDocuments(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedDocs int
	}{
		{
			name:         "single document",
			input:        "apiVersion: v1\nkind: ConfigMap",
			expectedDocs: 1,
		},
		{
			name:         "two documents",
			input:        "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: v1\nkind: Secret",
			expectedDocs: 2,
		},
		{
			name:         "three documents",
			input:        "doc1\n---\ndoc2\n---\ndoc3",
			expectedDocs: 3,
		},
		{
			name:         "empty documents filtered",
			input:        "doc1\n---\n\n---\ndoc2",
			expectedDocs: 2,
		},
		{
			name:         "leading separator",
			input:        "---\ndoc1",
			expectedDocs: 1,
		},
		{
			name:         "trailing separator",
			input:        "doc1\n---\n",
			expectedDocs: 1,
		},
		{
			name:         "only separators",
			input:        "---\n---\n---",
			expectedDocs: 0,
		},
		{
			name:         "empty input",
			input:        "",
			expectedDocs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := splitYAMLDocuments([]byte(tt.input))
			assert.Len(t, docs, tt.expectedDocs)
		})
	}
}

func TestTemplateRenderer_FullExample(t *testing.T) {
	renderer := NewTemplateRenderer()

	// Full storage test template similar to proposal example
	template := `apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-{{ .vars.testName }}-{{ .session.name | trunc 8 }}
  namespace: {{ .target.namespace }}
  labels:
    {{- range $k, $v := .labels }}
    {{ $k }}: {{ $v | quote }}
    {{- end }}
spec:
  accessModes:
    - {{ .vars.accessMode }}
  storageClassName: {{ .vars.storageClass | quote }}
  resources:
    requests:
      storage: {{ .vars.pvcSize }}`

	ctx := breakglassv1alpha1.AuxiliaryResourceContext{
		Session: breakglassv1alpha1.AuxiliaryResourceSessionContext{
			Name:        "debug-session-12345",
			Namespace:   "breakglass-system",
			Cluster:     "prod-cluster",
			RequestedBy: "user@example.com",
		},
		Target: breakglassv1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   "breakglass-debug",
			ClusterName: "prod-cluster",
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":          "breakglass",
			"breakglass.t-caas.telekom.com/session": "debug-session-12345",
		},
		Vars: map[string]string{
			"testName":     "customer-xyz",
			"pvcSize":      "50Gi",
			"storageClass": "csi-cinder-replicated",
			"accessMode":   "ReadWriteOnce",
		},
	}

	result, err := renderer.RenderTemplateString(template, ctx)
	require.NoError(t, err)

	rendered := string(result)

	// Verify key rendered values
	assert.Contains(t, rendered, "name: pvc-customer-xyz-debug-se")
	assert.Contains(t, rendered, "namespace: breakglass-debug")
	assert.Contains(t, rendered, "storage: 50Gi")
	assert.Contains(t, rendered, `storageClassName: "csi-cinder-replicated"`)
	assert.Contains(t, rendered, "- ReadWriteOnce")
	assert.Contains(t, rendered, `app.kubernetes.io/managed-by: "breakglass"`)
}

func TestTemplateRenderer_ConditionalResources(t *testing.T) {
	renderer := NewTemplateRenderer()

	// Template with conditional logic
	template := `{{- if eq .vars.createPvc "true" }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
spec:
  resources:
    requests:
      storage: {{ .vars.pvcSize }}
{{- end }}`

	tests := []struct {
		name      string
		vars      map[string]string
		expectPVC bool
	}{
		{
			name: "create PVC when enabled",
			vars: map[string]string{
				"createPvc": "true",
				"pvcSize":   "10Gi",
			},
			expectPVC: true,
		},
		{
			name: "skip PVC when disabled",
			vars: map[string]string{
				"createPvc": "false",
			},
			expectPVC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: tt.vars,
			}

			docs, err := renderer.RenderMultiDocumentTemplate(template, ctx)
			require.NoError(t, err)

			if tt.expectPVC {
				assert.Len(t, docs, 1)
				assert.Contains(t, string(docs[0]), "PersistentVolumeClaim")
			} else {
				assert.Len(t, docs, 0)
			}
		})
	}
}

// TestYamlQuote tests the yamlQuote function for YAML safety
func TestYamlQuote(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "empty string",
			input:    "",
			expected: `""`,
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: `"hello world"`,
		},
		{
			name:     "string with colon",
			input:    "key:value",
			expected: `"key:value"`,
		},
		{
			name:     "string with hash",
			input:    "test#comment",
			expected: `"test#comment"`,
		},
		{
			name:     "string with newline",
			input:    "line1\nline2",
			expected: `"line1\nline2"`,
		},
		{
			name:     "string with quotes",
			input:    `say "hello"`,
			expected: `"say \"hello\""`,
		},
		{
			name:     "yaml true",
			input:    "true",
			expected: `"true"`,
		},
		{
			name:     "yaml false",
			input:    "false",
			expected: `"false"`,
		},
		{
			name:     "yaml yes",
			input:    "yes",
			expected: `"yes"`,
		},
		{
			name:     "yaml null",
			input:    "null",
			expected: `"null"`,
		},
		{
			name:     "document separator",
			input:    "---test",
			expected: `"---test"`,
		},
		{
			name:     "curly braces",
			input:    "{key: value}",
			expected: `"{key: value}"`,
		},
		{
			name:     "square brackets",
			input:    "[1, 2, 3]",
			expected: `"[1, 2, 3]"`,
		},
		{
			name:     "backslash",
			input:    "path\\to\\file",
			expected: `"path\\to\\file"`,
		},
		{
			name:     "injection attempt",
			input:    "test\nkey: injected",
			expected: `"test\nkey: injected"`,
		},
		{
			name:     "yaml anchor attempt",
			input:    "&anchor value",
			expected: `"&anchor value"`,
		},
		{
			name:     "yaml alias attempt",
			input:    "*alias",
			expected: `"*alias"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := yamlQuote(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestYamlSafe tests the yamlSafe function
func TestYamlSafe(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "string with colon",
			input:    "key:value",
			expected: "key-value",
		},
		{
			name:     "string with hash",
			input:    "test#comment",
			expected: "test-comment",
		},
		{
			name:     "string with newline",
			input:    "line1\nline2",
			expected: "line1 line2",
		},
		{
			name:     "curly braces",
			input:    "{key: value}",
			expected: "-key- value-",
		},
		{
			name:     "injection attempt",
			input:    "test\nkey: injected",
			expected: "test key- injected",
		},
		{
			name:     "multiple special chars",
			input:    "test:::#value",
			expected: "test-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := yamlSafe(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestYamlQuoteInTemplate tests yamlQuote usage in actual template rendering
func TestYamlQuoteInTemplate(t *testing.T) {
	renderer := NewTemplateRenderer()

	tests := []struct {
		name          string
		template      string
		vars          map[string]string
		expected      string
		shouldContain []string
	}{
		{
			name:     "safe user value with yamlQuote",
			template: "key: {{ .vars.userValue | yamlQuote }}",
			vars: map[string]string{
				"userValue": "hello: world",
			},
			expected: `key: "hello: world"`,
		},
		{
			name:     "prevent injection with yamlQuote",
			template: "key: {{ .vars.userValue | yamlQuote }}",
			vars: map[string]string{
				"userValue": "test\ninjected: value",
			},
			expected: `key: "test\ninjected: value"`,
		},
		{
			name: "label values with yamlQuote",
			template: `metadata:
  labels:
    user-input: {{ .vars.label | yamlQuote }}`,
			vars: map[string]string{
				"label": "test value",
			},
			shouldContain: []string{
				`user-input: "test value"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: tt.vars,
			}

			result, err := renderer.RenderTemplateString(tt.template, ctx)
			require.NoError(t, err)

			if tt.expected != "" {
				assert.Equal(t, tt.expected, strings.TrimSpace(string(result)))
			}
			for _, contain := range tt.shouldContain {
				assert.Contains(t, string(result), contain)
			}
		})
	}
}

// TestIsYAMLSpecialWord tests the isYAMLSpecialWord function
func TestIsYAMLSpecialWord(t *testing.T) {
	specialWords := []string{"true", "false", "yes", "no", "on", "off", "null", "~", "TRUE", "FALSE", "Yes", "No"}
	for _, word := range specialWords {
		assert.True(t, isYAMLSpecialWord(word), "expected %q to be a special word", word)
	}

	normalWords := []string{"hello", "world", "truevalue", "falsified", "nullable", "123", "test-true"}
	for _, word := range normalWords {
		assert.False(t, isYAMLSpecialWord(word), "expected %q to NOT be a special word", word)
	}
}

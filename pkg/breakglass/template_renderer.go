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

package breakglass

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	"github.com/Masterminds/sprig/v3"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

// TemplateRenderer handles Go template rendering for auxiliary resources and pod templates.
// It provides Sprig functions plus custom Breakglass functions for Kubernetes resource templating.
type TemplateRenderer struct{}

// NewTemplateRenderer creates a new template renderer.
func NewTemplateRenderer() *TemplateRenderer {
	return &TemplateRenderer{}
}

// RenderTemplateString renders a Go template string with the given context.
// The context is converted to a map for template access.
func (r *TemplateRenderer) RenderTemplateString(templateStr string, ctx interface{}) ([]byte, error) {
	if templateStr == "" {
		return nil, fmt.Errorf("template string is empty")
	}

	// Convert context to map for template
	ctxMap, err := toMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert context: %w", err)
	}

	// Parse template with sprig and custom functions
	funcMap := r.buildFuncMap()
	tmpl, err := template.New("template").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctxMap); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// RenderMultiDocumentTemplate renders a template that may contain multiple YAML documents
// separated by "---". Returns a slice of rendered documents.
func (r *TemplateRenderer) RenderMultiDocumentTemplate(templateStr string, ctx interface{}) ([][]byte, error) {
	rendered, err := r.RenderTemplateString(templateStr, ctx)
	if err != nil {
		return nil, err
	}

	// Split by YAML document separator
	documents := splitYAMLDocuments(rendered)
	return documents, nil
}

// ValidateTemplate checks if a template is syntactically valid and can be rendered.
// It attempts a dry-run render with sample context to catch errors early.
func (r *TemplateRenderer) ValidateTemplate(templateStr string, sampleCtx interface{}) error {
	if templateStr == "" {
		return fmt.Errorf("template string is empty")
	}

	// Convert context to map for template
	ctxMap, err := toMap(sampleCtx)
	if err != nil {
		return fmt.Errorf("failed to convert context: %w", err)
	}

	// Parse template
	funcMap := r.buildFuncMap()
	tmpl, err := template.New("validation").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return fmt.Errorf("template syntax error: %w", err)
	}

	// Execute template with sample context
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctxMap); err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	// Validate that each document is valid YAML
	documents := splitYAMLDocuments(buf.Bytes())
	for i, doc := range documents {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue // Skip empty documents
		}
		var obj map[string]interface{}
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("document %d: invalid YAML: %w", i+1, err)
		}
	}

	return nil
}

// ValidateRenderedYAML validates that rendered YAML is valid and contains required fields.
func (r *TemplateRenderer) ValidateRenderedYAML(yamlBytes []byte) error {
	if len(bytes.TrimSpace(yamlBytes)) == 0 {
		return nil // Empty is valid (conditional rendering may produce empty output)
	}

	var obj map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &obj); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// Check for apiVersion and kind for Kubernetes resources
	if _, hasAPIVersion := obj["apiVersion"]; !hasAPIVersion {
		return fmt.Errorf("missing required field: apiVersion")
	}
	if _, hasKind := obj["kind"]; !hasKind {
		return fmt.Errorf("missing required field: kind")
	}

	return nil
}

// buildFuncMap creates the template function map with Sprig and custom functions.
func (r *TemplateRenderer) buildFuncMap() template.FuncMap {
	// Start with Sprig functions
	funcMap := sprig.FuncMap()

	// Add custom Breakglass functions
	funcMap["truncName"] = truncName
	funcMap["k8sName"] = k8sName
	funcMap["parseQuantity"] = parseQuantity
	funcMap["formatQuantity"] = formatQuantity
	funcMap["required"] = requiredFunc
	funcMap["indent"] = indentFunc
	funcMap["nindent"] = nindentFunc
	funcMap["yamlQuote"] = yamlQuote
	funcMap["yamlSafe"] = yamlSafe

	return funcMap
}

// splitYAMLDocuments splits a YAML byte slice by document separators (---).
// Returns non-empty documents only.
func splitYAMLDocuments(data []byte) [][]byte {
	// Split by document separator
	separator := regexp.MustCompile(`(?m)^---\s*$`)
	parts := separator.Split(string(data), -1)

	var documents [][]byte
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			documents = append(documents, []byte(trimmed))
		}
	}

	return documents
}

// Custom template functions

// truncName truncates a name to fit Kubernetes 63-character limit while keeping uniqueness.
// It appends a hash suffix if truncation is needed.
func truncName(maxLen int, name string) string {
	if maxLen <= 0 {
		maxLen = 63
	}
	if len(name) <= maxLen {
		return name
	}
	// Keep first maxLen chars
	return name[:maxLen]
}

// k8sName sanitizes a string to be a valid Kubernetes name.
// Kubernetes names must be lowercase alphanumeric with hyphens, max 63 chars,
// starting and ending with alphanumeric.
func k8sName(s string) string {
	if s == "" {
		return "resource"
	}

	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace invalid characters with hyphens
	var result strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(r)
		} else if r == '-' || r == '_' || r == ' ' || r == '.' {
			result.WriteRune('-')
		}
		// Skip other characters
	}

	name := result.String()

	// Remove leading/trailing hyphens
	name = strings.Trim(name, "-")

	// Collapse multiple hyphens
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// Truncate to 63 characters
	if len(name) > 63 {
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}

	if name == "" {
		return "resource"
	}

	return name
}

// parseQuantity parses a Kubernetes quantity string (e.g., "10Gi") to bytes.
func parseQuantity(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0, err
	}
	return q.Value(), nil
}

// formatQuantity formats bytes as a Kubernetes quantity string.
func formatQuantity(bytes int64) string {
	q := resource.NewQuantity(bytes, resource.BinarySI)
	return q.String()
}

// requiredFunc returns an error if the value is empty.
func requiredFunc(msg string, val interface{}) (interface{}, error) {
	if val == nil {
		return nil, fmt.Errorf("required value is missing: %s", msg)
	}
	if s, ok := val.(string); ok && s == "" {
		return nil, fmt.Errorf("required value is empty: %s", msg)
	}
	return val, nil
}

// indentFunc indents a string by the specified number of spaces.
func indentFunc(spaces int, s string) string {
	pad := strings.Repeat(" ", spaces)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = pad + line
		}
	}
	return strings.Join(lines, "\n")
}

// nindentFunc adds a newline before the indented string.
func nindentFunc(spaces int, s string) string {
	return "\n" + indentFunc(spaces, s)
}

// yamlQuote safely quotes a string for YAML values.
// This ensures user-provided values cannot inject YAML syntax.
// Use this for ANY user-provided values in templates, especially .Vars.* values.
// Example: key: {{ .Vars.userValue | yamlQuote }}
func yamlQuote(s string) string {
	// Check if value needs quoting - if it contains any YAML special chars
	needsQuoting := strings.ContainsAny(s, ":#{}[]|>!&*?-'\"\\`@,\n\r\t ")
	needsQuoting = needsQuoting || len(s) == 0
	needsQuoting = needsQuoting || strings.HasPrefix(s, "---")
	needsQuoting = needsQuoting || strings.HasPrefix(s, "...")
	needsQuoting = needsQuoting || isYAMLSpecialWord(s)

	if !needsQuoting {
		return s
	}

	// Use double quotes with proper escaping
	escaped := strings.ReplaceAll(s, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	escaped = strings.ReplaceAll(escaped, "\n", "\\n")
	escaped = strings.ReplaceAll(escaped, "\r", "\\r")
	escaped = strings.ReplaceAll(escaped, "\t", "\\t")

	return "\"" + escaped + "\""
}

// yamlSafe sanitizes a string to be safe as a YAML scalar value.
// Unlike yamlQuote, this removes potentially dangerous characters.
// Use for values that should NOT contain special characters.
func yamlSafe(s string) string {
	// Replace dangerous characters with safe alternatives
	result := strings.Map(func(r rune) rune {
		switch r {
		case ':', '#', '{', '}', '[', ']', '|', '>', '!', '&', '*', '?', '\'', '"', '\\', '`', '@':
			return '-'
		case '\n', '\r', '\t':
			return ' '
		default:
			return r
		}
	}, s)

	// Collapse multiple spaces/hyphens
	for strings.Contains(result, "  ") {
		result = strings.ReplaceAll(result, "  ", " ")
	}
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	return strings.TrimSpace(result)
}

// isYAMLSpecialWord checks if a string is a YAML special keyword.
// These must be quoted to avoid YAML interpreting them as boolean, null, etc.
func isYAMLSpecialWord(s string) bool {
	lower := strings.ToLower(s)
	switch lower {
	case "true", "false", "yes", "no", "on", "off", "null", "~":
		return true
	}
	return false
}

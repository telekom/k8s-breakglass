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
	"sort"
	"strings"
)

// Rendered templates are YAML documents, and every value that reaches
// AuxiliaryResourceContext.Vars originates from an end user via
// DebugSession.spec.extraDeployValues. A value carrying a line break can close the
// scalar it was substituted into and open sibling YAML keys, so an
// `{{ .Vars.x }}` interpolation anywhere in a document is enough to inject
// arbitrary structure into that document -- including hostNetwork/hostPID/hostIPC,
// which applyPodOverridesStruct honours verbatim.
//
// The repository already ships yamlQuote/yamlSafe template helpers, but those are
// opt-in: a template author has to remember to type them, and the auxiliary
// renderer does not even register them. Escaping is therefore done here, at the
// single point where untrusted values enter a render context, so that no template
// author can forget and no future template can reintroduce the hole.

// sanitizeTemplateVar neutralises the YAML structural characters that let a
// user-supplied scalar break out of its position in a rendered document.
//
// Only characters that can terminate a scalar or begin a new node are affected:
// line breaks (which are what actually enable sibling-key injection) plus the
// document separators. Everything else is preserved byte-for-byte, so ordinary
// values -- image references, quantities, comma-joined multiSelect values,
// sentences containing ':' or '#' -- render exactly as they do today.
//
// Line breaks collapse to a single space rather than being stripped, so that
// "a\nb" cannot silently become the different token "ab".
func sanitizeTemplateVar(value string) string {
	if !strings.ContainsAny(value, yamlLineTerminatorChars) {
		// Fast path: no line terminator, so the value cannot escape its line.
		// A leading document separator is still unsafe at column 0.
		return neutralizeDocumentSeparator(value)
	}

	return neutralizeDocumentSeparator(yamlLineTerminatorReplacer.Replace(value))
}

// yamlLineTerminatorChars lists every Unicode line terminator a YAML parser may
// honour: LF, CR, NEL (U+0085), LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR
// (U+2029).
const yamlLineTerminatorChars = "\n\r\u0085\u2028\u2029"

// yamlLineTerminatorReplacer collapses each terminator to a single space. CRLF is
// listed first so that it collapses to one space rather than two.
var yamlLineTerminatorReplacer = strings.NewReplacer(
	"\r\n", " ",
	"\n", " ",
	"\r", " ",
	"\u0085", " ",
	"\u2028", " ",
	"\u2029", " ",
)

// neutralizeDocumentSeparator defuses a value that begins with a YAML document
// marker ("---" or "..."), which would otherwise start or end a document when
// substituted at the start of a line.
func neutralizeDocumentSeparator(value string) string {
	if strings.HasPrefix(value, "---") || strings.HasPrefix(value, "...") {
		return " " + value
	}
	return value
}

// sanitizeTemplateVarsReportingChanges sanitizes every value in a var map and
// returns the sorted names of the variables whose value was modified, so the
// caller can log or record an event instead of silently rewriting user input.
func sanitizeTemplateVarsReportingChanges(vars map[string]string) (map[string]string, []string) {
	var changed []string
	for name, value := range vars {
		sanitized := sanitizeTemplateVar(value)
		if sanitized != value {
			changed = append(changed, name)
			vars[name] = sanitized
		}
	}
	sort.Strings(changed)
	return vars, changed
}

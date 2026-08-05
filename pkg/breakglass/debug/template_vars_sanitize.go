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
	"unicode/utf8"
)

// Rendered templates are YAML documents, and every value that reaches
// AuxiliaryResourceContext.Vars originates from an end user via
// DebugSession.spec.extraDeployValues. A value carrying a line break can close the
// scalar it was substituted into and open sibling YAML keys, so a
// `{{ .vars.x }}` interpolation anywhere in a document is enough to inject
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

// documentMarkerIndicators are the two YAML document indicators: the
// directives-end marker "---" and the document-end marker "...".
var documentMarkerIndicators = []string{"---", "..."}

// documentMarkerFollowers are the bytes that may follow a document indicator for
// it to still be recognised as a marker. Per the YAML spec (c-directives-end /
// c-document-end) the indicator must be followed by end-of-input, s-white (space
// or tab) or a line break; anything else makes the token a plain scalar.
//
// The line terminators are listed even though sanitizeTemplateVar collapses them
// before this runs, so the predicate stays correct on its own rather than
// depending on call order.
const documentMarkerFollowers = " \t" + yamlLineTerminatorChars

// startsWithDocumentMarker reports whether value begins with a genuine YAML
// document marker, i.e. one that a parser would honour if the value landed at
// column 0.
//
// This is deliberately narrower than "starts with --- or ...": values such as
// "---foo" or "...bar" are plain scalars, not markers, and rewriting them would
// break the byte-for-byte-preservation guarantee for legitimate input. Only a
// marker followed by end-of-string or whitespace can split a document.
func startsWithDocumentMarker(value string) bool {
	for _, indicator := range documentMarkerIndicators {
		rest, found := strings.CutPrefix(value, indicator)
		if !found {
			continue
		}
		if rest == "" {
			return true
		}
		// Decode a full rune rather than slicing a byte, so a multi-byte follower
		// is classified correctly and invalid UTF-8 (RuneError, not a follower)
		// falls through to "plain scalar".
		follower, _ := utf8.DecodeRuneInString(rest)
		if strings.ContainsRune(documentMarkerFollowers, follower) {
			return true
		}
	}
	return false
}

// neutralizeDocumentSeparator defuses a value that begins with a YAML document
// marker, which would otherwise start or end a document when substituted at the
// start of a line. A single leading space is enough: an indented "---" is not a
// document marker, because markers are only recognised at column 0.
//
// Only the prefix is inspected. A marker anywhere else in the value cannot split
// the document, because sanitizeTemplateVar has already collapsed every line
// terminator to a space by the time this runs, so the value occupies a single
// line and "a --- b" is just a plain scalar. A leading space in the value has the
// same effect for the same reason, so it needs no further handling.
func neutralizeDocumentSeparator(value string) string {
	if startsWithDocumentMarker(value) {
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

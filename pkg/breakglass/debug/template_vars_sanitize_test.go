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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// jsonString builds an apiextensionsv1.JSON holding a JSON string, mirroring what
// the DebugSession REST API stores in spec.extraDeployValues.
func jsonString(t *testing.T, s string) apiextensionsv1.JSON {
	t.Helper()
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	return apiextensionsv1.JSON{Raw: raw}
}

// sessionWithVar returns a DebugSession carrying a single end-user supplied
// extraDeployValues entry.
func sessionWithVar(t *testing.T, name, value string) *breakglassv1alpha1.DebugSession {
	t.Helper()
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "injection-session"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			TemplateRef: "test-template",
			RequestedBy: "attacker@example.com",
			ExtraDeployValues: map[string]apiextensionsv1.JSON{
				name: jsonString(t, value),
			},
		},
	}
}

// hostNamespaceInjectionPayloads are end-user values that attempt to escape the
// YAML scalar they are substituted into and set host-namespace sibling keys.
// applyPodOverridesStruct honours hostNetwork/hostPID/hostIPC verbatim, so a
// successful escape is a privilege escalation on the debug path.
func hostNamespaceInjectionPayloads() map[string]string {
	return map[string]string{
		"unix newline":     "worker-1\nhostNetwork: true\nhostPID: true",
		"crlf newline":     "worker-1\r\nhostNetwork: true\r\nhostIPC: true",
		"bare cr":          "worker-1\rhostNetwork: true",
		"leading newline":  "worker-1\n\nhostNetwork: true",
		"nel":              "worker-1\u0085hostNetwork: true",
		"line separator":   "worker-1\u2028hostNetwork: true",
		"para separator":   "worker-1\u2029hostPID: true",
		"document break":   "worker-1\n---\nhostNetwork: true",
		"trailing comment": "worker-1\nhostIPC: true # pwn",
	}
}

// podOverridesInjectionTemplate interpolates a user-controlled var into a
// nodeSelector value. The template author did nothing unusual and did not opt into
// yamlQuote -- which is precisely the footgun being closed.
//
// The accessor is lowercase `.vars` because the render context is marshalled
// through JSON before execution (see toMap), matching docs/extra-deploy-variables.md.
const podOverridesInjectionTemplate = `nodeSelector:
  kubernetes.io/hostname: {{ .vars.node }}
`

// TestPodOverridesTemplate_UserVarsCannotInjectHostNamespaces pins BUG 1 on the
// pod-override path: end-user extraDeployValues must not be able to inject sibling
// YAML keys that enable host namespaces.
//
// Before the fix this test fails: each payload's newline closes the nodeSelector
// scalar and the following line parses as a top-level hostNetwork/hostPID/hostIPC
// key, which applyPodOverridesStruct then copies onto the pod spec.
func TestPodOverridesTemplate_UserVarsCannotInjectHostNamespaces(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}
	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{}

	for name, payload := range hostNamespaceInjectionPayloads() {
		t.Run(name, func(t *testing.T) {
			session := sessionWithVar(t, "node", payload)

			renderCtx := breakglassv1alpha1.AuxiliaryResourceContext{
				Vars: controller.buildVarsFromSession(session, templateSpec),
			}

			// Guard the test itself: if the var accessor ever stops resolving, the
			// template renders "<no value>" and the injection assertions below would
			// pass vacuously. Assert the value actually reached the document first.
			rendered, err := NewTemplateRenderer().RenderTemplateString(podOverridesInjectionTemplate, renderCtx)
			require.NoError(t, err)
			require.NotContains(t, string(rendered), "<no value>",
				"template var must resolve, otherwise this test proves nothing")
			require.Contains(t, string(rendered), "worker-1",
				"the user-supplied value must actually be interpolated")

			// The injected payload must never become YAML structure. Two outcomes are
			// acceptable, both fail closed:
			//   1. the document parses and no host-namespace key was created, or
			//   2. the document fails to parse, because the neutralised payload is no
			//      longer a well-formed scalar -- the caller turns that into a session
			//      failure rather than a privileged pod.
			// What must never happen is a successful parse that sets a host namespace.
			overrides, err := controller.renderPodOverridesTemplate(podOverridesInjectionTemplate, renderCtx)
			if err != nil {
				assert.Contains(t, err.Error(), "failed to parse rendered overrides YAML",
					"the only tolerated failure is a YAML parse rejection")
				return
			}
			require.NotNil(t, overrides)

			assert.Nil(t, overrides.HostNetwork, "user value must not be able to set hostNetwork")
			assert.Nil(t, overrides.HostPID, "user value must not be able to set hostPID")
			assert.Nil(t, overrides.HostIPC, "user value must not be able to set hostIPC")

			// And the escape must not have leaked into the applied pod spec either.
			spec := &corev1.PodSpec{}
			controller.applyPodOverridesStruct(spec, overrides)
			assert.False(t, spec.HostNetwork, "hostNetwork must remain disabled")
			assert.False(t, spec.HostPID, "hostPID must remain disabled")
			assert.False(t, spec.HostIPC, "hostIPC must remain disabled")
		})
	}
}

// TestAuxiliaryVars_UserVarsCannotInjectSiblingKeys pins BUG 1 on the auxiliary
// resource path, which renders with a bare sprig.FuncMap() that does not even
// register yamlQuote/yamlSafe, so escaping there could only ever happen at the
// boundary.
func TestAuxiliaryVars_UserVarsCannotInjectSiblingKeys(t *testing.T) {
	mgr := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), nil)

	for name, payload := range hostNamespaceInjectionPayloads() {
		t.Run(name, func(t *testing.T) {
			session := sessionWithVar(t, "node", payload)
			vars := mgr.buildVarsFromSession(session, nil)

			got := vars["node"]
			assert.NotContains(t, got, "\n", "sanitized value must not contain a line feed")
			assert.NotContains(t, got, "\r", "sanitized value must not contain a carriage return")
			assert.NotContains(t, got, "\u0085", "sanitized value must not contain NEL")
			assert.NotContains(t, got, "\u2028", "sanitized value must not contain LINE SEPARATOR")
			assert.NotContains(t, got, "\u2029", "sanitized value must not contain PARAGRAPH SEPARATOR")
		})
	}
}

// TestSanitizeTemplateVar_PreservesOrdinaryValues guards against over-escaping:
// the fix tightens behaviour, so values operators legitimately use today must
// render byte-identically.
func TestSanitizeTemplateVar_PreservesOrdinaryValues(t *testing.T) {
	unchanged := []string{
		"",
		"worker-1",
		"10Gi",
		"registry.example.com/team/image:v1.2.3",
		"a,b,c",
		"true",
		"3",
		"key=value",
		"some reason with spaces",
		"a: colon inside text",
		"trailing hash # comment-ish",
		"{{ not a template }}",
		"-flag-like",
		"path/to/thing",
		"emoji 🎉 and unicode 日本語",
	}

	for _, value := range unchanged {
		assert.Equal(t, value, sanitizeTemplateVar(value),
			"ordinary value must pass through unchanged: %q", value)
	}
}

// TestSanitizeTemplateVar_CollapsesLineBreaksToSpace documents that line breaks
// become a space rather than being deleted, so two tokens cannot silently merge.
func TestSanitizeTemplateVar_CollapsesLineBreaksToSpace(t *testing.T) {
	assert.Equal(t, "a b", sanitizeTemplateVar("a\nb"))
	assert.Equal(t, "a b", sanitizeTemplateVar("a\r\nb"))
	assert.Equal(t, "a b", sanitizeTemplateVar("a\rb"))
}

// TestSanitizeTemplateVar_DefusesDocumentSeparators covers a value that begins with
// a YAML document marker, which would start or end a document at column 0.
//
// Per the YAML spec a document indicator is only a marker when it is followed by
// end-of-input or whitespace, so every case here is a genuine marker.
func TestSanitizeTemplateVar_DefusesDocumentSeparators(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{"bare directives-end", "---", " ---"},
		{"bare document-end", "...", " ..."},
		{"marker then space", "--- ", " --- "},
		{"marker then tab", "---\t", " ---\t"},
		{"marker then newline", "---\nfoo", " --- foo"},
		{"document-end then newline", "...\nfoo", " ... foo"},
		{"marker then comment", "--- # c", " --- # c"},
		{"marker plus injection payload", "---\nhostNetwork: true", " --- hostNetwork: true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeTemplateVar(tc.value),
				"a real document marker must be defused")
		})
	}
}

// TestSanitizeTemplateVar_PreservesNonMarkerTripleIndicators pins the tightened
// predicate. "---foo" and "...bar" are plain YAML scalars, not document markers --
// a marker requires end-of-input or whitespace after the indicator -- so rewriting
// them would break the byte-for-byte-preservation guarantee this change promises.
//
// This test fails before the neutralizeDocumentSeparator tightening (the old
// strings.HasPrefix check prefixed a space to all of these) and passes after.
func TestSanitizeTemplateVar_PreservesNonMarkerTripleIndicators(t *testing.T) {
	unchanged := []string{
		"---foo",
		"...bar",
		"----",
		"....",
		"---:",
		"...v1.2.3",
		"---foo bar",
		"--->redirect",
		"...trailing ellipsis text",
	}

	for _, value := range unchanged {
		assert.Equal(t, value, sanitizeTemplateVar(value),
			"non-marker value must pass through unchanged: %q", value)
	}
}

// TestStartsWithDocumentMarker_MatchesYAMLSpec exercises the predicate directly,
// including the near-miss cases that separate a marker from a plain scalar.
func TestStartsWithDocumentMarker_MatchesYAMLSpec(t *testing.T) {
	markers := []string{"---", "...", "--- ", "...\t", "---\n", "...\r\n", "--- a: b"}
	for _, value := range markers {
		assert.True(t, startsWithDocumentMarker(value), "must be treated as a marker: %q", value)
	}

	plain := []string{"", "-", "--", "..", "---foo", "...bar", "----", "....", "a---", " ---", "x", "---é"}
	for _, value := range plain {
		assert.False(t, startsWithDocumentMarker(value), "must not be treated as a marker: %q", value)
	}
}

// TestSanitizeTemplateVarsReportingChanges proves the rewrite is observable rather
// than a silent mutation of user input (backwards-compat contract rule 5).
func TestSanitizeTemplateVarsReportingChanges(t *testing.T) {
	vars := map[string]string{
		"safe":      "worker-1",
		"dangerous": "worker-1\nhostNetwork: true",
		"alsoBad":   "x\ry",
	}

	sanitized, changed := sanitizeTemplateVarsReportingChanges(vars)

	assert.Equal(t, []string{"alsoBad", "dangerous"}, changed,
		"changed variable names must be reported, sorted, for logging")
	assert.Equal(t, "worker-1", sanitized["safe"], "safe value must be untouched")
	assert.NotContains(t, sanitized["dangerous"], "\n")
	assert.NotContains(t, sanitized["alsoBad"], "\r")
}

// TestBuildVarsFromSession_TemplateDefaultsAreAlsoSanitized covers the defaulting
// branch: a template-supplied default flows through the same var map, so it is
// escaped too. Defaults are operator-controlled, but escaping them keeps the
// invariant "every value in Vars is YAML-inert" total.
func TestBuildVarsFromSession_TemplateDefaultsAreAlsoSanitized(t *testing.T) {
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	raw := jsonString(t, "worker-1\nhostNetwork: true")
	templateSpec := &breakglassv1alpha1.DebugSessionTemplateSpec{
		ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
			{Name: "node", Default: &raw},
		},
	}

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{TemplateRef: "test-template"},
	}

	vars := controller.buildVarsFromSession(session, templateSpec)
	assert.NotContains(t, vars["node"], "\n")
}

// yamlLineTerminators are every terminator a YAML parser may honour, expressed as
// escapes so they stay visible in source review.
var yamlLineTerminators = []string{"\n", "\r", "\u0085", "\u2028", "\u2029"}

// FuzzSanitizeTemplateVar asserts the boundary invariant on arbitrary input: after
// sanitization a value can never carry a YAML line terminator, which is what makes
// sibling-key injection possible. It must also never panic and must be idempotent.
func FuzzSanitizeTemplateVar(f *testing.F) {
	seeds := []string{
		"",
		"worker-1",
		"worker-1\nhostNetwork: true",
		"worker-1\r\nhostPID: true",
		"worker-1\rhostIPC: true",
		"\n\n\n",
		"---",
		"...",
		"---\nhostNetwork: true",
		"a\u0085b",
		"a\u2028b",
		"a\u2029b",
		"10Gi",
		"registry.example.com/img:v1",
		"a: b # c",
		"{{ .vars.x }}",
		"\x00null-byte",
		"unicode\nhostNetwork: true",
		string(make([]byte, 300)),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		got := sanitizeTemplateVar(value)

		for _, terminator := range yamlLineTerminators {
			if strings.Contains(got, terminator) {
				t.Fatalf("sanitized value retained line terminator %q: input=%q output=%q",
					terminator, value, got)
			}
		}

		// A sanitized value must never begin a YAML document at column 0. Checked
		// against the spec predicate, not a bare HasPrefix, because "---foo" is a
		// plain scalar and must be preserved rather than rewritten.
		if startsWithDocumentMarker(got) {
			t.Fatalf("sanitized value still starts with a document separator: input=%q output=%q", value, got)
		}

		// Independent cross-check of the predicate against a real YAML parser: if
		// the sanitized value is parsed alone as a document it must still be a
		// single scalar node, never a document split. This catches a predicate that
		// is too narrow, which HasPrefix-style assertions cannot.
		var parsed []yaml.Node
		decoder := yaml.NewDecoder(strings.NewReader(got))
		for {
			var node yaml.Node
			if err := decoder.Decode(&node); err != nil {
				break
			}
			parsed = append(parsed, node)
		}
		if len(parsed) > 1 {
			t.Fatalf("sanitized value parsed as %d documents: input=%q output=%q", len(parsed), value, got)
		}

		// Sanitizing an already-sanitized value must be a no-op, otherwise repeated
		// reconciles would keep rewriting the same field.
		if again := sanitizeTemplateVar(got); again != got {
			t.Fatalf("sanitize is not idempotent: %q -> %q -> %q", value, got, again)
		}
	})
}

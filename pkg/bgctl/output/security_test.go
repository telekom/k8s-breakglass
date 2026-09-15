// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAllTableRenderersNeutralizeControls(t *testing.T) {
	dirty := "before\x00\x1b\u009b\u009d\n\rafter"
	sessions := []breakglassv1alpha1.BreakglassSession{{ObjectMeta: metav1.ObjectMeta{Name: dirty}, Spec: breakglassv1alpha1.BreakglassSessionSpec{Cluster: dirty, User: dirty, GrantedGroup: dirty}}}
	debug := []client.DebugSessionSummary{{Name: dirty, Cluster: dirty, RequestedBy: dirty, TemplateRef: dirty, TargetNamespace: dirty}}
	for name, render := range map[string]func(io.Writer){
		"session":      func(w io.Writer) { WriteSessionTable(w, sessions) },
		"session-wide": func(w io.Writer) { WriteSessionTableWide(w, sessions) },
		"escalation": func(w io.Writer) {
			WriteEscalationTable(w, []breakglassv1alpha1.BreakglassEscalation{{ObjectMeta: metav1.ObjectMeta{Name: dirty}}})
		},
		"watch":      func(w io.Writer) { WriteDebugSessionWatchLine(w, debug[0]) },
		"debug":      func(w io.Writer) { WriteDebugSessionTable(w, debug) },
		"debug-wide": func(w io.Writer) { WriteDebugSessionTableWide(w, debug) },
		"template": func(w io.Writer) {
			WriteDebugTemplateTable(w, []client.DebugSessionTemplateSummary{{Name: dirty, DisplayName: dirty, TargetNamespace: dirty}})
		},
		"pod-template": func(w io.Writer) {
			WriteDebugPodTemplateTable(w, []client.DebugPodTemplateSummary{{Name: dirty, DisplayName: dirty, Description: dirty}})
		},
		"cluster": func(w io.Writer) {
			WriteTemplateClusterTable(w, []client.AvailableClusterDetail{{Name: dirty, DisplayName: dirty, Environment: dirty}})
		},
		"cluster-wide": func(w io.Writer) {
			WriteTemplateClusterTableWide(w, []client.AvailableClusterDetail{{Name: dirty, DisplayName: dirty, Environment: dirty}})
		},
		"binding":       func(w io.Writer) { WriteBindingOptionsTable(w, dirty, []client.BindingOption{{DisplayName: dirty}}) },
		"binding-empty": func(w io.Writer) { WriteBindingOptionsTable(w, dirty, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			render(&b)
			if !strings.Contains(b.String(), "before") || !strings.Contains(b.String(), "after") {
				t.Fatalf("printable content lost: %q", b.String())
			}
			for _, r := range b.String() {
				if unicode.IsControl(r) && r != '\n' && r != '\t' {
					t.Fatalf("terminal control %U: %q", r, b.String())
				}
			}
			if strings.Contains(b.String(), "\nafter") {
				t.Fatalf("remote newline was retained: %q", b.String())
			}
		})
	}
}

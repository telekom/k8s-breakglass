// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Indexed by docs/debug-session-acceptance-matrix.md; keep the name stable.

import (
	"context"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Once a session exists its target (cluster, node, pod, namespace, template,
// binding, identity and every input the renderer consumes) is frozen: the
// admission webhook refuses any spec change, whatever the session state.
func TestDebugSessionValidateUpdateRejectsTargetReplacement(t *testing.T) {
	expires := metav1.NewTime(time.Now().Add(time.Hour))
	base := func(state DebugSessionState) *DebugSession {
		return &DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "breakglass"},
			Spec: DebugSessionSpec{
				Cluster: "cluster-a", TemplateRef: "template", RequestedBy: "user@example.com",
				TargetNamespace: "ns-a", NodeSelector: map[string]string{"pool": "a"},
				BindingRef:      &BindingReference{Name: "b", Namespace: "breakglass"},
				NodeMaintenance: &NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "uid-a"},
			},
			Status: DebugSessionStatus{State: state, ExpiresAt: &expires},
		}
	}
	changes := map[string]func(*DebugSessionSpec){
		"cluster":                func(s *DebugSessionSpec) { s.Cluster = "cluster-b" },
		"templateRef":            func(s *DebugSessionSpec) { s.TemplateRef = "other" },
		"requestedBy":            func(s *DebugSessionSpec) { s.RequestedBy = "attacker@example.com" },
		"requestedByEmail":       func(s *DebugSessionSpec) { s.RequestedByEmail = "attacker@example.com" },
		"userGroups":             func(s *DebugSessionSpec) { s.UserGroups = []string{"system:masters"} },
		"targetNamespace":        func(s *DebugSessionSpec) { s.TargetNamespace = "kube-system" },
		"nodeSelector":           func(s *DebugSessionSpec) { s.NodeSelector = map[string]string{"pool": "b"} },
		"bindingRef":             func(s *DebugSessionSpec) { s.BindingRef = &BindingReference{Name: "other", Namespace: "breakglass"} },
		"selectedScheduling":     func(s *DebugSessionSpec) { s.SelectedSchedulingOption = "other" },
		"auxiliaryResources":     func(s *DebugSessionSpec) { s.SelectedAuxiliaryResources = []string{"extra"} },
		"requestedDuration":      func(s *DebugSessionSpec) { s.RequestedDuration = "999h" },
		"invitedParticipants":    func(s *DebugSessionSpec) { s.InvitedParticipants = []string{"someone@example.com"} },
		"nodeMaintenance.node":   func(s *DebugSessionSpec) { s.NodeMaintenance.TargetNode = "node-b" },
		"nodeMaintenance.nodeID": func(s *DebugSessionSpec) { s.NodeMaintenance.TargetNodeUID = "uid-b" },
		"extraDeployValues": func(s *DebugSessionSpec) {
			s.ExtraDeployValues = map[string]apiextensionsv1.JSON{"image": {Raw: []byte(`"attacker/image"`)}}
		},
	}
	for _, state := range []DebugSessionState{DebugSessionStatePendingApproval, DebugSessionStateActive} {
		for name, change := range changes {
			t.Run(string(state)+"/"+name, func(t *testing.T) {
				old := base(state)
				updated := base(state)
				change(&updated.Spec)
				_, err := updated.ValidateUpdate(context.Background(), old, updated)
				if err == nil || !strings.Contains(err.Error(), "spec is immutable") {
					t.Fatalf("spec change %q after creation must be rejected as immutable, got: %v", name, err)
				}
			})
		}
	}
}

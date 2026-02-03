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

package v1alpha1

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionState(t *testing.T) {
	tests := []struct {
		name  string
		state DebugSessionState
	}{
		{"pending state", DebugSessionStatePending},
		{"pending approval state", DebugSessionStatePendingApproval},
		{"active state", DebugSessionStateActive},
		{"expired state", DebugSessionStateExpired},
		{"terminated state", DebugSessionStateTerminated},
		{"failed state", DebugSessionStateFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					State: tt.state,
				},
			}
			if session.Status.State != tt.state {
				t.Errorf("Expected state %s, got %s", tt.state, session.Status.State)
			}
		})
	}
}

func TestParticipantRole(t *testing.T) {
	tests := []struct {
		name string
		role ParticipantRole
	}{
		{"owner role", ParticipantRoleOwner},
		{"participant role", ParticipantRoleParticipant},
		{"viewer role", ParticipantRoleViewer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			participant := DebugSessionParticipant{
				Role: tt.role,
			}
			if participant.Role != tt.role {
				t.Errorf("Expected role %s, got %s", tt.role, participant.Role)
			}
		})
	}
}

func TestDebugSession_BasicSpec(t *testing.T) {
	session := DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-1",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:           "production-cluster",
			TemplateRef:       "standard-debug",
			RequestedBy:       "alice@example.com",
			RequestedDuration: "2h",
			Reason:            "Investigating production issue #12345",
		},
	}

	if session.Spec.Cluster != "production-cluster" {
		t.Error("Cluster mismatch")
	}
	if session.Spec.TemplateRef != "standard-debug" {
		t.Error("TemplateRef mismatch")
	}
	if session.Spec.RequestedBy != "alice@example.com" {
		t.Error("RequestedBy mismatch")
	}
	if session.Spec.RequestedDuration != "2h" {
		t.Error("RequestedDuration mismatch")
	}
}

func TestDebugSession_WithNodeSelector(t *testing.T) {
	session := DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "cluster-1",
			TemplateRef: "debug-template",
			RequestedBy: "user@example.com",
			NodeSelector: map[string]string{
				"node-type":                   "worker",
				"topology.kubernetes.io/zone": "us-east-1a",
				"kubernetes.io/arch":          "amd64",
			},
		},
	}

	if len(session.Spec.NodeSelector) != 3 {
		t.Errorf("Expected 3 node selectors, got %d", len(session.Spec.NodeSelector))
	}
	if session.Spec.NodeSelector["node-type"] != "worker" {
		t.Error("Expected node-type=worker")
	}
}

func TestDebugSession_WithInvitedParticipants(t *testing.T) {
	session := DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "cluster-1",
			TemplateRef: "debug-template",
			RequestedBy: "alice@example.com",
			InvitedParticipants: []string{
				"bob@example.com",
				"charlie@example.com",
				"diana@example.com",
			},
		},
	}

	if len(session.Spec.InvitedParticipants) != 3 {
		t.Errorf("Expected 3 invited participants, got %d", len(session.Spec.InvitedParticipants))
	}
}

func TestDebugSessionStatus_StateTransitions(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	tests := []struct {
		name   string
		status DebugSessionStatus
	}{
		{
			name: "pending state",
			status: DebugSessionStatus{
				State:   DebugSessionStatePending,
				Message: "Setting up debug session",
			},
		},
		{
			name: "pending approval state",
			status: DebugSessionStatus{
				State: DebugSessionStatePendingApproval,
				Approval: &DebugSessionApproval{
					Required: true,
				},
				Message: "Waiting for approval",
			},
		},
		{
			name: "active state",
			status: DebugSessionStatus{
				State:        DebugSessionStateActive,
				StartsAt:     &now,
				ExpiresAt:    &expiresAt,
				RenewalCount: 0,
				Participants: []DebugSessionParticipant{
					{
						User:     "alice@example.com",
						Role:     ParticipantRoleOwner,
						JoinedAt: now,
					},
				},
			},
		},
		{
			name: "expired state",
			status: DebugSessionStatus{
				State:        DebugSessionStateExpired,
				RenewalCount: 2,
				Message:      "Session expired",
			},
		},
		{
			name: "terminated state",
			status: DebugSessionStatus{
				State:   DebugSessionStateTerminated,
				Message: "Terminated by user",
			},
		},
		{
			name: "failed state",
			status: DebugSessionStatus{
				State:   DebugSessionStateFailed,
				Message: "Failed to deploy debug pods: namespace not found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: tt.status,
			}
			if session.Status.State != tt.status.State {
				t.Errorf("State mismatch")
			}
		})
	}
}

func TestDebugSessionApproval(t *testing.T) {
	now := metav1.Now()

	tests := []struct {
		name     string
		approval DebugSessionApproval
	}{
		{
			name: "pending approval",
			approval: DebugSessionApproval{
				Required: true,
			},
		},
		{
			name: "approved",
			approval: DebugSessionApproval{
				Required:   true,
				ApprovedBy: "manager@example.com",
				ApprovedAt: &now,
				Reason:     "Approved for incident response",
			},
		},
		{
			name: "rejected",
			approval: DebugSessionApproval{
				Required:   true,
				RejectedBy: "security@example.com",
				RejectedAt: &now,
				Reason:     "Request does not meet criteria",
			},
		},
		{
			name: "not required (auto-approved)",
			approval: DebugSessionApproval{
				Required:   false,
				ApprovedBy: "auto",
				ApprovedAt: &now,
				Reason:     "Auto-approved: user in senior-sre group",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					Approval: &tt.approval,
				},
			}
			if session.Status.Approval == nil {
				t.Fatal("Expected approval")
			}
			if session.Status.Approval.Required != tt.approval.Required {
				t.Error("Required mismatch")
			}
		})
	}
}

func TestDebugSessionParticipant(t *testing.T) {
	now := metav1.Now()
	leftAt := metav1.NewTime(now.Add(1 * time.Hour))

	tests := []struct {
		name        string
		participant DebugSessionParticipant
	}{
		{
			name: "owner currently active",
			participant: DebugSessionParticipant{
				User:     "alice@example.com",
				Role:     ParticipantRoleOwner,
				JoinedAt: now,
			},
		},
		{
			name: "participant currently active",
			participant: DebugSessionParticipant{
				User:     "bob@example.com",
				Role:     ParticipantRoleParticipant,
				JoinedAt: now,
			},
		},
		{
			name: "viewer currently active",
			participant: DebugSessionParticipant{
				User:     "viewer@example.com",
				Role:     ParticipantRoleViewer,
				JoinedAt: now,
			},
		},
		{
			name: "participant who left",
			participant: DebugSessionParticipant{
				User:     "charlie@example.com",
				Role:     ParticipantRoleParticipant,
				JoinedAt: now,
				LeftAt:   &leftAt,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					Participants: []DebugSessionParticipant{tt.participant},
				},
			}
			if len(session.Status.Participants) != 1 {
				t.Fatal("Expected 1 participant")
			}
			p := session.Status.Participants[0]
			if p.User != tt.participant.User {
				t.Error("User mismatch")
			}
			if p.Role != tt.participant.Role {
				t.Error("Role mismatch")
			}
		})
	}
}

func TestTerminalSharingStatus(t *testing.T) {
	tests := []struct {
		name   string
		status TerminalSharingStatus
	}{
		{
			name: "sharing disabled",
			status: TerminalSharingStatus{
				Enabled: false,
			},
		},
		{
			name: "sharing enabled with tmux",
			status: TerminalSharingStatus{
				Enabled:       true,
				SessionName:   "debug-session-abc123",
				AttachCommand: "tmux attach-session -t debug-session-abc123",
			},
		},
		{
			name: "sharing enabled with screen",
			status: TerminalSharingStatus{
				Enabled:       true,
				SessionName:   "debug_abc123",
				AttachCommand: "screen -x debug_abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					TerminalSharing: &tt.status,
				},
			}
			if session.Status.TerminalSharing.Enabled != tt.status.Enabled {
				t.Error("Enabled mismatch")
			}
		})
	}
}

func TestDeployedResourceRef(t *testing.T) {
	tests := []struct {
		name     string
		resource DeployedResourceRef
	}{
		{
			name: "DaemonSet",
			resource: DeployedResourceRef{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
				Name:       "debug-session-abc-debug",
				Namespace:  "breakglass-debug",
			},
		},
		{
			name: "Deployment",
			resource: DeployedResourceRef{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       "debug-session-abc-debug",
				Namespace:  "breakglass-debug",
			},
		},
		{
			name: "ServiceAccount",
			resource: DeployedResourceRef{
				APIVersion: "v1",
				Kind:       "ServiceAccount",
				Name:       "debug-sa",
				Namespace:  "breakglass-debug",
			},
		},
		{
			name: "cluster-scoped resource",
			resource: DeployedResourceRef{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "ClusterRole",
				Name:       "debug-role",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					DeployedResources: []DeployedResourceRef{tt.resource},
				},
			}
			if len(session.Status.DeployedResources) != 1 {
				t.Fatal("Expected 1 deployed resource")
			}
			r := session.Status.DeployedResources[0]
			if r.Kind != tt.resource.Kind {
				t.Error("Kind mismatch")
			}
		})
	}
}

func TestAllowedPodRef(t *testing.T) {
	tests := []struct {
		name string
		pod  AllowedPodRef
	}{
		{
			name: "ready pod",
			pod: AllowedPodRef{
				Namespace: "breakglass-debug",
				Name:      "debug-abc-xyz",
				NodeName:  "worker-1",
				Ready:     true,
			},
		},
		{
			name: "not ready pod",
			pod: AllowedPodRef{
				Namespace: "breakglass-debug",
				Name:      "debug-abc-123",
				NodeName:  "worker-2",
				Ready:     false,
			},
		},
		{
			name: "pod without node (pending)",
			pod: AllowedPodRef{
				Namespace: "breakglass-debug",
				Name:      "debug-pending",
				Ready:     false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					AllowedPods: []AllowedPodRef{tt.pod},
				},
			}
			if len(session.Status.AllowedPods) != 1 {
				t.Fatal("Expected 1 allowed pod")
			}
			p := session.Status.AllowedPods[0]
			if p.Name != tt.pod.Name {
				t.Error("Name mismatch")
			}
			if p.Ready != tt.pod.Ready {
				t.Error("Ready mismatch")
			}
		})
	}
}

func TestKubectlDebugStatus(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	status := KubectlDebugStatus{
		EphemeralContainersInjected: []EphemeralContainerRef{
			{
				PodName:       "app-pod-1",
				Namespace:     "default",
				ContainerName: "debug",
				Image:         "busybox:latest",
				InjectedAt:    now,
				InjectedBy:    "alice@example.com",
			},
		},
		CopiedPods: []CopiedPodRef{
			{
				OriginalPod:       "app-pod-2",
				OriginalNamespace: "default",
				CopyName:          "app-pod-2-debug",
				CopyNamespace:     "debug-copies",
				CreatedAt:         now,
				ExpiresAt:         &expiresAt,
			},
		},
	}

	session := DebugSession{
		Status: DebugSessionStatus{
			KubectlDebugStatus: &status,
		},
	}

	if session.Status.KubectlDebugStatus == nil {
		t.Fatal("Expected kubectl debug status")
	}
	if len(session.Status.KubectlDebugStatus.EphemeralContainersInjected) != 1 {
		t.Error("Expected 1 ephemeral container")
	}
	if len(session.Status.KubectlDebugStatus.CopiedPods) != 1 {
		t.Error("Expected 1 copied pod")
	}
}

func TestEphemeralContainerRef(t *testing.T) {
	now := metav1.Now()
	ref := EphemeralContainerRef{
		PodName:       "my-app",
		Namespace:     "production",
		ContainerName: "debugger",
		Image:         "nicolaka/netshoot:latest",
		InjectedAt:    now,
		InjectedBy:    "admin@example.com",
	}

	if ref.PodName != "my-app" {
		t.Error("PodName mismatch")
	}
	if ref.ContainerName != "debugger" {
		t.Error("ContainerName mismatch")
	}
	if ref.InjectedBy != "admin@example.com" {
		t.Error("InjectedBy mismatch")
	}
}

func TestCopiedPodRef(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	ref := CopiedPodRef{
		OriginalPod:       "production-app",
		OriginalNamespace: "production",
		CopyName:          "production-app-debug-abc123",
		CopyNamespace:     "debug-copies",
		CreatedAt:         now,
		ExpiresAt:         &expiresAt,
	}

	if ref.OriginalPod != "production-app" {
		t.Error("OriginalPod mismatch")
	}
	if ref.CopyName != "production-app-debug-abc123" {
		t.Error("CopyName mismatch")
	}
	if ref.ExpiresAt == nil {
		t.Fatal("Expected ExpiresAt")
	}
}

func TestDebugSession_DeepCopy(t *testing.T) {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	original := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "original-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "debug-template",
			RequestedBy:       "alice@example.com",
			RequestedDuration: "2h",
			NodeSelector: map[string]string{
				"zone": "us-east-1",
			},
		},
		Status: DebugSessionStatus{
			State:        DebugSessionStateActive,
			StartsAt:     &now,
			ExpiresAt:    &expiresAt,
			RenewalCount: 1,
			Participants: []DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     ParticipantRoleOwner,
					JoinedAt: now,
				},
			},
		},
	}

	copied := original.DeepCopy()

	// Verify copy
	if copied.Name != original.Name {
		t.Error("Name mismatch")
	}
	if copied.Spec.Cluster != original.Spec.Cluster {
		t.Error("Cluster mismatch")
	}
	if copied.Status.State != original.Status.State {
		t.Error("State mismatch")
	}

	// Modify copy and verify original unchanged
	copied.Spec.Cluster = "staging"
	if original.Spec.Cluster == "staging" {
		t.Error("DeepCopy modified original cluster")
	}

	copied.Spec.NodeSelector["zone"] = "us-west-2"
	if original.Spec.NodeSelector["zone"] == "us-west-2" {
		t.Error("DeepCopy modified original node selector")
	}

	copied.Status.RenewalCount = 5
	if original.Status.RenewalCount == 5 {
		t.Error("DeepCopy modified original renewal count")
	}
}

func TestDebugSessionList(t *testing.T) {
	list := &DebugSessionList{
		Items: []DebugSession{
			{ObjectMeta: metav1.ObjectMeta{Name: "session-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "session-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "session-3"}},
		},
	}

	if len(list.Items) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list.Items))
	}

	// Verify DeepCopy of list
	copiedList := list.DeepCopy()
	if len(copiedList.Items) != 3 {
		t.Error("DeepCopy list length mismatch")
	}
}

func TestDebugSession_CompleteLifecycle(t *testing.T) {
	now := metav1.Now()
	startsAt := now
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))
	approvedAt := metav1.NewTime(now.Add(-5 * time.Minute))

	session := DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "incident-debug-12345",
			Namespace: "breakglass",
			Labels: map[string]string{
				"incident":    "12345",
				"environment": "production",
			},
		},
		Spec: DebugSessionSpec{
			Cluster:           "production-us-east",
			TemplateRef:       "production-debug",
			RequestedBy:       "alice@example.com",
			RequestedDuration: "2h",
			Reason:            "Investigating incident #12345 - API latency issues",
			NodeSelector: map[string]string{
				"node-role.kubernetes.io/worker": "",
			},
			InvitedParticipants: []string{
				"bob@example.com",
				"charlie@example.com",
			},
		},
		Status: DebugSessionStatus{
			State: DebugSessionStateActive,
			Approval: &DebugSessionApproval{
				Required:   true,
				ApprovedBy: "manager@example.com",
				ApprovedAt: &approvedAt,
				Reason:     "Approved for incident response",
			},
			Participants: []DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     ParticipantRoleOwner,
					JoinedAt: startsAt,
				},
				{
					User:     "bob@example.com",
					Role:     ParticipantRoleParticipant,
					JoinedAt: metav1.NewTime(now.Add(5 * time.Minute)),
				},
			},
			TerminalSharing: &TerminalSharingStatus{
				Enabled:       true,
				SessionName:   "incident-debug-12345",
				AttachCommand: "tmux attach-session -t incident-debug-12345",
			},
			DeployedResources: []DeployedResourceRef{
				{
					APIVersion: "apps/v1",
					Kind:       "DaemonSet",
					Name:       "incident-debug-12345-debug",
					Namespace:  "breakglass-debug",
				},
			},
			AllowedPods: []AllowedPodRef{
				{
					Namespace: "breakglass-debug",
					Name:      "incident-debug-12345-debug-abc",
					NodeName:  "worker-1",
					Ready:     true,
				},
				{
					Namespace: "breakglass-debug",
					Name:      "incident-debug-12345-debug-def",
					NodeName:  "worker-2",
					Ready:     true,
				},
			},
			StartsAt:     &startsAt,
			ExpiresAt:    &expiresAt,
			RenewalCount: 0,
			Message:      "Session active with 2 debug pods",
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: now,
					Reason:             "AllPodsReady",
					Message:            "All debug pods are ready",
				},
			},
		},
	}

	// Validate complete session
	if session.Status.State != DebugSessionStateActive {
		t.Error("Expected active state")
	}
	if session.Status.Approval == nil || !session.Status.Approval.Required {
		t.Error("Expected approval required")
	}
	if len(session.Status.Participants) != 2 {
		t.Error("Expected 2 participants")
	}
	if session.Status.TerminalSharing == nil || !session.Status.TerminalSharing.Enabled {
		t.Error("Expected terminal sharing enabled")
	}
	if len(session.Status.DeployedResources) != 1 {
		t.Error("Expected 1 deployed resource")
	}
	if len(session.Status.AllowedPods) != 2 {
		t.Error("Expected 2 allowed pods")
	}
	if len(session.Status.Conditions) != 1 {
		t.Error("Expected 1 condition")
	}
}

func TestDebugSession_RenewalTracking(t *testing.T) {
	now := metav1.Now()

	tests := []struct {
		name         string
		renewalCount int32
	}{
		{"no renewals", 0},
		{"one renewal", 1},
		{"max renewals", 3},
		{"over max", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Status: DebugSessionStatus{
					State:        DebugSessionStateActive,
					StartsAt:     &now,
					RenewalCount: tt.renewalCount,
				},
			}
			if session.Status.RenewalCount != tt.renewalCount {
				t.Errorf("Expected %d renewals, got %d", tt.renewalCount, session.Status.RenewalCount)
			}
		})
	}
}

func TestDebugSession_WithResolvedTemplate(t *testing.T) {
	allowRenewal := true
	maxRenewals := int32(3)
	session := DebugSession{
		Status: DebugSessionStatus{
			State: DebugSessionStateActive,
			ResolvedTemplate: &DebugSessionTemplateSpec{
				DisplayName: "Cached Template",
				Mode:        DebugSessionModeWorkload,
				Constraints: &DebugSessionConstraints{
					MaxDuration:     "4h",
					DefaultDuration: "1h",
					AllowRenewal:    &allowRenewal,
					MaxRenewals:     &maxRenewals,
				},
			},
		},
	}

	if session.Status.ResolvedTemplate == nil {
		t.Fatal("Expected resolved template")
	}
	if session.Status.ResolvedTemplate.Mode != DebugSessionModeWorkload {
		t.Error("Expected workload mode in resolved template")
	}
	if session.Status.ResolvedTemplate.Constraints == nil {
		t.Fatal("Expected constraints in resolved template")
	}
	if session.Status.ResolvedTemplate.Constraints.MaxDuration != "4h" {
		t.Error("Expected MaxDuration 4h")
	}
}

func TestDebugSession_MultipleParticipantStates(t *testing.T) {
	now := metav1.Now()
	leftAt := metav1.NewTime(now.Add(30 * time.Minute))

	session := DebugSession{
		Status: DebugSessionStatus{
			Participants: []DebugSessionParticipant{
				{
					User:     "alice@example.com",
					Role:     ParticipantRoleOwner,
					JoinedAt: now,
				},
				{
					User:     "bob@example.com",
					Role:     ParticipantRoleParticipant,
					JoinedAt: metav1.NewTime(now.Add(5 * time.Minute)),
				},
				{
					User:     "charlie@example.com",
					Role:     ParticipantRoleParticipant,
					JoinedAt: metav1.NewTime(now.Add(10 * time.Minute)),
					LeftAt:   &leftAt,
				},
				{
					User:     "viewer@example.com",
					Role:     ParticipantRoleViewer,
					JoinedAt: metav1.NewTime(now.Add(15 * time.Minute)),
				},
			},
		},
	}

	if len(session.Status.Participants) != 4 {
		t.Errorf("Expected 4 participants, got %d", len(session.Status.Participants))
	}

	// Count active participants (not left)
	activeCount := 0
	for _, p := range session.Status.Participants {
		if p.LeftAt == nil {
			activeCount++
		}
	}
	if activeCount != 3 {
		t.Errorf("Expected 3 active participants, got %d", activeCount)
	}

	// Count by role
	roleCount := make(map[ParticipantRole]int)
	for _, p := range session.Status.Participants {
		roleCount[p.Role]++
	}
	if roleCount[ParticipantRoleOwner] != 1 {
		t.Error("Expected 1 owner")
	}
	if roleCount[ParticipantRoleParticipant] != 2 {
		t.Error("Expected 2 participants")
	}
	if roleCount[ParticipantRoleViewer] != 1 {
		t.Error("Expected 1 viewer")
	}
}

// ============================================================================
// BAD CASE / VALIDATION ERROR TESTS FOR DEBUG SESSION TYPES
// ============================================================================

func TestDebugSession_EmptyRequiredFields(t *testing.T) {
	t.Run("empty cluster", func(t *testing.T) {
		session := DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "", // Empty
				TemplateRef: "template",
				RequestedBy: "user@example.com",
			},
		}
		if session.Spec.Cluster != "" {
			t.Error("Expected empty cluster")
		}
	})

	t.Run("empty template ref", func(t *testing.T) {
		session := DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "cluster",
				TemplateRef: "", // Empty
				RequestedBy: "user@example.com",
			},
		}
		if session.Spec.TemplateRef != "" {
			t.Error("Expected empty template ref")
		}
	})

	t.Run("empty requestedBy", func(t *testing.T) {
		session := DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "cluster",
				TemplateRef: "template",
				RequestedBy: "", // Empty
			},
		}
		if session.Spec.RequestedBy != "" {
			t.Error("Expected empty requestedBy")
		}
	})

	t.Run("empty reason", func(t *testing.T) {
		session := DebugSession{
			Spec: DebugSessionSpec{
				Cluster:     "cluster",
				TemplateRef: "template",
				RequestedBy: "user@example.com",
				Reason:      "", // Empty
			},
		}
		if session.Spec.Reason != "" {
			t.Error("Expected empty reason")
		}
	})
}

func TestDebugSession_InvalidDurationFormats(t *testing.T) {
	tests := []struct {
		name     string
		duration string
	}{
		{"invalid format", "invalid"},
		{"negative duration", "-1h"},
		{"zero duration", "0"},
		{"just numbers", "123"},
		{"wrong units", "2days"},
		{"spaces", " 2h "},
		{"special chars", "2h@#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Spec: DebugSessionSpec{
					Cluster:           "cluster",
					TemplateRef:       "template",
					RequestedBy:       "user@example.com",
					RequestedDuration: tt.duration,
				},
			}
			// The CRD accepts these strings; validation would happen at runtime
			if session.Spec.RequestedDuration != tt.duration {
				t.Errorf("Expected duration %s, got %s", tt.duration, session.Spec.RequestedDuration)
			}
		})
	}
}

func TestDebugSession_InvalidState(t *testing.T) {
	t.Run("unknown state value", func(t *testing.T) {
		session := DebugSession{
			Status: DebugSessionStatus{
				State: DebugSessionState("InvalidState"), // Cast invalid string
			},
		}
		// This would be caught by CEL validation in production
		if session.Status.State == DebugSessionStatePending ||
			session.Status.State == DebugSessionStatePendingApproval ||
			session.Status.State == DebugSessionStateActive ||
			session.Status.State == DebugSessionStateExpired ||
			session.Status.State == DebugSessionStateTerminated ||
			session.Status.State == DebugSessionStateFailed {
			t.Error("Expected invalid state")
		}
	})
}

func TestDebugSession_InvalidParticipantRole(t *testing.T) {
	t.Run("unknown role value", func(t *testing.T) {
		participant := DebugSessionParticipant{
			User: "user@example.com",
			Role: ParticipantRole("InvalidRole"), // Cast invalid string
		}
		// This would be caught by validation in production
		if participant.Role == ParticipantRoleOwner ||
			participant.Role == ParticipantRoleParticipant ||
			participant.Role == ParticipantRoleViewer {
			t.Error("Expected invalid role")
		}
	})
}

func TestDebugSession_InvalidApprovalState(t *testing.T) {
	t.Run("both approved and rejected", func(t *testing.T) {
		now := metav1.Now()
		session := DebugSession{
			Status: DebugSessionStatus{
				State: DebugSessionStateFailed,
				Approval: &DebugSessionApproval{
					Required:   true,
					ApprovedBy: "approver@example.com", // Both approved...
					ApprovedAt: &now,
					RejectedBy: "security@example.com", // ...and rejected
					RejectedAt: &now,
				},
			},
		}
		// Invalid state - should not have both approved and rejected
		if session.Status.Approval.ApprovedBy != "" && session.Status.Approval.RejectedBy != "" {
			// This is an inconsistent state
			t.Log("Warning: Session has both ApprovedBy and RejectedBy set - invalid state")
		}
	})

	t.Run("approved without approvedAt", func(t *testing.T) {
		session := DebugSession{
			Status: DebugSessionStatus{
				Approval: &DebugSessionApproval{
					Required:   true,
					ApprovedBy: "approver@example.com",
					ApprovedAt: nil, // Missing timestamp
				},
			},
		}
		// Should have ApprovedAt when ApprovedBy is set
		if session.Status.Approval.ApprovedBy != "" && session.Status.Approval.ApprovedAt == nil {
			t.Log("Warning: ApprovedBy set without ApprovedAt - inconsistent state")
		}
	})
}

func TestDebugSession_NegativeRenewalCount(t *testing.T) {
	session := DebugSession{
		Status: DebugSessionStatus{
			RenewalCount: -1, // Negative
		},
	}
	if session.Status.RenewalCount >= 0 {
		t.Error("Expected negative renewal count")
	}
}

func TestDebugSession_ExpiresBeforeStarts(t *testing.T) {
	now := metav1.Now()
	startsAt := metav1.NewTime(now.Add(2 * time.Hour))
	expiresAt := metav1.NewTime(now.Add(1 * time.Hour)) // Before startsAt

	session := DebugSession{
		Status: DebugSessionStatus{
			StartsAt:  &startsAt,
			ExpiresAt: &expiresAt,
		},
	}
	// ExpiresAt should be after StartsAt
	if session.Status.ExpiresAt.Before(session.Status.StartsAt) {
		t.Log("Warning: ExpiresAt is before StartsAt - invalid state")
	}
}

func TestDebugSession_ParticipantLeftBeforeJoined(t *testing.T) {
	now := metav1.Now()
	joinedAt := metav1.NewTime(now.Add(1 * time.Hour))
	leftAt := metav1.NewTime(now.Add(-1 * time.Hour)) // Before joinedAt

	participant := DebugSessionParticipant{
		User:     "user@example.com",
		Role:     ParticipantRoleParticipant,
		JoinedAt: joinedAt,
		LeftAt:   &leftAt,
	}
	// LeftAt should be after JoinedAt
	if participant.LeftAt.Before(&participant.JoinedAt) {
		t.Log("Warning: LeftAt is before JoinedAt - invalid state")
	}
}

func TestDebugSession_DuplicateParticipants(t *testing.T) {
	now := metav1.Now()
	session := DebugSession{
		Status: DebugSessionStatus{
			Participants: []DebugSessionParticipant{
				{
					User:     "user@example.com",
					Role:     ParticipantRoleOwner,
					JoinedAt: now,
				},
				{
					User:     "user@example.com", // Duplicate
					Role:     ParticipantRoleParticipant,
					JoinedAt: now,
				},
			},
		},
	}
	// Check for duplicates
	seen := make(map[string]bool)
	hasDuplicates := false
	for _, p := range session.Status.Participants {
		if seen[p.User] {
			hasDuplicates = true
			break
		}
		seen[p.User] = true
	}
	if !hasDuplicates {
		t.Error("Expected to find duplicate participants")
	}
}

func TestDebugSession_MultipleOwners(t *testing.T) {
	now := metav1.Now()
	session := DebugSession{
		Status: DebugSessionStatus{
			Participants: []DebugSessionParticipant{
				{
					User:     "owner1@example.com",
					Role:     ParticipantRoleOwner,
					JoinedAt: now,
				},
				{
					User:     "owner2@example.com",
					Role:     ParticipantRoleOwner, // Second owner
					JoinedAt: now,
				},
			},
		},
	}
	// Count owners
	ownerCount := 0
	for _, p := range session.Status.Participants {
		if p.Role == ParticipantRoleOwner {
			ownerCount++
		}
	}
	if ownerCount <= 1 {
		t.Error("Expected multiple owners")
	}
}

func TestDebugSession_EmptyAllowedPods(t *testing.T) {
	session := DebugSession{
		Status: DebugSessionStatus{
			State:       DebugSessionStateActive,
			AllowedPods: []AllowedPodRef{}, // Empty slice
		},
	}
	if len(session.Status.AllowedPods) != 0 {
		t.Error("Expected empty allowed pods")
	}
}

func TestDebugSession_InvalidNodeSelectors(t *testing.T) {
	tests := []struct {
		name     string
		selector map[string]string
	}{
		{"empty key", map[string]string{"": "value"}},
		{"empty value", map[string]string{"key": ""}},
		{"special chars in key", map[string]string{"key@#$": "value"}},
		{"very long key", map[string]string{string(make([]byte, 1000)): "value"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Spec: DebugSessionSpec{
					Cluster:      "cluster",
					TemplateRef:  "template",
					RequestedBy:  "user@example.com",
					NodeSelector: tt.selector,
				},
			}
			// CRD accepts these; Kubernetes would reject at runtime
			if session.Spec.NodeSelector == nil {
				t.Error("Expected node selector to be set")
			}
		})
	}
}

func TestDebugSession_NilResolvedTemplate(t *testing.T) {
	session := DebugSession{
		Status: DebugSessionStatus{
			State:            DebugSessionStateActive,
			ResolvedTemplate: nil, // Not resolved yet
		},
	}
	if session.Status.ResolvedTemplate != nil {
		t.Error("Expected nil resolved template")
	}
}

func TestDebugSession_EmptyDeployedResources(t *testing.T) {
	session := DebugSession{
		Status: DebugSessionStatus{
			State:             DebugSessionStateActive,
			DeployedResources: []DeployedResourceRef{}, // Empty
		},
	}
	if len(session.Status.DeployedResources) != 0 {
		t.Error("Expected empty deployed resources")
	}
}

func TestDebugSession_InvalidEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"no at sign", "userexample.com"},
		{"no domain", "user@"},
		{"no local", "@example.com"},
		{"spaces", "user @example.com"},
		{"special chars", "user<>@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := DebugSession{
				Spec: DebugSessionSpec{
					Cluster:     "cluster",
					TemplateRef: "template",
					RequestedBy: tt.email, // Invalid email
				},
			}
			// CRD accepts these; validation would happen elsewhere
			if session.Spec.RequestedBy != tt.email {
				t.Errorf("Expected email %s", tt.email)
			}
		})
	}
}

// Webhook validation tests

func TestDebugSession_ValidateCreate_Valid(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "standard-debug",
			RequestedBy:       "user@example.com",
			RequestedDuration: "2h",
			Reason:            "Investigating issue",
		},
	}

	warnings, err := session.ValidateCreate(ctx, session)
	if err != nil {
		t.Errorf("ValidateCreate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
	}
}

func TestDebugSession_ValidateCreate_MissingCluster(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:     "", // missing
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
	}

	_, err := session.ValidateCreate(ctx, session)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing cluster")
	}
}

func TestDebugSession_ValidateCreate_MissingTemplateRef(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "", // missing
			RequestedBy: "user@example.com",
		},
	}

	_, err := session.ValidateCreate(ctx, session)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing templateRef")
	}
}

func TestDebugSession_ValidateCreate_MissingRequestedBy(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "", // missing
		},
	}

	_, err := session.ValidateCreate(ctx, session)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing requestedBy")
	}
}

func TestDebugSession_ValidateCreate_InvalidDuration(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:           "cluster",
			TemplateRef:       "template",
			RequestedBy:       "user@example.com",
			RequestedDuration: "invalid", // invalid duration
		},
	}

	_, err := session.ValidateCreate(ctx, session)
	if err == nil {
		t.Error("ValidateCreate() expected error for invalid duration")
	}
}

func TestDebugSession_ValidateCreate_ValidDurations(t *testing.T) {
	ctx := context.Background()
	validDurations := []string{"1h", "30m", "2h30m", "24h", "1h30m45s", ""}

	for _, duration := range validDurations {
		t.Run("duration_"+duration, func(t *testing.T) {
			session := &DebugSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "session",
					Namespace: "breakglass",
				},
				Spec: DebugSessionSpec{
					Cluster:           "cluster",
					TemplateRef:       "template",
					RequestedBy:       "user@example.com",
					RequestedDuration: duration,
				},
			}

			_, err := session.ValidateCreate(ctx, session)
			if err != nil {
				t.Errorf("ValidateCreate() unexpected error for duration %q: %v", duration, err)
			}
		})
	}
}

func TestDebugSession_ValidateUpdate(t *testing.T) {
	ctx := context.Background()
	oldSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
	}
	newSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session",
			Namespace: "breakglass",
		},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
			Reason:      "Updated reason",
		},
	}

	warnings, err := newSession.ValidateUpdate(ctx, oldSession, newSession)
	if err != nil {
		t.Errorf("ValidateUpdate() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateUpdate() unexpected warnings: %v", warnings)
	}
}

func TestDebugSession_ValidateDelete(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session",
			Namespace: "breakglass",
		},
	}

	warnings, err := session.ValidateDelete(ctx, session)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("ValidateDelete() unexpected warnings: %v", warnings)
	}
}

func TestDebugSession_ValidateCreate_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session"},
		Spec:       DebugSessionSpec{},
	}

	_, err := session.ValidateCreate(ctx, session)
	if err == nil {
		t.Error("ValidateCreate() expected error for missing required fields")
	}
}

// SetCondition and GetCondition tests

func TestDebugSession_SetCondition(t *testing.T) {
	session := &DebugSession{}
	condition := metav1.Condition{
		Type:               string(DebugSessionConditionApproved),
		Status:             metav1.ConditionTrue,
		Reason:             "Approved",
		Message:            "Session approved",
		LastTransitionTime: metav1.Now(),
	}

	session.SetCondition(condition)

	if len(session.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(session.Status.Conditions))
	}
	if session.Status.Conditions[0].Type != string(DebugSessionConditionApproved) {
		t.Errorf("Expected condition type %s", DebugSessionConditionApproved)
	}
}

func TestDebugSession_SetCondition_Update(t *testing.T) {
	session := &DebugSession{}
	condition1 := metav1.Condition{
		Type:               string(DebugSessionConditionApproved),
		Status:             metav1.ConditionFalse,
		Reason:             "Pending",
		LastTransitionTime: metav1.Now(),
	}
	session.SetCondition(condition1)

	condition2 := metav1.Condition{
		Type:               string(DebugSessionConditionApproved),
		Status:             metav1.ConditionTrue,
		Reason:             "Approved",
		LastTransitionTime: metav1.Now(),
	}
	session.SetCondition(condition2)

	if len(session.Status.Conditions) != 1 {
		t.Errorf("Expected 1 condition after update, got %d", len(session.Status.Conditions))
	}
	if session.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Error("Expected condition status to be updated to True")
	}
}

func TestDebugSession_GetCondition(t *testing.T) {
	session := &DebugSession{
		Status: DebugSessionStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(DebugSessionConditionApproved),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	condition := session.GetCondition(string(DebugSessionConditionApproved))
	if condition == nil {
		t.Fatal("Expected to find condition")
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("Expected status True, got %v", condition.Status)
	}
}

func TestDebugSession_GetCondition_NotFound(t *testing.T) {
	session := &DebugSession{}
	condition := session.GetCondition("non-existent")
	if condition != nil {
		t.Error("Expected nil for non-existent condition")
	}
}

func TestDebugSession_MultipleConditions(t *testing.T) {
	session := &DebugSession{}

	session.SetCondition(metav1.Condition{
		Type:               string(DebugSessionConditionApproved),
		Status:             metav1.ConditionTrue,
		Reason:             "Approved",
		LastTransitionTime: metav1.Now(),
	})
	session.SetCondition(metav1.Condition{
		Type:               string(DebugSessionConditionReady),
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		LastTransitionTime: metav1.Now(),
	})

	if len(session.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions, got %d", len(session.Status.Conditions))
	}

	approved := session.GetCondition(string(DebugSessionConditionApproved))
	ready := session.GetCondition(string(DebugSessionConditionReady))

	if approved == nil || ready == nil {
		t.Error("Expected both conditions to be found")
	}
}

func TestDebugSession_ValidateUpdate_InvalidSpec(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{}

	oldSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
	}

	newSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       DebugSessionSpec{},
	}

	_, err := session.ValidateUpdate(ctx, oldSession, newSession)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid new spec")
	}
}

func TestDebugSession_ValidateUpdate_Invalid(t *testing.T) {
	ctx := context.Background()
	session := &DebugSession{}

	oldSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
	}

	newSession := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: DebugSessionSpec{
			Cluster:           "cluster",
			TemplateRef:       "", // missing - invalid
			RequestedBy:       "user@example.com",
			RequestedDuration: "invalid-duration",
		},
	}

	_, err := session.ValidateUpdate(ctx, oldSession, newSession)
	if err == nil {
		t.Error("ValidateUpdate() expected error for invalid spec")
	}
}

func TestValidateDebugSessionSpec_Nil(t *testing.T) {
	errs := validateDebugSessionSpec(nil)
	if errs != nil {
		t.Errorf("validateDebugSessionSpec(nil) expected nil errors, got %v", errs)
	}
}

func TestDebugSession_ValidateCreate_ValidDuration(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:           "cluster",
			TemplateRef:       "template",
			RequestedBy:       "user@example.com",
			RequestedDuration: "2h",
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err != nil {
		t.Errorf("expected success with valid duration, got %v", err)
	}
}

// TestValidateDebugSessionSpec_AllFieldsMissing tests validation when all required fields are missing
func TestValidateDebugSessionSpec_AllFieldsMissing(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "",
			TemplateRef: "",
			RequestedBy: "",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 3 {
		t.Errorf("expected 3 errors for missing cluster, templateRef, and requestedBy, got %d: %v", len(errs), errs)
	}
}

// TestValidateDebugSessionSpec_MissingCluster tests validation when cluster is missing
func TestValidateDebugSessionSpec_MissingCluster(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "",
			TemplateRef: "template",
			RequestedBy: "user@example.com",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 1 {
		t.Errorf("expected 1 error for missing cluster, got %d: %v", len(errs), errs)
	}
	if errs[0].Field != "spec.cluster" {
		t.Errorf("expected error field spec.cluster, got %s", errs[0].Field)
	}
}

// TestValidateDebugSessionSpec_MissingTemplateRef tests validation when templateRef is missing
func TestValidateDebugSessionSpec_MissingTemplateRef(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "",
			RequestedBy: "user@example.com",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 1 {
		t.Errorf("expected 1 error for missing templateRef, got %d: %v", len(errs), errs)
	}
	if errs[0].Field != "spec.templateRef" {
		t.Errorf("expected error field spec.templateRef, got %s", errs[0].Field)
	}
}

// TestValidateDebugSessionSpec_MissingRequestedBy tests validation when requestedBy is missing
func TestValidateDebugSessionSpec_MissingRequestedBy(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:     "cluster",
			TemplateRef: "template",
			RequestedBy: "",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 1 {
		t.Errorf("expected 1 error for missing requestedBy, got %d: %v", len(errs), errs)
	}
	if errs[0].Field != "spec.requestedBy" {
		t.Errorf("expected error field spec.requestedBy, got %s", errs[0].Field)
	}
}

// TestValidateDebugSessionSpec_InvalidDuration tests validation with an invalid duration format
func TestValidateDebugSessionSpec_InvalidDuration(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:           "cluster",
			TemplateRef:       "template",
			RequestedBy:       "user@example.com",
			RequestedDuration: "invalid",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 1 {
		t.Errorf("expected 1 error for invalid duration, got %d: %v", len(errs), errs)
	}
}

// TestValidateDebugSessionSpec_ValidWithAllFields tests a fully valid session spec
func TestValidateDebugSessionSpec_ValidWithAllFields(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:           "production",
			TemplateRef:       "debug-template",
			RequestedBy:       "user@example.com",
			RequestedDuration: "2h30m",
			Reason:            "Investigating issue #1234",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for valid session, got %d: %v", len(errs), errs)
	}
}

// TestValidateDebugSessionSpec_DayDuration tests a valid day duration
func TestValidateDebugSessionSpec_DayDuration(t *testing.T) {
	session := &DebugSession{
		Spec: DebugSessionSpec{
			Cluster:           "cluster",
			TemplateRef:       "template",
			RequestedBy:       "user@example.com",
			RequestedDuration: "1d12h",
		},
	}
	errs := validateDebugSessionSpec(session)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for valid day duration, got %d: %v", len(errs), errs)
	}
}

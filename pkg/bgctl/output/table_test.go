/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWriteSessionTable(t *testing.T) {
	now := time.Now()
	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "session-1",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Hour)),
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster: "cluster-a",
				User:    "user@example.com",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State:     v1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "session-2",
				CreationTimestamp: metav1.NewTime(now),
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster: "cluster-b",
				User:    "admin@example.com",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStatePending,
			},
		},
	}

	buf := &bytes.Buffer{}
	WriteSessionTable(buf, sessions)

	output := buf.String()
	// Check header
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "CLUSTER")
	assert.Contains(t, output, "USER")
	assert.Contains(t, output, "STATE")
	assert.Contains(t, output, "CREATED")
	assert.Contains(t, output, "EXPIRES")

	// Check data
	assert.Contains(t, output, "session-1")
	assert.Contains(t, output, "cluster-a")
	assert.Contains(t, output, "user@example.com")
	assert.Contains(t, output, "Approved")

	assert.Contains(t, output, "session-2")
	assert.Contains(t, output, "cluster-b")
	assert.Contains(t, output, "admin@example.com")
	assert.Contains(t, output, "Pending")
}

func TestWriteSessionTable_EmptyList(t *testing.T) {
	buf := &bytes.Buffer{}
	WriteSessionTable(buf, []v1alpha1.BreakglassSession{})

	output := buf.String()
	// Should still have header
	assert.Contains(t, output, "NAME")
	// Should not have any data rows beyond the header
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Len(t, lines, 1, "should only have header row for empty list")
}

func TestWriteSessionTableWide(t *testing.T) {
	now := time.Now()
	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "session-1",
				CreationTimestamp: metav1.NewTime(now),
			},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cluster-a",
				User:         "user@example.com",
				GrantedGroup: "admins",
			},
			Status: v1alpha1.BreakglassSessionStatus{
				State:     v1alpha1.SessionStateApproved,
				Approver:  "approver@example.com",
				ExpiresAt: metav1.NewTime(now.Add(1 * time.Hour)),
			},
		},
	}

	buf := &bytes.Buffer{}
	WriteSessionTableWide(buf, sessions)

	output := buf.String()
	// Wide format should include GROUP and APPROVER
	assert.Contains(t, output, "GROUP")
	assert.Contains(t, output, "APPROVER")
	assert.Contains(t, output, "admins")
	assert.Contains(t, output, "approver@example.com")
}

func TestWriteEscalationTable(t *testing.T) {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-1"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "cluster-admin",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"prod-1", "prod-2"},
					Groups:   []string{"developers"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"security-team"},
					Users:  []string{"lead@example.com"},
				},
			},
		},
	}

	buf := &bytes.Buffer{}
	WriteEscalationTable(buf, escalations)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "CLUSTERS")
	assert.Contains(t, output, "ALLOWED_GROUPS")
	assert.Contains(t, output, "ESCALATED_GROUP")
	assert.Contains(t, output, "APPROVERS")

	assert.Contains(t, output, "escalation-1")
	assert.Contains(t, output, "prod-1,prod-2")
	assert.Contains(t, output, "developers")
	assert.Contains(t, output, "cluster-admin")
	assert.Contains(t, output, "security-team")
}

func TestWriteDebugSessionTable(t *testing.T) {
	now := time.Now()
	startsAt := metav1.NewTime(now)
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	sessions := []client.DebugSessionSummary{
		{
			Name:         "debug-session-1",
			TemplateRef:  "debug-template",
			Cluster:      "dev-cluster",
			RequestedBy:  "developer@example.com",
			State:        v1alpha1.DebugSessionStateActive,
			StartsAt:     &startsAt,
			ExpiresAt:    &expiresAt,
			Participants: 2,
			AllowedPods:  5,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugSessionTable(buf, sessions)

	output := buf.String()
	// Compact table should have basic columns
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "CLUSTER")
	assert.Contains(t, output, "REQUESTED_BY")
	assert.Contains(t, output, "STATE")
	assert.Contains(t, output, "EXPIRES")

	assert.Contains(t, output, "debug-session-1")
	assert.Contains(t, output, "dev-cluster")
	assert.Contains(t, output, "developer@example.com")
	assert.Contains(t, output, "Active")
}

func TestWriteDebugSessionTableWide(t *testing.T) {
	now := time.Now()
	startsAt := metav1.NewTime(now)
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	sessions := []client.DebugSessionSummary{
		{
			Name:         "debug-session-1",
			TemplateRef:  "debug-template",
			Cluster:      "dev-cluster",
			RequestedBy:  "developer@example.com",
			State:        v1alpha1.DebugSessionStateActive,
			StartsAt:     &startsAt,
			ExpiresAt:    &expiresAt,
			Participants: 2,
			AllowedPods:  5,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugSessionTableWide(buf, sessions)

	output := buf.String()
	// Wide format should include TEMPLATE, STARTS, PARTICIPANTS, ALLOWED_PODS, OPERATIONS
	assert.Contains(t, output, "TEMPLATE")
	assert.Contains(t, output, "STARTS")
	assert.Contains(t, output, "PARTICIPANTS")
	assert.Contains(t, output, "ALLOWED_PODS")
	assert.Contains(t, output, "OPERATIONS")

	assert.Contains(t, output, "debug-template")
	assert.Contains(t, output, "2") // participants
	assert.Contains(t, output, "5") // allowed pods
	// Default operations when nil: exec,attach,portforward
	assert.Contains(t, output, "exec,attach,portforward")
}

func TestWriteDebugSessionTableWide_WithAllowedPodOperations(t *testing.T) {
	now := time.Now()
	startsAt := metav1.NewTime(now)
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	boolTrue := true
	boolFalse := false

	sessions := []client.DebugSessionSummary{
		{
			Name:         "debug-session-1",
			TemplateRef:  "debug-template",
			Cluster:      "dev-cluster",
			RequestedBy:  "developer@example.com",
			State:        v1alpha1.DebugSessionStateActive,
			StartsAt:     &startsAt,
			ExpiresAt:    &expiresAt,
			Participants: 2,
			AllowedPods:  5,
			AllowedPodOperations: &v1alpha1.AllowedPodOperations{
				Exec:        &boolTrue,
				Attach:      &boolFalse,
				Logs:        &boolTrue,
				PortForward: &boolTrue,
			},
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugSessionTableWide(buf, sessions)

	output := buf.String()
	// Should show exec,logs,portforward (not attach)
	assert.Contains(t, output, "exec")
	assert.Contains(t, output, "logs")
	assert.Contains(t, output, "portforward")
	assert.NotContains(t, output, "attach") // disabled
}

func TestFormatAllowedPodOperations(t *testing.T) {
	boolTrue := true
	boolFalse := false

	tests := []struct {
		name     string
		ops      *v1alpha1.AllowedPodOperations
		expected string
	}{
		{
			name:     "nil operations uses defaults",
			ops:      nil,
			expected: "exec,attach,portforward",
		},
		{
			name: "all enabled",
			ops: &v1alpha1.AllowedPodOperations{
				Exec:        &boolTrue,
				Attach:      &boolTrue,
				Logs:        &boolTrue,
				PortForward: &boolTrue,
			},
			expected: "exec,attach,logs,portforward",
		},
		{
			name: "all disabled",
			ops: &v1alpha1.AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolFalse,
				Logs:        &boolFalse,
				PortForward: &boolFalse,
			},
			expected: "none",
		},
		{
			name: "only exec enabled",
			ops: &v1alpha1.AllowedPodOperations{
				Exec:        &boolTrue,
				Attach:      &boolFalse,
				Logs:        &boolFalse,
				PortForward: &boolFalse,
			},
			expected: "exec",
		},
		{
			name: "only logs enabled",
			ops: &v1alpha1.AllowedPodOperations{
				Exec:        &boolFalse,
				Attach:      &boolFalse,
				Logs:        &boolTrue,
				PortForward: &boolFalse,
			},
			expected: "logs",
		},
		{
			name:     "empty struct uses defaults per field",
			ops:      &v1alpha1.AllowedPodOperations{},
			expected: "exec,attach,portforward",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAllowedPodOperations(tt.ops)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWriteDebugSessionTable_NilTimes(t *testing.T) {
	sessions := []client.DebugSessionSummary{
		{
			Name:        "debug-session-1",
			TemplateRef: "template",
			Cluster:     "cluster",
			RequestedBy: "user@example.com",
			State:       v1alpha1.DebugSessionStatePending,
			StartsAt:    nil,
			ExpiresAt:   nil,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugSessionTable(buf, sessions)

	output := buf.String()
	// Nil times should be displayed as "-"
	assert.Contains(t, output, "-")
}

func TestWriteDebugTemplateTable(t *testing.T) {
	templates := []client.DebugSessionTemplateSummary{
		{
			Name:                  "template-1",
			DisplayName:           "Debug Template One",
			Mode:                  "workload",
			TargetNamespace:       "debug-ns",
			RequiresApproval:      true,
			HasAvailableClusters:  true,
			AvailableClusterCount: 3,
		},
		{
			Name:                  "template-2",
			DisplayName:           "Debug Template Two",
			Mode:                  "kubectl-debug",
			TargetNamespace:       "",
			RequiresApproval:      false,
			HasAvailableClusters:  false,
			AvailableClusterCount: 0,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugTemplateTable(buf, templates)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "DISPLAY_NAME")
	assert.Contains(t, output, "MODE")
	assert.Contains(t, output, "CLUSTERS")
	assert.Contains(t, output, "TARGET_NAMESPACE")
	assert.Contains(t, output, "REQUIRES_APPROVAL")

	assert.Contains(t, output, "template-1")
	assert.Contains(t, output, "Debug Template One")
	assert.Contains(t, output, "workload")
	assert.Contains(t, output, "debug-ns")
	assert.Contains(t, output, "true")
	// Verify cluster count is shown
	assert.Contains(t, output, "3") // template-1 has 3 clusters
	assert.Contains(t, output, "0") // template-2 has 0 clusters
}

func TestWriteDebugTemplateTable_ClusterStatusVariants(t *testing.T) {
	// Test the three different cluster status display cases:
	// 1. HasAvailableClusters=true with AvailableClusterCount>0 -> shows count
	// 2. HasAvailableClusters=true with AvailableClusterCount=0 -> shows "✓" (has clusters but count unknown)
	// 3. HasAvailableClusters=false -> shows "0"
	templates := []client.DebugSessionTemplateSummary{
		{
			Name:                  "template-with-count",
			DisplayName:           "Template With Count",
			Mode:                  "workload",
			HasAvailableClusters:  true,
			AvailableClusterCount: 5,
		},
		{
			Name:                  "template-available-no-count",
			DisplayName:           "Template Available No Count",
			Mode:                  "workload",
			HasAvailableClusters:  true,
			AvailableClusterCount: 0, // Clusters available but count not provided
		},
		{
			Name:                  "template-unavailable",
			DisplayName:           "Template Unavailable",
			Mode:                  "workload",
			HasAvailableClusters:  false,
			AvailableClusterCount: 0,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugTemplateTable(buf, templates)

	output := buf.String()

	// template-with-count shows "5"
	assert.Contains(t, output, "5")

	// template-available-no-count shows "✓" (checkmark for available but unknown count)
	assert.Contains(t, output, "✓")

	// template-unavailable shows "0"
	// Already verified in the other test, but also checked here
}

func TestWriteDebugPodTemplateTable(t *testing.T) {
	templates := []client.DebugPodTemplateSummary{
		{
			Name:        "pod-template-1",
			DisplayName: "Pod Template One",
			Description: "A test pod template",
			Containers:  2,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugPodTemplateTable(buf, templates)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "DISPLAY_NAME")
	assert.Contains(t, output, "DESCRIPTION")
	assert.Contains(t, output, "CONTAINERS")

	assert.Contains(t, output, "pod-template-1")
	assert.Contains(t, output, "Pod Template One")
	assert.Contains(t, output, "A test pod template")
	assert.Contains(t, output, "2")
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Time
		expected string
	}{
		{
			name:     "zero time",
			input:    time.Time{},
			expected: "-",
		},
		{
			name:     "valid time",
			input:    time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
			expected: "2026-01-15T10:30:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.input)
			if tt.expected == "-" {
				require.Equal(t, "-", result)
			} else {
				require.Contains(t, result, "2026-01-15")
			}
		})
	}
}

func TestWriteTemplateClusterTable(t *testing.T) {
	tests := []struct {
		name           string
		clusters       []client.AvailableClusterDetail
		wantHeaders    []string
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:     "empty clusters",
			clusters: []client.AvailableClusterDetail{},
			wantHeaders: []string{
				"NAME", "DISPLAY_NAME", "ENVIRONMENT", "BINDINGS", "MAX_DURATION", "APPROVAL",
			},
		},
		{
			name: "cluster with binding options",
			clusters: []client.AvailableClusterDetail{
				{
					Name:        "prod-cluster",
					DisplayName: "Production Cluster",
					Environment: "production",
					BindingOptions: []client.BindingOption{
						{BindingRef: client.BindingReference{Name: "binding-1", Namespace: "ns-1"}},
						{BindingRef: client.BindingReference{Name: "binding-2", Namespace: "ns-2"}},
					},
					Constraints: &v1alpha1.DebugSessionConstraints{MaxDuration: "2h"},
					Approval:    &client.ApprovalInfo{Required: true},
				},
			},
			wantContains: []string{
				"prod-cluster", "Production Cluster", "production",
				"2", // 2 binding options
				"2h", "yes",
			},
		},
		{
			name: "cluster with single binding ref",
			clusters: []client.AvailableClusterDetail{
				{
					Name:        "dev-cluster",
					DisplayName: "Development Cluster",
					Environment: "development",
					BindingRef:  &client.BindingReference{Name: "default-binding", Namespace: "ns"},
					Approval:    &client.ApprovalInfo{Required: false},
				},
			},
			wantContains: []string{
				"dev-cluster", "Development Cluster", "development",
				"1", // 1 binding
				"no",
			},
		},
		{
			name: "cluster with no constraints",
			clusters: []client.AvailableClusterDetail{
				{
					Name: "test-cluster",
				},
			},
			wantContains: []string{
				"test-cluster", "-", // dashes for missing values
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			WriteTemplateClusterTable(buf, tt.clusters)
			output := buf.String()

			for _, header := range tt.wantHeaders {
				assert.Contains(t, output, header, "missing header: %s", header)
			}
			for _, want := range tt.wantContains {
				assert.Contains(t, output, want, "missing content: %s", want)
			}
			for _, notWant := range tt.wantNotContain {
				assert.NotContains(t, output, notWant, "should not contain: %s", notWant)
			}
		})
	}
}

func TestWriteTemplateClusterTableWide(t *testing.T) {
	tests := []struct {
		name         string
		clusters     []client.AvailableClusterDetail
		wantHeaders  []string
		wantContains []string
	}{
		{
			name:     "empty clusters wide",
			clusters: []client.AvailableClusterDetail{},
			wantHeaders: []string{
				"NAME", "DISPLAY_NAME", "ENVIRONMENT", "BINDINGS", "MAX_DURATION",
				"NS_DEFAULT", "SCHEDULING", "IMPERSONATION", "APPROVAL", "STATUS",
			},
		},
		{
			name: "cluster with full details",
			clusters: []client.AvailableClusterDetail{
				{
					Name:        "prod-cluster",
					DisplayName: "Production Cluster",
					Environment: "production",
					BindingOptions: []client.BindingOption{
						{BindingRef: client.BindingReference{Name: "binding-1", Namespace: "ns-1"}},
						{BindingRef: client.BindingReference{Name: "binding-2", Namespace: "ns-2"}},
						{BindingRef: client.BindingReference{Name: "binding-3", Namespace: "ns-3"}},
					},
					Constraints:          &v1alpha1.DebugSessionConstraints{MaxDuration: "2h"},
					NamespaceConstraints: &client.NamespaceConstraintsResponse{DefaultNamespace: "debug-ns"},
					SchedulingOptions: &client.SchedulingOptionsResponse{
						Required: true,
						Options: []client.SchedulingOptionResponse{
							{Name: "opt1"},
							{Name: "opt2"},
						},
					},
					Impersonation: &client.ImpersonationSummary{Enabled: true, ServiceAccount: "debug-sa"},
					Approval:      &client.ApprovalInfo{Required: true},
					Status:        &client.ClusterStatusInfo{Healthy: true},
				},
			},
			wantContains: []string{
				"prod-cluster", "Production Cluster", "production",
				"binding-1, +2 more", // multiple bindings formatted
				"2h", "debug-ns",
				"2 options (required)", // scheduling options with required flag
				"debug-sa", "yes", "healthy",
			},
		},
		{
			name: "cluster with exactly 2 bindings",
			clusters: []client.AvailableClusterDetail{
				{
					Name: "two-binding-cluster",
					BindingOptions: []client.BindingOption{
						{BindingRef: client.BindingReference{Name: "b1", Namespace: "ns"}},
						{BindingRef: client.BindingReference{Name: "b2", Namespace: "ns"}},
					},
				},
			},
			wantContains: []string{
				"b1, b2", // exactly 2 bindings shown together
			},
		},
		{
			name: "cluster with unhealthy status",
			clusters: []client.AvailableClusterDetail{
				{
					Name:   "unhealthy-cluster",
					Status: &client.ClusterStatusInfo{Healthy: false},
				},
			},
			wantContains: []string{
				"unhealthy-cluster", "unhealthy",
			},
		},
		{
			name: "cluster with single binding ref wide",
			clusters: []client.AvailableClusterDetail{
				{
					Name:       "single-binding-cluster",
					BindingRef: &client.BindingReference{Name: "my-binding", Namespace: "ns"},
				},
			},
			wantContains: []string{
				"my-binding",
			},
		},
		{
			name: "cluster with scheduling options not required",
			clusters: []client.AvailableClusterDetail{
				{
					Name: "sched-cluster",
					SchedulingOptions: &client.SchedulingOptionsResponse{
						Required: false,
						Options: []client.SchedulingOptionResponse{
							{Name: "opt1"},
						},
					},
				},
			},
			wantContains: []string{
				"1 options",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			WriteTemplateClusterTableWide(buf, tt.clusters)
			output := buf.String()

			for _, header := range tt.wantHeaders {
				assert.Contains(t, output, header, "missing header: %s", header)
			}
			for _, want := range tt.wantContains {
				assert.Contains(t, output, want, "missing content: %s", want)
			}
		})
	}
}

func TestWriteBindingOptionsTable(t *testing.T) {
	tests := []struct {
		name         string
		clusterName  string
		options      []client.BindingOption
		wantContains []string
	}{
		{
			name:        "empty options",
			clusterName: "test-cluster",
			options:     []client.BindingOption{},
			wantContains: []string{
				"No binding options available for cluster 'test-cluster'",
				"Using template defaults",
			},
		},
		{
			name:        "single binding option",
			clusterName: "prod-cluster",
			options: []client.BindingOption{
				{
					BindingRef:           client.BindingReference{Name: "admin-binding", Namespace: "breakglass"},
					DisplayName:          "Admin Access",
					Constraints:          &v1alpha1.DebugSessionConstraints{MaxDuration: "1h"},
					NamespaceConstraints: &client.NamespaceConstraintsResponse{DefaultNamespace: "admin-ns"},
					SchedulingOptions: &client.SchedulingOptionsResponse{
						Options: []client.SchedulingOptionResponse{{Name: "opt"}},
					},
					Impersonation: &client.ImpersonationSummary{Enabled: true, ServiceAccount: "admin-sa"},
					Approval:      &client.ApprovalInfo{Required: true},
				},
			},
			wantContains: []string{
				"Binding options for cluster 'prod-cluster'",
				"BINDING", "DISPLAY_NAME", "MAX_DURATION", "NAMESPACE", "SCHEDULING", "IMPERSONATION", "APPROVAL",
				"breakglass/admin-binding", "Admin Access", "1h", "admin-ns", "1 options", "admin-sa", "yes",
			},
		},
		{
			name:        "binding with auto-approve",
			clusterName: "dev-cluster",
			options: []client.BindingOption{
				{
					BindingRef: client.BindingReference{Name: "dev-binding", Namespace: "ns"},
					Approval:   &client.ApprovalInfo{Required: false, CanAutoApprove: true},
				},
			},
			wantContains: []string{
				"auto", // auto-approve shows as "auto"
			},
		},
		{
			name:        "binding with impersonation enabled no SA",
			clusterName: "special-cluster",
			options: []client.BindingOption{
				{
					BindingRef:    client.BindingReference{Name: "binding", Namespace: "ns"},
					Impersonation: &client.ImpersonationSummary{Enabled: true, ServiceAccount: ""},
				},
			},
			wantContains: []string{
				"yes", // impersonation enabled without specific SA
			},
		},
		{
			name:        "binding with minimal fields",
			clusterName: "minimal-cluster",
			options: []client.BindingOption{
				{
					BindingRef: client.BindingReference{Name: "basic", Namespace: "ns"},
				},
			},
			wantContains: []string{
				"ns/basic", "-", // dashes for missing values
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			WriteBindingOptionsTable(buf, tt.clusterName, tt.options)
			output := buf.String()

			for _, want := range tt.wantContains {
				assert.Contains(t, output, want, "missing content: %s", want)
			}
		})
	}
}

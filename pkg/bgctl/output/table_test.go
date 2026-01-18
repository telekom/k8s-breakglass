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
	// Wide format should include TEMPLATE, STARTS, PARTICIPANTS, ALLOWED_PODS
	assert.Contains(t, output, "TEMPLATE")
	assert.Contains(t, output, "STARTS")
	assert.Contains(t, output, "PARTICIPANTS")
	assert.Contains(t, output, "ALLOWED_PODS")

	assert.Contains(t, output, "debug-template")
	assert.Contains(t, output, "2") // participants
	assert.Contains(t, output, "5") // allowed pods
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
			Name:             "template-1",
			DisplayName:      "Debug Template One",
			Mode:             "workload",
			TargetNamespace:  "debug-ns",
			RequiresApproval: true,
		},
		{
			Name:             "template-2",
			DisplayName:      "Debug Template Two",
			Mode:             "kubectl-debug",
			TargetNamespace:  "",
			RequiresApproval: false,
		},
	}

	buf := &bytes.Buffer{}
	WriteDebugTemplateTable(buf, templates)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "DISPLAY_NAME")
	assert.Contains(t, output, "MODE")
	assert.Contains(t, output, "TARGET_NAMESPACE")
	assert.Contains(t, output, "REQUIRES_APPROVAL")

	assert.Contains(t, output, "template-1")
	assert.Contains(t, output, "Debug Template One")
	assert.Contains(t, output, "workload")
	assert.Contains(t, output, "debug-ns")
	assert.Contains(t, output, "true")
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

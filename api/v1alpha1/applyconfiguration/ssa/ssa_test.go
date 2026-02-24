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

// Package ssa provides comprehensive tests for Server-Side Apply (SSA) helpers.
// These tests follow patterns from cluster-api: https://github.com/kubernetes-sigs/cluster-api
package ssa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

// TestApplyBreakglassSessionStatus tests SSA status updates for BreakglassSession.
func TestApplyBreakglassSessionStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing session", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster: "test-cluster",
				User:    "test@example.com",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			Build()

		// Update status
		session.Status.State = breakglassv1alpha1.SessionStatePending
		session.Status.Approver = "admin@example.com"

		err := ApplyBreakglassSessionStatus(context.Background(), c, session)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.BreakglassSession
		err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, updated.Status.State)
		assert.Equal(t, "admin@example.com", updated.Status.Approver)
	})

	t.Run("returns error when session does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			Build()

		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nonexistent-session",
				Namespace: "default",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStatePending,
			},
		}

		err := ApplyBreakglassSessionStatus(context.Background(), c, session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})

	t.Run("updates conditions correctly", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster: "test-cluster",
				User:    "test@example.com",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			Build()

		// Update with conditions
		session.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Approved",
				Message:            "Session approved",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyBreakglassSessionStatus(context.Background(), c, session)
		require.NoError(t, err)

		// Verify conditions
		var updated breakglassv1alpha1.BreakglassSession
		err = c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated)
		require.NoError(t, err)
		require.Len(t, updated.Status.Conditions, 1)
		assert.Equal(t, "Ready", updated.Status.Conditions[0].Type)
		assert.Equal(t, metav1.ConditionTrue, updated.Status.Conditions[0].Status)
	})
}

// TestApplyBreakglassEscalationStatus tests SSA status updates for BreakglassEscalation.
func TestApplyBreakglassEscalationStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing escalation", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin-access",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
			Build()

		// Update status
		escalation.Status.ObservedGeneration = 5

		err := ApplyBreakglassEscalationStatus(context.Background(), c, escalation)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.BreakglassEscalation
		err = c.Get(context.Background(), client.ObjectKeyFromObject(escalation), &updated)
		require.NoError(t, err)
		assert.Equal(t, int64(5), updated.Status.ObservedGeneration)
	})

	t.Run("returns error when escalation does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
			Build()

		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nonexistent",
				Namespace: "default",
			},
			Status: breakglassv1alpha1.BreakglassEscalationStatus{
				ObservedGeneration: 1,
			},
		}

		err := ApplyBreakglassEscalationStatus(context.Background(), c, escalation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})

	t.Run("updates conditions correctly", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin-access",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassEscalation{}).
			Build()

		// Update with conditions
		escalation.Status.Conditions = []metav1.Condition{
			{
				Type:               "Valid",
				Status:             metav1.ConditionTrue,
				Reason:             "ConfigValid",
				Message:            "Escalation configuration is valid",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyBreakglassEscalationStatus(context.Background(), c, escalation)
		require.NoError(t, err)

		// Verify conditions
		var updated breakglassv1alpha1.BreakglassEscalation
		err = c.Get(context.Background(), client.ObjectKeyFromObject(escalation), &updated)
		require.NoError(t, err)
		require.Len(t, updated.Status.Conditions, 1)
		assert.Equal(t, "Valid", updated.Status.Conditions[0].Type)
	})
}

// TestApplyClusterConfigStatus tests SSA status updates for ClusterConfig.
func TestApplyClusterConfigStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing cluster config", func(t *testing.T) {
		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cc).
			WithStatusSubresource(&breakglassv1alpha1.ClusterConfig{}).
			Build()

		// Update status
		cc.Status.ObservedGeneration = 3
		cc.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Connected",
				Message:            "Cluster is reachable",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyClusterConfigStatus(context.Background(), c, cc)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.ClusterConfig
		err = c.Get(context.Background(), client.ObjectKeyFromObject(cc), &updated)
		require.NoError(t, err)
		assert.Equal(t, int64(3), updated.Status.ObservedGeneration)
		require.Len(t, updated.Status.Conditions, 1)
		assert.Equal(t, "Ready", updated.Status.Conditions[0].Type)
	})

	t.Run("returns error when cluster config does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.ClusterConfig{}).
			Build()

		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nonexistent",
				Namespace: "default",
			},
		}

		err := ApplyClusterConfigStatus(context.Background(), c, cc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})
}

// TestApplyMailProviderStatus tests SSA status updates for MailProvider.
func TestApplyMailProviderStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing mail provider", func(t *testing.T) {
		mp := &breakglassv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-provider",
			},
			Spec: breakglassv1alpha1.MailProviderSpec{
				SMTP: breakglassv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(mp).
			WithStatusSubresource(&breakglassv1alpha1.MailProvider{}).
			Build()

		// Update status
		mp.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Configured",
				Message:            "Mail provider is ready",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyMailProviderStatus(context.Background(), c, mp)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.MailProvider
		err = c.Get(context.Background(), client.ObjectKeyFromObject(mp), &updated)
		require.NoError(t, err)
		require.Len(t, updated.Status.Conditions, 1)
		assert.Equal(t, "Ready", updated.Status.Conditions[0].Type)
	})

	t.Run("returns error when mail provider does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.MailProvider{}).
			Build()

		mp := &breakglassv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: "nonexistent",
			},
		}

		err := ApplyMailProviderStatus(context.Background(), c, mp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})
}

// TestApplyIdentityProviderStatus tests SSA status updates for IdentityProvider.
func TestApplyIdentityProviderStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing identity provider", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-idp",
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				Issuer: "https://idp.example.com",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(idp).
			WithStatusSubresource(&breakglassv1alpha1.IdentityProvider{}).
			Build()

		// Update status
		idp.Status.ObservedGeneration = 2
		idp.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Valid",
				Message:            "Identity provider is configured",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyIdentityProviderStatus(context.Background(), c, idp)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.IdentityProvider
		err = c.Get(context.Background(), client.ObjectKeyFromObject(idp), &updated)
		require.NoError(t, err)
		assert.Equal(t, int64(2), updated.Status.ObservedGeneration)
		require.Len(t, updated.Status.Conditions, 1)
	})

	t.Run("returns error when identity provider does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.IdentityProvider{}).
			Build()

		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: "nonexistent",
			},
		}

		err := ApplyIdentityProviderStatus(context.Background(), c, idp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})
}

// TestApplyDebugSessionStatus tests SSA status updates for DebugSession.
func TestApplyDebugSessionStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing debug session", func(t *testing.T) {
		ds := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-debug",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster:     "test-cluster",
				TemplateRef: "test-template",
				RequestedBy: "test@example.com",
			},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(ds).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()

		// Update status
		ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
		ds.Status.Message = "Session is running"

		err := ApplyDebugSessionStatus(context.Background(), c, ds)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.DebugSession
		err = c.Get(context.Background(), client.ObjectKeyFromObject(ds), &updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.DebugSessionStateActive, updated.Status.State)
		assert.Equal(t, "Session is running", updated.Status.Message)
	})

	t.Run("returns error when debug session does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()

		ds := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nonexistent",
				Namespace: "default",
			},
		}

		err := ApplyDebugSessionStatus(context.Background(), c, ds)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})
}

// TestApplyAuditConfigStatus tests SSA status updates for AuditConfig.
func TestApplyAuditConfigStatus(t *testing.T) {
	scheme := newTestScheme()

	t.Run("successfully updates status on existing audit config", func(t *testing.T) {
		ac := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-audit",
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{},
		}

		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(ac).
			WithStatusSubresource(&breakglassv1alpha1.AuditConfig{}).
			Build()

		// Update status
		ac.Status.EventsProcessed = 100
		ac.Status.ActiveSinks = []string{"webhook-sink"}
		ac.Status.Conditions = []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Configured",
				Message:            "Audit config is ready",
				LastTransitionTime: metav1.Now(),
			},
		}

		err := ApplyAuditConfigStatus(context.Background(), c, ac)
		require.NoError(t, err)

		// Verify the status was updated
		var updated breakglassv1alpha1.AuditConfig
		err = c.Get(context.Background(), client.ObjectKeyFromObject(ac), &updated)
		require.NoError(t, err)
		assert.Equal(t, int64(100), updated.Status.EventsProcessed)
		assert.Equal(t, []string{"webhook-sink"}, updated.Status.ActiveSinks)
		require.Len(t, updated.Status.Conditions, 1)
	})

	t.Run("returns error when audit config does not exist", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&breakglassv1alpha1.AuditConfig{}).
			Build()

		ac := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "nonexistent",
			},
		}

		err := ApplyAuditConfigStatus(context.Background(), c, ac)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get object for status update")
	})
}

// TestConditionFrom verifies correct conversion of metav1.Condition.
func TestConditionFrom(t *testing.T) {
	now := metav1.Now()
	condition := &metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: 5,
		LastTransitionTime: now,
		Reason:             "TestReason",
		Message:            "Test message",
	}

	result := ConditionFrom(condition)

	assert.NotNil(t, result)
	assert.Equal(t, "Ready", *result.Type)
	assert.Equal(t, metav1.ConditionTrue, *result.Status)
	assert.Equal(t, int64(5), *result.ObservedGeneration)
	assert.Equal(t, "TestReason", *result.Reason)
	assert.Equal(t, "Test message", *result.Message)
}

// TestConditionFromNil verifies nil handling.
func TestConditionFromNil(t *testing.T) {
	result := ConditionFrom(nil)
	assert.Nil(t, result)
}

// TestDebugSessionApprovalFrom tests conversion of DebugSessionApproval.
func TestDebugSessionApprovalFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionApprovalFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full approval", func(t *testing.T) {
		now := metav1.Now()
		approval := &breakglassv1alpha1.DebugSessionApproval{
			Required:   true,
			ApprovedBy: "admin@example.com",
			ApprovedAt: &now,
			Reason:     "Test reason",
		}

		result := DebugSessionApprovalFrom(approval)

		require.NotNil(t, result)
		assert.True(t, *result.Required)
		assert.Equal(t, "admin@example.com", *result.ApprovedBy)
		assert.NotNil(t, result.ApprovedAt)
		assert.Equal(t, "Test reason", *result.Reason)
	})

	t.Run("converts rejection", func(t *testing.T) {
		now := metav1.Now()
		approval := &breakglassv1alpha1.DebugSessionApproval{
			Required:   true,
			RejectedBy: "rejector@example.com",
			RejectedAt: &now,
			Reason:     "Rejected reason",
		}

		result := DebugSessionApprovalFrom(approval)

		require.NotNil(t, result)
		assert.Equal(t, "rejector@example.com", *result.RejectedBy)
		assert.NotNil(t, result.RejectedAt)
		assert.Equal(t, "Rejected reason", *result.Reason)
	})
}

// TestDebugSessionParticipantFrom tests conversion of DebugSessionParticipant.
func TestDebugSessionParticipantFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionParticipantFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full participant", func(t *testing.T) {
		now := metav1.Now()
		left := metav1.Now()
		participant := &breakglassv1alpha1.DebugSessionParticipant{
			User:        "user@example.com",
			Role:        breakglassv1alpha1.ParticipantRoleOwner,
			JoinedAt:    now,
			Email:       "user@example.com",
			DisplayName: "Test User",
			LeftAt:      &left,
		}

		result := DebugSessionParticipantFrom(participant)

		require.NotNil(t, result)
		assert.Equal(t, "user@example.com", *result.User)
		assert.Equal(t, breakglassv1alpha1.ParticipantRoleOwner, *result.Role)
		assert.Equal(t, "user@example.com", *result.Email)
		assert.Equal(t, "Test User", *result.DisplayName)
		assert.NotNil(t, result.LeftAt)
	})
}

// TestTerminalSharingStatusFrom tests conversion of TerminalSharingStatus.
func TestTerminalSharingStatusFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := TerminalSharingStatusFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full status", func(t *testing.T) {
		status := &breakglassv1alpha1.TerminalSharingStatus{
			Enabled:       true,
			SessionName:   "test-session",
			AttachCommand: "tmux attach -t test-session",
		}

		result := TerminalSharingStatusFrom(status)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.Equal(t, "test-session", *result.SessionName)
		assert.Equal(t, "tmux attach -t test-session", *result.AttachCommand)
	})
}

// TestDeployedResourceRefFrom tests conversion of DeployedResourceRef.
func TestDeployedResourceRefFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DeployedResourceRefFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full resource ref", func(t *testing.T) {
		ref := &breakglassv1alpha1.DeployedResourceRef{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "debug-pod",
			Namespace:  "debug-ns",
		}

		result := DeployedResourceRefFrom(ref)

		require.NotNil(t, result)
		assert.Equal(t, "apps/v1", *result.APIVersion)
		assert.Equal(t, "Deployment", *result.Kind)
		assert.Equal(t, "debug-pod", *result.Name)
		assert.Equal(t, "debug-ns", *result.Namespace)
	})
}

// TestAllowedPodRefFrom tests conversion of AllowedPodRef.
func TestAllowedPodRefFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := AllowedPodRefFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full pod ref", func(t *testing.T) {
		ref := &breakglassv1alpha1.AllowedPodRef{
			Namespace: "debug-ns",
			Name:      "debug-pod",
			Ready:     true,
			NodeName:  "node-1",
			Phase:     "Running",
			ContainerStatus: &breakglassv1alpha1.PodContainerStatus{
				WaitingReason: "ContainerCreating",
			},
		}

		result := AllowedPodRefFrom(ref)

		require.NotNil(t, result)
		assert.Equal(t, "debug-ns", *result.Namespace)
		assert.Equal(t, "debug-pod", *result.Name)
		assert.True(t, *result.Ready)
		assert.Equal(t, "node-1", *result.NodeName)
		assert.Equal(t, "Running", *result.Phase)
		assert.NotNil(t, result.ContainerStatus)
	})
}

// TestPodContainerStatusFrom tests conversion of PodContainerStatus.
func TestPodContainerStatusFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := PodContainerStatusFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full status", func(t *testing.T) {
		status := &breakglassv1alpha1.PodContainerStatus{
			WaitingReason:         "ContainerCreating",
			WaitingMessage:        "Pulling image",
			RestartCount:          3,
			LastTerminationReason: "Error",
		}

		result := PodContainerStatusFrom(status)

		require.NotNil(t, result)
		assert.Equal(t, "ContainerCreating", *result.WaitingReason)
		assert.Equal(t, "Pulling image", *result.WaitingMessage)
		assert.Equal(t, int32(3), *result.RestartCount)
		assert.Equal(t, "Error", *result.LastTerminationReason)
	})
}

// TestKubectlDebugStatusFrom tests conversion of KubectlDebugStatus.
func TestKubectlDebugStatusFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := KubectlDebugStatusFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full status", func(t *testing.T) {
		now := metav1.Now()
		status := &breakglassv1alpha1.KubectlDebugStatus{
			EphemeralContainersInjected: []breakglassv1alpha1.EphemeralContainerRef{
				{
					PodName:       "target-pod",
					Namespace:     "app-ns",
					ContainerName: "debugger",
					Image:         "busybox:latest",
					InjectedAt:    now,
					InjectedBy:    "admin@example.com",
				},
			},
			CopiedPods: []breakglassv1alpha1.CopiedPodRef{
				{
					OriginalPod:       "original-pod",
					OriginalNamespace: "app-ns",
					CopyName:          "debug-copy",
					CopyNamespace:     "debug-ns",
					CreatedAt:         now,
				},
			},
		}

		result := KubectlDebugStatusFrom(status)

		require.NotNil(t, result)
		require.Len(t, result.EphemeralContainersInjected, 1)
		require.Len(t, result.CopiedPods, 1)
	})
}

// TestEphemeralContainerRefFrom tests conversion of EphemeralContainerRef.
func TestEphemeralContainerRefFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := EphemeralContainerRefFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full ref", func(t *testing.T) {
		now := metav1.Now()
		ref := &breakglassv1alpha1.EphemeralContainerRef{
			PodName:       "target-pod",
			Namespace:     "app-ns",
			ContainerName: "debugger",
			Image:         "busybox:latest",
			InjectedAt:    now,
			InjectedBy:    "admin@example.com",
		}

		result := EphemeralContainerRefFrom(ref)

		require.NotNil(t, result)
		assert.Equal(t, "target-pod", *result.PodName)
		assert.Equal(t, "app-ns", *result.Namespace)
		assert.Equal(t, "debugger", *result.ContainerName)
		assert.Equal(t, "busybox:latest", *result.Image)
		assert.Equal(t, "admin@example.com", *result.InjectedBy)
	})
}

// TestCopiedPodRefFrom tests conversion of CopiedPodRef.
func TestCopiedPodRefFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := CopiedPodRefFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full ref", func(t *testing.T) {
		now := metav1.Now()
		expires := metav1.Now()
		ref := &breakglassv1alpha1.CopiedPodRef{
			OriginalPod:       "original-pod",
			OriginalNamespace: "app-ns",
			CopyName:          "debug-copy",
			CopyNamespace:     "debug-ns",
			CreatedAt:         now,
			ExpiresAt:         &expires,
		}

		result := CopiedPodRefFrom(ref)

		require.NotNil(t, result)
		assert.Equal(t, "original-pod", *result.OriginalPod)
		assert.Equal(t, "app-ns", *result.OriginalNamespace)
		assert.Equal(t, "debug-copy", *result.CopyName)
		assert.Equal(t, "debug-ns", *result.CopyNamespace)
		assert.NotNil(t, result.ExpiresAt)
	})
}

// TestDebugSessionTemplateSpecFrom tests conversion of DebugSessionTemplateSpec.
func TestDebugSessionTemplateSpecFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionTemplateSpecFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts basic template spec", func(t *testing.T) {
		replicas := int32(3)
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Test Template",
			Description:     "A test debug session template",
			Mode:            breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType:    breakglassv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "debug-ns",
			FailMode:        "closed",
		}

		result := DebugSessionTemplateSpecFrom(spec)

		require.NotNil(t, result)
		assert.Equal(t, "Test Template", *result.DisplayName)
		assert.Equal(t, "A test debug session template", *result.Description)
		assert.Equal(t, breakglassv1alpha1.DebugSessionModeWorkload, *result.Mode)
		assert.Equal(t, breakglassv1alpha1.DebugWorkloadDeployment, *result.WorkloadType)
		assert.Equal(t, int32(3), *result.Replicas)
		assert.Equal(t, "debug-ns", *result.TargetNamespace)
		assert.Equal(t, "closed", *result.FailMode)
	})

	t.Run("converts template with pod template ref", func(t *testing.T) {
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
				Name: "debug-pod-template",
			},
		}

		result := DebugSessionTemplateSpecFrom(spec)

		require.NotNil(t, result)
		require.NotNil(t, result.PodTemplateRef)
		assert.Equal(t, "debug-pod-template", *result.PodTemplateRef.Name)
	})

	t.Run("converts template with allowed config", func(t *testing.T) {
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Groups:   []string{"sre-team", "admins"},
				Users:    []string{"user@example.com"},
				Clusters: []string{"prod-*", "staging"},
			},
		}

		result := DebugSessionTemplateSpecFrom(spec)

		require.NotNil(t, result)
		require.NotNil(t, result.Allowed)
		assert.Equal(t, []string{"sre-team", "admins"}, result.Allowed.Groups)
		assert.Equal(t, []string{"user@example.com"}, result.Allowed.Users)
		assert.Equal(t, []string{"prod-*", "staging"}, result.Allowed.Clusters)
	})

	t.Run("converts template with constraints", func(t *testing.T) {
		allowRenewal := true
		maxRenewals := int32(5)
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:           "4h",
				DefaultDuration:       "1h",
				AllowRenewal:          &allowRenewal,
				MaxRenewals:           &maxRenewals,
				MaxConcurrentSessions: 3,
			},
		}

		result := DebugSessionTemplateSpecFrom(spec)

		require.NotNil(t, result)
		require.NotNil(t, result.Constraints)
		assert.Equal(t, "4h", *result.Constraints.MaxDuration)
		assert.Equal(t, "1h", *result.Constraints.DefaultDuration)
		assert.True(t, *result.Constraints.AllowRenewal)
		assert.Equal(t, int32(5), *result.Constraints.MaxRenewals)
		assert.Equal(t, int32(3), *result.Constraints.MaxConcurrentSessions)
	})

	t.Run("converts template with terminal sharing", func(t *testing.T) {
		spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
			TerminalSharing: &breakglassv1alpha1.TerminalSharingConfig{
				Enabled:         true,
				Provider:        "tmux",
				MaxParticipants: 5,
			},
		}

		result := DebugSessionTemplateSpecFrom(spec)

		require.NotNil(t, result)
		require.NotNil(t, result.TerminalSharing)
		assert.True(t, *result.TerminalSharing.Enabled)
		assert.Equal(t, "tmux", *result.TerminalSharing.Provider)
		assert.Equal(t, int32(5), *result.TerminalSharing.MaxParticipants)
	})
}

// TestDebugPodTemplateReferenceFrom tests conversion of DebugPodTemplateReference.
func TestDebugPodTemplateReferenceFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugPodTemplateReferenceFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts reference", func(t *testing.T) {
		ref := &breakglassv1alpha1.DebugPodTemplateReference{
			Name: "template-name",
		}

		result := DebugPodTemplateReferenceFrom(ref)

		require.NotNil(t, result)
		assert.Equal(t, "template-name", *result.Name)
	})
}

// TestDebugSessionAllowedFrom tests conversion of DebugSessionAllowed.
func TestDebugSessionAllowedFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionAllowedFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full allowed config", func(t *testing.T) {
		allowed := &breakglassv1alpha1.DebugSessionAllowed{
			Groups:   []string{"group1", "group2"},
			Users:    []string{"user1@example.com"},
			Clusters: []string{"cluster-*"},
		}

		result := DebugSessionAllowedFrom(allowed)

		require.NotNil(t, result)
		assert.Equal(t, []string{"group1", "group2"}, result.Groups)
		assert.Equal(t, []string{"user1@example.com"}, result.Users)
		assert.Equal(t, []string{"cluster-*"}, result.Clusters)
	})
}

// TestDebugSessionApproversFrom tests conversion of DebugSessionApprovers.
func TestDebugSessionApproversFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionApproversFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full approvers config", func(t *testing.T) {
		approvers := &breakglassv1alpha1.DebugSessionApprovers{
			Groups: []string{"approvers-group"},
			Users:  []string{"approver@example.com"},
			AutoApproveFor: &breakglassv1alpha1.AutoApproveConfig{
				Groups:   []string{"auto-approve-group"},
				Clusters: []string{"dev-*"},
			},
		}

		result := DebugSessionApproversFrom(approvers)

		require.NotNil(t, result)
		assert.Equal(t, []string{"approvers-group"}, result.Groups)
		assert.Equal(t, []string{"approver@example.com"}, result.Users)
		require.NotNil(t, result.AutoApproveFor)
		assert.Equal(t, []string{"auto-approve-group"}, result.AutoApproveFor.Groups)
	})
}

// TestAutoApproveConfigFrom tests conversion of AutoApproveConfig.
func TestAutoApproveConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := AutoApproveConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.AutoApproveConfig{
			Groups:   []string{"trusted-group"},
			Clusters: []string{"dev-*", "test-*"},
		}

		result := AutoApproveConfigFrom(config)

		require.NotNil(t, result)
		assert.Equal(t, []string{"trusted-group"}, result.Groups)
		assert.Equal(t, []string{"dev-*", "test-*"}, result.Clusters)
	})
}

// TestDebugSessionConstraintsFrom tests conversion of DebugSessionConstraints.
func TestDebugSessionConstraintsFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionConstraintsFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full constraints", func(t *testing.T) {
		allowRenewal := true
		maxRenewals := int32(3)
		constraints := &breakglassv1alpha1.DebugSessionConstraints{
			MaxDuration:           "8h",
			DefaultDuration:       "2h",
			AllowRenewal:          &allowRenewal,
			MaxRenewals:           &maxRenewals,
			MaxConcurrentSessions: 5,
		}

		result := DebugSessionConstraintsFrom(constraints)

		require.NotNil(t, result)
		assert.Equal(t, "8h", *result.MaxDuration)
		assert.Equal(t, "2h", *result.DefaultDuration)
		assert.True(t, *result.AllowRenewal)
		assert.Equal(t, int32(3), *result.MaxRenewals)
		assert.Equal(t, int32(5), *result.MaxConcurrentSessions)
	})
}

// TestTerminalSharingConfigFrom tests conversion of TerminalSharingConfig.
func TestTerminalSharingConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := TerminalSharingConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.TerminalSharingConfig{
			Enabled:         true,
			Provider:        "screen",
			MaxParticipants: 10,
		}

		result := TerminalSharingConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.Equal(t, "screen", *result.Provider)
		assert.Equal(t, int32(10), *result.MaxParticipants)
	})
}

// TestDebugSessionAuditConfigFrom tests conversion of DebugSessionAuditConfig.
func TestDebugSessionAuditConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugSessionAuditConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.DebugSessionAuditConfig{
			Enabled:                 true,
			EnableTerminalRecording: true,
			EnableShellHistory:      true,
			RecordingRetention:      "30d",
			Destinations: []breakglassv1alpha1.AuditDestination{
				{
					Type: "webhook",
					URL:  "https://audit.example.com/events",
					Headers: map[string]string{
						"Authorization": "Bearer token",
					},
				},
			},
		}

		result := DebugSessionAuditConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.True(t, *result.EnableTerminalRecording)
		assert.True(t, *result.EnableShellHistory)
		assert.Equal(t, "30d", *result.RecordingRetention)
		require.Len(t, result.Destinations, 1)
	})
}

// TestAuditDestinationFrom tests conversion of AuditDestination.
func TestAuditDestinationFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := AuditDestinationFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full destination", func(t *testing.T) {
		dest := &breakglassv1alpha1.AuditDestination{
			Type: "webhook",
			URL:  "https://audit.example.com",
			Headers: map[string]string{
				"X-API-Key": "secret",
			},
		}

		result := AuditDestinationFrom(dest)

		require.NotNil(t, result)
		assert.Equal(t, "webhook", *result.Type)
		assert.Equal(t, "https://audit.example.com", *result.URL)
		assert.Equal(t, map[string]string{"X-API-Key": "secret"}, result.Headers)
	})
}

// TestNamespaceFilterFrom tests conversion of NamespaceFilter.
func TestNamespaceFilterFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := NamespaceFilterFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts patterns", func(t *testing.T) {
		filter := &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"app-*", "kube-*"},
		}

		result := NamespaceFilterFrom(filter)

		require.NotNil(t, result)
		assert.Equal(t, []string{"app-*", "kube-*"}, result.Patterns)
	})

	t.Run("converts selector terms", func(t *testing.T) {
		filter := &breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{
					MatchLabels: map[string]string{"env": "production"},
				},
			},
		}

		result := NamespaceFilterFrom(filter)

		require.NotNil(t, result)
		require.Len(t, result.SelectorTerms, 1)
		assert.Equal(t, map[string]string{"env": "production"}, result.SelectorTerms[0].MatchLabels)
	})
}

// TestNamespaceSelectorTermFrom tests conversion of NamespaceSelectorTerm.
func TestNamespaceSelectorTermFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := NamespaceSelectorTermFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts match labels", func(t *testing.T) {
		term := &breakglassv1alpha1.NamespaceSelectorTerm{
			MatchLabels: map[string]string{"key": "value"},
		}

		result := NamespaceSelectorTermFrom(term)

		require.NotNil(t, result)
		assert.Equal(t, map[string]string{"key": "value"}, result.MatchLabels)
	})

	t.Run("converts match expressions", func(t *testing.T) {
		term := &breakglassv1alpha1.NamespaceSelectorTerm{
			MatchExpressions: []breakglassv1alpha1.NamespaceSelectorRequirement{
				{
					Key:      "team",
					Operator: breakglassv1alpha1.NamespaceSelectorOpIn,
					Values:   []string{"sre", "platform"},
				},
			},
		}

		result := NamespaceSelectorTermFrom(term)

		require.NotNil(t, result)
		require.Len(t, result.MatchExpressions, 1)
		assert.Equal(t, "team", *result.MatchExpressions[0].Key)
	})
}

// TestNamespaceSelectorRequirementFrom tests conversion of NamespaceSelectorRequirement.
func TestNamespaceSelectorRequirementFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := NamespaceSelectorRequirementFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full requirement", func(t *testing.T) {
		req := &breakglassv1alpha1.NamespaceSelectorRequirement{
			Key:      "environment",
			Operator: breakglassv1alpha1.NamespaceSelectorOpIn,
			Values:   []string{"prod", "staging"},
		}

		result := NamespaceSelectorRequirementFrom(req)

		require.NotNil(t, result)
		assert.Equal(t, "environment", *result.Key)
		assert.Equal(t, breakglassv1alpha1.NamespaceSelectorOpIn, *result.Operator)
		assert.Equal(t, []string{"prod", "staging"}, result.Values)
	})
}

// TestKubectlDebugConfigFrom tests conversion of KubectlDebugConfig.
func TestKubectlDebugConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := KubectlDebugConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.KubectlDebugConfig{
			EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
				Enabled: true,
			},
			NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
				Enabled: true,
			},
			PodCopy: &breakglassv1alpha1.PodCopyConfig{
				Enabled: true,
			},
		}

		result := KubectlDebugConfigFrom(config)

		require.NotNil(t, result)
		require.NotNil(t, result.EphemeralContainers)
		require.NotNil(t, result.NodeDebug)
		require.NotNil(t, result.PodCopy)
	})
}

// TestEphemeralContainersConfigFrom tests conversion of EphemeralContainersConfig.
func TestEphemeralContainersConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := EphemeralContainersConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.EphemeralContainersConfig{
			Enabled:            true,
			RequireImageDigest: true,
			AllowPrivileged:    false,
			RequireNonRoot:     true,
			AllowedImages:      []string{"busybox:*", "alpine:*"},
			MaxCapabilities:    []string{"NET_ADMIN"},
			AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
		}

		result := EphemeralContainersConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.True(t, *result.RequireImageDigest)
		assert.False(t, *result.AllowPrivileged)
		assert.True(t, *result.RequireNonRoot)
		assert.Equal(t, []string{"busybox:*", "alpine:*"}, result.AllowedImages)
		assert.Equal(t, []string{"NET_ADMIN"}, result.MaxCapabilities)
		require.NotNil(t, result.AllowedNamespaces)
	})
}

// TestNodeDebugConfigFrom tests conversion of NodeDebugConfig.
func TestNodeDebugConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := NodeDebugConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.NodeDebugConfig{
			Enabled:       true,
			AllowedImages: []string{"debug-image:latest"},
			HostNamespaces: &breakglassv1alpha1.HostNamespacesConfig{
				HostNetwork: true,
				HostPID:     true,
				HostIPC:     false,
			},
			NodeSelector: map[string]string{"node-type": "debug"},
		}

		result := NodeDebugConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.Equal(t, []string{"debug-image:latest"}, result.AllowedImages)
		require.NotNil(t, result.HostNamespaces)
	})
}

// TestHostNamespacesConfigFrom tests conversion of HostNamespacesConfig.
func TestHostNamespacesConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := HostNamespacesConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.HostNamespacesConfig{
			HostNetwork: true,
			HostPID:     true,
			HostIPC:     false,
		}

		result := HostNamespacesConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.HostNetwork)
		assert.True(t, *result.HostPID)
		assert.False(t, *result.HostIPC)
	})
}

// TestPodCopyConfigFrom tests conversion of PodCopyConfig.
func TestPodCopyConfigFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := PodCopyConfigFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full config", func(t *testing.T) {
		config := &breakglassv1alpha1.PodCopyConfig{
			Enabled:         true,
			TargetNamespace: "debug-copies",
			Labels:          map[string]string{"debug": "true"},
			TTL:             "4h",
		}

		result := PodCopyConfigFrom(config)

		require.NotNil(t, result)
		assert.True(t, *result.Enabled)
		assert.Equal(t, "debug-copies", *result.TargetNamespace)
		assert.Equal(t, "4h", *result.TTL)
	})
}

// TestAuditSinkStatusFrom tests conversion of AuditSinkStatus.
func TestAuditSinkStatusFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := AuditSinkStatusFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full status", func(t *testing.T) {
		now := metav1.Now()
		status := &breakglassv1alpha1.AuditSinkStatus{
			Name:            "webhook-sink",
			Ready:           true,
			LastError:       "connection timeout",
			LastSuccessTime: &now,
			EventsWritten:   100,
		}

		result := AuditSinkStatusFrom(status)

		require.NotNil(t, result)
		assert.Equal(t, "webhook-sink", *result.Name)
		assert.True(t, *result.Ready)
		assert.Equal(t, "connection timeout", *result.LastError)
		assert.NotNil(t, result.LastSuccessTime)
		assert.Equal(t, int64(100), *result.EventsWritten)
	})
}

// TestDebugPodOverridesFrom tests conversion of DebugPodOverrides.
func TestDebugPodOverridesFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugPodOverridesFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full overrides", func(t *testing.T) {
		hostNetwork := true
		overrides := &breakglassv1alpha1.DebugPodOverrides{
			Spec: &breakglassv1alpha1.DebugPodSpecOverrides{
				HostNetwork: &hostNetwork,
			},
		}

		result := DebugPodOverridesFrom(overrides)

		require.NotNil(t, result)
		require.NotNil(t, result.Spec)
		assert.True(t, *result.Spec.HostNetwork)
	})
}

// TestDebugPodSpecOverridesFrom tests conversion of DebugPodSpecOverrides.
func TestDebugPodSpecOverridesFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugPodSpecOverridesFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full overrides", func(t *testing.T) {
		hostNetwork := true
		hostPID := false
		hostIPC := true
		overrides := &breakglassv1alpha1.DebugPodSpecOverrides{
			HostNetwork: &hostNetwork,
			HostPID:     &hostPID,
			HostIPC:     &hostIPC,
			Containers: []breakglassv1alpha1.DebugContainerOverride{
				{Name: "debug-container"},
			},
		}

		result := DebugPodSpecOverridesFrom(overrides)

		require.NotNil(t, result)
		assert.True(t, *result.HostNetwork)
		assert.False(t, *result.HostPID)
		assert.True(t, *result.HostIPC)
		require.Len(t, result.Containers, 1)
	})
}

// TestDebugContainerOverrideFrom tests conversion of DebugContainerOverride.
func TestDebugContainerOverrideFrom(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := DebugContainerOverrideFrom(nil)
		assert.Nil(t, result)
	})

	t.Run("converts full override", func(t *testing.T) {
		override := &breakglassv1alpha1.DebugContainerOverride{
			Name: "debug-container",
			SecurityContext: &corev1.SecurityContext{
				Privileged: func() *bool { b := true; return &b }(),
			},
			Resources: &corev1.ResourceRequirements{},
			Env: []corev1.EnvVar{
				{Name: "DEBUG", Value: "true"},
			},
		}

		result := DebugContainerOverrideFrom(override)

		require.NotNil(t, result)
		assert.Equal(t, "debug-container", *result.Name)
		require.NotNil(t, result.SecurityContext)
		assert.Len(t, result.Env, 1)
	})
}

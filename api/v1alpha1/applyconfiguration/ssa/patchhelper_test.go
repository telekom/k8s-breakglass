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

package ssa

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newPatchTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

// ---------------------------------------------------------------------------
// PatchApplyBreakglassSessionStatus
// ---------------------------------------------------------------------------

func TestPatchApplyBreakglassSessionStatus_Created(t *testing.T) {
	scheme := newPatchTestScheme()
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "user@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		Build()

	session.Status.State = breakglassv1alpha1.SessionStatePending

	result, err := PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)

	// Verify
	var updated breakglassv1alpha1.BreakglassSession
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated))
	assert.Equal(t, breakglassv1alpha1.SessionStatePending, updated.Status.State)
}

func TestPatchApplyBreakglassSessionStatus_Skipped(t *testing.T) {
	scheme := newPatchTestScheme()
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "user@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:    breakglassv1alpha1.SessionStatePending,
			Approver: "admin@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		Build()

	// Apply the same status — should skip because the object was created
	// with WithObjects which preserves status via WithStatusSubresource.
	result, err := PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultSkipped, result)

	// Apply again with same status — still skipped.
	result, err = PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultSkipped, result)
}

func TestPatchApplyBreakglassSessionStatus_ErrorNotFound(t *testing.T) {
	scheme := newPatchTestScheme()
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		Build()

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nonexistent",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	_, err := PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get object for status update")
}

func TestPatchApplyBreakglassSessionStatus_Changed(t *testing.T) {
	scheme := newPatchTestScheme()
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "user@example.com",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		Build()

	// First apply — patches.
	session.Status.State = breakglassv1alpha1.SessionStatePending
	result, err := PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)

	// Change status — should patch again.
	session.Status.State = breakglassv1alpha1.SessionStateApproved
	result, err = PatchApplyBreakglassSessionStatus(context.Background(), c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)

	// Verify final state.
	var updated breakglassv1alpha1.BreakglassSession
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(session), &updated))
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
}

// ---------------------------------------------------------------------------
// PatchApplyClusterConfigStatus
// ---------------------------------------------------------------------------

func TestPatchApplyClusterConfigStatus_Patched(t *testing.T) {
	scheme := newPatchTestScheme()
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cc",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		WithStatusSubresource(&breakglassv1alpha1.ClusterConfig{}).
		Build()

	fixedTime := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cc.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "AllGood",
		LastTransitionTime: fixedTime,
	}}

	result, err := PatchApplyClusterConfigStatus(context.Background(), c, cc)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)
}

func TestPatchApplyClusterConfigStatus_Skipped(t *testing.T) {
	scheme := newPatchTestScheme()
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cc",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			ObservedGeneration: 42,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		WithStatusSubresource(&breakglassv1alpha1.ClusterConfig{}).
		Build()

	// Status already matches the stored object — should skip.
	result, err := PatchApplyClusterConfigStatus(context.Background(), c, cc)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultSkipped, result)
}

// ---------------------------------------------------------------------------
// statusSubsetMatch
// ---------------------------------------------------------------------------

func TestStatusSubsetMatch_NilDesired(t *testing.T) {
	assert.True(t, statusSubsetMatch(map[string]interface{}{"foo": "bar"}, nil))
}

func TestStatusSubsetMatch_NilCurrent(t *testing.T) {
	assert.False(t, statusSubsetMatch(nil, map[string]interface{}{"foo": "bar"}))
}

func TestStatusSubsetMatch_EmptyDesired(t *testing.T) {
	assert.True(t, statusSubsetMatch(map[string]interface{}{"foo": "bar"}, map[string]interface{}{}))
}

func TestStatusSubsetMatch_ExactMatch(t *testing.T) {
	current := map[string]interface{}{"state": "active", "count": float64(3)}
	desired := map[string]interface{}{"state": "active", "count": float64(3)}
	assert.True(t, statusSubsetMatch(current, desired))
}

func TestStatusSubsetMatch_SubsetMatch(t *testing.T) {
	current := map[string]interface{}{
		"state":   "active",
		"count":   float64(3),
		"extra":   "field",
		"tracker": map[string]interface{}{"last": "2026-01-01"},
	}
	desired := map[string]interface{}{"state": "active", "count": float64(3)}
	assert.True(t, statusSubsetMatch(current, desired))
}

func TestStatusSubsetMatch_ValueDiffers(t *testing.T) {
	current := map[string]interface{}{"state": "pending", "count": float64(1)}
	desired := map[string]interface{}{"state": "active", "count": float64(1)}
	assert.False(t, statusSubsetMatch(current, desired))
}

func TestStatusSubsetMatch_MissingKey(t *testing.T) {
	current := map[string]interface{}{"state": "active"}
	desired := map[string]interface{}{"state": "active", "count": float64(1)}
	assert.False(t, statusSubsetMatch(current, desired))
}

func TestStatusSubsetMatch_NestedMap(t *testing.T) {
	current := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		},
	}
	desired := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		},
	}
	assert.True(t, statusSubsetMatch(current, desired))
}

func TestStatusSubsetMatch_NestedMapDiffers(t *testing.T) {
	current := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Ready", "status": "False"},
		},
	}
	desired := map[string]interface{}{
		"conditions": []interface{}{
			map[string]interface{}{"type": "Ready", "status": "True"},
		},
	}
	assert.False(t, statusSubsetMatch(current, desired))
}

// ---------------------------------------------------------------------------
// PatchApplyResult.String()
// ---------------------------------------------------------------------------

func TestPatchApplyResult_String(t *testing.T) {
	assert.Equal(t, "skipped", PatchApplyResultSkipped.String())
	assert.Equal(t, "created", PatchApplyResultCreated.String())
	assert.Equal(t, "patched", PatchApplyResultPatched.String())
	assert.Equal(t, "unknown", PatchApplyResult(99).String())
}

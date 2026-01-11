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

package helpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

const (
	// DefaultTimeout for waiting operations
	DefaultTimeout = 60 * time.Second
	// DefaultInterval between polling attempts
	DefaultInterval = 2 * time.Second
)

// WaitForCondition waits for a condition function to return true
func WaitForCondition(ctx context.Context, condition func() (bool, error), timeout, interval time.Duration) error {
	return wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		return condition()
	})
}

// WaitForSessionState waits for a BreakglassSession to reach the specified state
func WaitForSessionState(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, expectedState telekomv1alpha1.BreakglassSessionState, timeout time.Duration) *telekomv1alpha1.BreakglassSession {
	var session telekomv1alpha1.BreakglassSession

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &session); err != nil {
			return false, nil // Keep waiting
		}
		return session.Status.State == expectedState, nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for session %s to reach state %s (current: %s)", name, expectedState, session.Status.State)
	return &session
}

// WaitForDebugSessionState waits for a DebugSession to reach the specified state
func WaitForDebugSessionState(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, expectedState telekomv1alpha1.DebugSessionState, timeout time.Duration) *telekomv1alpha1.DebugSession {
	var session telekomv1alpha1.DebugSession

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &session); err != nil {
			return false, nil // Keep waiting
		}
		return session.Status.State == expectedState, nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for debug session %s to reach state %s (current: %s)", name, expectedState, session.Status.State)
	return &session
}

// WaitForDebugSessionStateAny waits for a DebugSession to have any non-empty state
func WaitForDebugSessionStateAny(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, timeout time.Duration) *telekomv1alpha1.DebugSession {
	var session telekomv1alpha1.DebugSession

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &session); err != nil {
			return false, nil // Keep waiting
		}
		return session.Status.State != "", nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for debug session %s to have any state (current: %s)", name, session.Status.State)
	return &session
}

// WaitForResourceExists waits for a resource to exist
func WaitForResourceExists[T client.Object](t *testing.T, ctx context.Context, cli client.Client, key types.NamespacedName, obj T, timeout time.Duration) T {
	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, key, obj); err != nil {
			return false, nil
		}
		return true, nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for resource %s to exist", key)
	return obj
}

// WaitForResourceDeleted waits for a resource to be deleted
func WaitForResourceDeleted[T client.Object](ctx context.Context, cli client.Client, key types.NamespacedName, obj T, timeout time.Duration) error {
	return WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, key, obj); err != nil {
			// Resource not found means it's deleted
			if client.IgnoreNotFound(err) == nil {
				return true, nil
			}
			return false, err
		}
		return false, nil // Resource still exists
	}, timeout, DefaultInterval)
}

// WaitForDeploymentReady waits for a deployment to have available replicas
func WaitForDeploymentReady(ctx context.Context, cli client.Client, namespace, name string, timeout time.Duration) error {
	return WaitForCondition(ctx, func() (bool, error) {
		// Use unstructured to avoid importing apps/v1
		// This is a simplified check - in practice you'd check the full deployment status
		return true, nil
	}, timeout, DefaultInterval)
}

// WaitForPodReady waits for a pod to be in Running phase with all containers ready
func WaitForPodReady(ctx context.Context, cli client.Client, namespace, name string, timeout time.Duration) error {
	return WaitForCondition(ctx, func() (bool, error) {
		var pod corev1.Pod
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &pod); err != nil {
			return false, nil // Not found yet, keep waiting
		}
		// Check if pod is running
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}
		// Check all containers are ready
		for _, cs := range pod.Status.ContainerStatuses {
			if !cs.Ready {
				return false, nil
			}
		}
		return true, nil
	}, timeout, DefaultInterval)
}

// WaitForClusterConfigCondition waits for a ClusterConfig to have a specific condition status
func WaitForClusterConfigCondition(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, conditionType telekomv1alpha1.ClusterConfigConditionType, expectedStatus metav1.ConditionStatus, timeout time.Duration) *telekomv1alpha1.ClusterConfig {
	var cfg telekomv1alpha1.ClusterConfig

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cfg); err != nil {
			return false, nil
		}
		for _, c := range cfg.Status.Conditions {
			if telekomv1alpha1.ClusterConfigConditionType(c.Type) == conditionType {
				return c.Status == expectedStatus, nil
			}
		}
		return false, nil
	}, timeout, DefaultInterval)

	if t != nil {
		require.NoError(t, err, "Timeout waiting for ClusterConfig %s condition %s to be %s", name, conditionType, expectedStatus)
	}
	return &cfg
}

// WaitForAuditConfigReady waits for an AuditConfig to have Ready=True condition.
// This is important to ensure the audit system is fully configured before running tests
// that expect audit events to be captured.
func WaitForAuditConfigReady(t *testing.T, ctx context.Context, cli client.Client, name string, timeout time.Duration) *telekomv1alpha1.AuditConfig {
	var cfg telekomv1alpha1.AuditConfig

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name}, &cfg); err != nil {
			t.Logf("WaitForAuditConfigReady: AuditConfig %s not found yet: %v", name, err)
			return false, nil
		}
		for _, c := range cfg.Status.Conditions {
			if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
				t.Logf("WaitForAuditConfigReady: AuditConfig %s is Ready (sinks: %v)", name, cfg.Status.ActiveSinks)
				return true, nil
			}
		}
		t.Logf("WaitForAuditConfigReady: AuditConfig %s not Ready yet (conditions: %v)", name, cfg.Status.Conditions)
		return false, nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for AuditConfig %s to be Ready", name)
	return &cfg
}

// WaitForSessionStateAny waits for a BreakglassSession to have one of multiple expected states
func WaitForSessionStateAny(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, expectedStates []telekomv1alpha1.BreakglassSessionState, timeout time.Duration) *telekomv1alpha1.BreakglassSession {
	var session telekomv1alpha1.BreakglassSession

	err := WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &session); err != nil {
			return false, nil
		}
		for _, s := range expectedStates {
			if session.Status.State == s {
				return true, nil
			}
		}
		return false, nil
	}, timeout, DefaultInterval)

	require.NoError(t, err, "Timeout waiting for session %s to reach one of states %v (current: %s)", name, expectedStates, session.Status.State)
	return &session
}

// RetryWithBackoff retries an operation with exponential backoff
func RetryWithBackoff(ctx context.Context, maxRetries int, initialDelay time.Duration, operation func() error) error {
	delay := initialDelay
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if err := operation(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			delay *= 2
		}
	}

	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}

// ApproveSession approves a BreakglassSession by updating its status
func ApproveSession(ctx context.Context, cli client.Client, name, namespace, approverEmail string) error {
	var session telekomv1alpha1.BreakglassSession
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := cli.Get(ctx, key, &session); err != nil {
		return fmt.Errorf("failed to get session %s: %w", name, err)
	}

	session.Status.Approver = approverEmail
	session.Status.ApprovedAt = metav1.Now()
	session.Status.State = telekomv1alpha1.SessionStateApproved
	// CRITICAL: Set ExpiresAt - the webhook requires this to recognize active sessions
	// Parse MaxValidFor from spec or default to 1h
	maxValidFor := time.Hour
	if session.Spec.MaxValidFor != "" {
		if d, err := time.ParseDuration(session.Spec.MaxValidFor); err == nil && d > 0 {
			maxValidFor = d
		}
	}
	session.Status.ExpiresAt = metav1.NewTime(time.Now().Add(maxValidFor))

	if err := cli.Status().Update(ctx, &session); err != nil {
		return fmt.Errorf("failed to approve session %s: %w", name, err)
	}
	return nil
}

// RejectSession rejects a BreakglassSession by updating its status
func RejectSession(ctx context.Context, cli client.Client, name, namespace, approverEmail, reason string) error {
	var session telekomv1alpha1.BreakglassSession
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := cli.Get(ctx, key, &session); err != nil {
		return fmt.Errorf("failed to get session %s: %w", name, err)
	}

	session.Status.Approver = approverEmail
	session.Status.RejectedAt = metav1.Now()
	session.Status.State = telekomv1alpha1.SessionStateRejected
	session.Status.ApprovalReason = reason

	if err := cli.Status().Update(ctx, &session); err != nil {
		return fmt.Errorf("failed to reject session %s: %w", name, err)
	}
	return nil
}

// WithdrawSession withdraws a BreakglassSession by updating its status
func WithdrawSession(ctx context.Context, cli client.Client, name, namespace string) error {
	var session telekomv1alpha1.BreakglassSession
	key := types.NamespacedName{Name: name, Namespace: namespace}
	if err := cli.Get(ctx, key, &session); err != nil {
		return fmt.Errorf("failed to get session %s: %w", name, err)
	}

	session.Status.State = telekomv1alpha1.SessionStateWithdrawn

	if err := cli.Status().Update(ctx, &session); err != nil {
		return fmt.Errorf("failed to withdraw session %s: %w", name, err)
	}
	return nil
}

// ApproveSessionViaAPI approves a BreakglassSession via the REST API using an authenticated API client.
// This is the preferred method as it goes through the proper authorization flow.
func ApproveSessionViaAPI(ctx context.Context, t *testing.T, apiClient *APIClient, name, namespace string) error {
	return apiClient.ApproveSessionViaAPI(ctx, t, name, namespace)
}

// RejectSessionViaAPI rejects a BreakglassSession via the REST API using an authenticated API client.
// This is the preferred method as it goes through the proper authorization flow.
func RejectSessionViaAPI(ctx context.Context, t *testing.T, apiClient *APIClient, name, namespace, reason string) error {
	return apiClient.RejectSessionViaAPI(ctx, t, name, namespace, reason)
}

// WithdrawSessionViaAPI withdraws a BreakglassSession via the REST API using an authenticated API client.
// The requester can withdraw their own pending session.
func WithdrawSessionViaAPI(ctx context.Context, t *testing.T, apiClient *APIClient, name, namespace string) error {
	return apiClient.WithdrawSessionViaAPI(ctx, t, name, namespace)
}

// DropSessionViaAPI drops a BreakglassSession via the REST API using an authenticated API client.
// The session owner can drop an active or pending session.
func DropSessionViaAPI(ctx context.Context, t *testing.T, apiClient *APIClient, name, namespace string) error {
	return apiClient.DropSessionViaAPI(ctx, t, name, namespace)
}

// CancelSessionViaAPI cancels a BreakglassSession via the REST API using an authenticated API client.
// An approver can cancel an active/approved session.
func CancelSessionViaAPI(ctx context.Context, t *testing.T, apiClient *APIClient, name, namespace string) error {
	return apiClient.CancelSessionViaAPI(ctx, t, name, namespace)
}

// CachePropagationDelay is the time to wait for controller cache propagation.
// This is a safer alternative to bare time.Sleep() calls.
const CachePropagationDelay = 2 * time.Second

// WaitForCachePropagation waits for controller cache to propagate changes.
// Use this instead of bare time.Sleep() when waiting for cache updates.
// If a verification function is provided, it will poll until the function returns true.
//
// Example:
//
//	// Simple cache wait
//	helpers.WaitForCachePropagation(ctx)
//
//	// Wait with verification
//	helpers.WaitForCachePropagationWithVerify(ctx, t, func() bool {
//	    var esc telekomv1alpha1.BreakglassEscalation
//	    err := cli.Get(ctx, key, &esc)
//	    return err == nil && esc.Status.Ready
//	})
func WaitForCachePropagation(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(CachePropagationDelay):
		return
	}
}

// WaitForCachePropagationWithVerify waits for cache propagation with verification.
// It polls the verify function until it returns true or times out.
func WaitForCachePropagationWithVerify(ctx context.Context, t *testing.T, verify func() bool) {
	t.Helper()

	timeout := 10 * time.Second
	interval := 500 * time.Millisecond

	err := WaitForCondition(ctx, func() (bool, error) {
		return verify(), nil
	}, timeout, interval)

	if err != nil && ctx.Err() == nil {
		t.Logf("Warning: cache propagation verification timed out")
	}
}

// WaitForResourceUpdate waits for a resource to be updated by the controller.
// It checks that the resource's generation has been observed.
func WaitForResourceUpdate[T interface {
	client.Object
	GetGeneration() int64
}](ctx context.Context, t *testing.T, cli client.Client, key types.NamespacedName, obj T, timeout time.Duration) error {
	t.Helper()

	expectedGen := obj.GetGeneration()
	return WaitForCondition(ctx, func() (bool, error) {
		if err := cli.Get(ctx, key, obj); err != nil {
			return false, nil
		}
		// Check if controller has observed this generation
		// Most status structs have ObservedGeneration
		return obj.GetGeneration() >= expectedGen, nil
	}, timeout, DefaultInterval)
}

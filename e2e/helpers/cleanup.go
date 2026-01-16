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
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/naming"
)

// isCleanupDisabled returns true if E2E_SKIP_CLEANUP is set.
// In CI, we skip cleanup so that resources remain for post-test debugging
// and resource dump (e.g., kubectl get escalations -o yaml).
// Each test uses unique names (with random suffixes) to avoid conflicts.
func isCleanupDisabled() bool {
	return os.Getenv("E2E_SKIP_CLEANUP") == "true"
}

// Cleanup handles test resource cleanup
type Cleanup struct {
	t         *testing.T
	cli       client.Client
	resources []client.Object
}

// NewCleanup creates a new cleanup handler
func NewCleanup(t *testing.T, cli client.Client) *Cleanup {
	c := &Cleanup{
		t:         t,
		cli:       cli,
		resources: make([]client.Object, 0),
	}

	t.Cleanup(func() {
		c.Run()
	})

	return c
}

// Add registers a resource for cleanup
func (c *Cleanup) Add(obj client.Object) {
	c.resources = append(c.resources, obj)
}

// CreateAndRegister creates a resource and registers it for cleanup only on success.
// This is the recommended pattern - it avoids registering cleanup for resources
// that failed to create (which would cause noisy "not found" errors during cleanup).
//
// Usage:
//
//	err := cleanup.CreateAndRegister(ctx, cli, escalation)
//	require.NoError(t, err)
func (c *Cleanup) CreateAndRegister(ctx context.Context, cli client.Client, obj client.Object) error {
	if err := cli.Create(ctx, obj); err != nil {
		return err
	}
	c.Add(obj)
	return nil
}

// MustCreateAndRegister creates a resource and registers it for cleanup.
// Fails the test immediately if creation fails.
func (c *Cleanup) MustCreateAndRegister(ctx context.Context, cli client.Client, obj client.Object) {
	c.t.Helper()
	if err := c.CreateAndRegister(ctx, cli, obj); err != nil {
		c.t.Fatalf("Failed to create resource %T %s: %v", obj, obj.GetName(), err)
	}
}

// Run executes cleanup of all registered resources.
// If E2E_SKIP_CLEANUP=true (set in CI), cleanup is skipped to allow
// post-test debugging via resource dumps (kubectl get ... -o yaml).
func (c *Cleanup) Run() {
	if isCleanupDisabled() {
		c.t.Logf("Cleanup skipped: E2E_SKIP_CLEANUP=true (resources remain for debugging)")
		return
	}
	ctx := context.Background()
	for _, obj := range c.resources {
		if err := c.cli.Delete(ctx, obj); err != nil {
			if client.IgnoreNotFound(err) != nil {
				c.t.Logf("Cleanup warning: failed to delete %T %s: %v", obj, obj.GetName(), err)
			}
		}
	}
}

// CleanupAllSessions deletes all BreakglassSessions in a namespace
func CleanupAllSessions(ctx context.Context, cli client.Client, namespace string) error {
	sessions := &telekomv1alpha1.BreakglassSessionList{}
	if err := cli.List(ctx, sessions, client.InNamespace(namespace)); err != nil {
		return err
	}

	for i := range sessions.Items {
		if err := cli.Delete(ctx, &sessions.Items[i]); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// ExpireActiveSessionsForUser expires (sets to Expired state) all active sessions for a user.
// This is useful to avoid 409 conflicts when a test needs to create a new session
// for a user that may already have an active session from a previous test.
// Unlike deletion, expiring a session is cleaner and reflects natural lifecycle.
func ExpireActiveSessionsForUser(ctx context.Context, cli client.Client, namespace, userEmail string) error {
	sessions := &telekomv1alpha1.BreakglassSessionList{}
	if err := cli.List(ctx, sessions,
		client.InNamespace(namespace),
		client.MatchingLabels{"breakglass.t-caas.telekom.com/user": naming.ToRFC1123Label(userEmail)},
	); err != nil {
		return err
	}

	now := metav1.Now()
	for i := range sessions.Items {
		session := &sessions.Items[i]
		// Only expire active sessions (Pending or Approved)
		if session.Status.State == telekomv1alpha1.SessionStatePending ||
			session.Status.State == telekomv1alpha1.SessionStateApproved {
			// Mark as expired by setting expiresAt to the past
			session.Status.ExpiresAt = now
			session.Status.State = telekomv1alpha1.SessionStateExpired
			if err := cli.Status().Update(ctx, session); err != nil {
				if client.IgnoreNotFound(err) != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ExpireActiveSessionsForUserAndGroup deletes all active sessions for a specific user+group+cluster
// and waits for the deletion to complete.
// This is more precise than ExpireActiveSessionsForUser and helps avoid conflicts in tests
// that reuse user+group combinations.
// Note: We delete rather than expire because the API server may cache the old state.
func ExpireActiveSessionsForUserAndGroup(ctx context.Context, cli client.Client, namespace, cluster, userEmail, group string) error {
	matchingLabels := client.MatchingLabels{
		"breakglass.t-caas.telekom.com/user":    naming.ToRFC1123Label(userEmail),
		"breakglass.t-caas.telekom.com/cluster": cluster,
		"breakglass.t-caas.telekom.com/group":   group,
	}

	sessions := &telekomv1alpha1.BreakglassSessionList{}
	if err := cli.List(ctx, sessions,
		client.InNamespace(namespace),
		matchingLabels,
	); err != nil {
		return err
	}

	deletedSessions := []string{}
	for i := range sessions.Items {
		session := &sessions.Items[i]
		// Delete active sessions (Pending or Approved)
		if session.Status.State == telekomv1alpha1.SessionStatePending ||
			session.Status.State == telekomv1alpha1.SessionStateApproved {
			if err := cli.Delete(ctx, session); err != nil {
				if client.IgnoreNotFound(err) != nil {
					return err
				}
			}
			deletedSessions = append(deletedSessions, session.Name)
		}
	}

	// If we deleted any sessions, wait for them to actually be gone
	if len(deletedSessions) > 0 {
		return waitForSessionsDeleted(ctx, cli, namespace, matchingLabels, 5*time.Second)
	}
	return nil
}

// waitForSessionsDeleted polls until no active sessions exist for the given labels
func waitForSessionsDeleted(ctx context.Context, cli client.Client, namespace string, labels client.MatchingLabels, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pollInterval := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		sessions := &telekomv1alpha1.BreakglassSessionList{}
		if err := cli.List(ctx, sessions, client.InNamespace(namespace), labels); err != nil {
			return err
		}

		// Check if any active sessions remain
		activeCount := 0
		for i := range sessions.Items {
			if sessions.Items[i].Status.State == telekomv1alpha1.SessionStatePending ||
				sessions.Items[i].Status.State == telekomv1alpha1.SessionStateApproved {
				activeCount++
			}
		}

		if activeCount == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
			// continue polling
		}
	}

	return fmt.Errorf("timeout waiting for sessions to be deleted")
}

// DeleteActiveDebugSessionsForCluster deletes all active debug sessions for a specific cluster
// and waits for the deletion to complete.
// This helps avoid "session already exists" conflicts in tests.
func DeleteActiveDebugSessionsForCluster(ctx context.Context, cli client.Client, namespace, cluster string) error {
	matchingLabels := client.MatchingLabels{"breakglass.telekom.com/debug-cluster": cluster}

	sessions := &telekomv1alpha1.DebugSessionList{}
	if err := cli.List(ctx, sessions, client.InNamespace(namespace), matchingLabels); err != nil {
		return err
	}

	deletedSessions := []string{}
	for i := range sessions.Items {
		session := &sessions.Items[i]
		// Delete active sessions for this cluster
		if session.Status.State == telekomv1alpha1.DebugSessionStateActive ||
			session.Status.State == telekomv1alpha1.DebugSessionStatePending ||
			session.Status.State == "" { // Also handle empty state (just created)
			if err := cli.Delete(ctx, session); err != nil {
				if client.IgnoreNotFound(err) != nil {
					return err
				}
			}
			deletedSessions = append(deletedSessions, session.Name)
		}
	}

	// If we deleted any sessions, wait for them to actually be gone
	if len(deletedSessions) > 0 {
		return waitForDebugSessionsDeleted(ctx, cli, namespace, matchingLabels, 5*time.Second)
	}
	return nil
}

// waitForDebugSessionsDeleted polls until no active debug sessions exist for the given labels
func waitForDebugSessionsDeleted(ctx context.Context, cli client.Client, namespace string, labels client.MatchingLabels, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pollInterval := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		sessions := &telekomv1alpha1.DebugSessionList{}
		if err := cli.List(ctx, sessions, client.InNamespace(namespace), labels); err != nil {
			return err
		}

		// Check if any active sessions remain
		activeCount := 0
		for i := range sessions.Items {
			state := sessions.Items[i].Status.State
			if state == telekomv1alpha1.DebugSessionStateActive ||
				state == telekomv1alpha1.DebugSessionStatePending ||
				state == "" {
				activeCount++
			}
		}

		if activeCount == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
			// continue polling
		}
	}

	return fmt.Errorf("timeout waiting for debug sessions to be deleted")
}

// CleanupAllEscalations deletes all BreakglassEscalations
func CleanupAllEscalations(ctx context.Context, cli client.Client) error {
	escalations := &telekomv1alpha1.BreakglassEscalationList{}
	if err := cli.List(ctx, escalations); err != nil {
		return err
	}

	for i := range escalations.Items {
		if err := cli.Delete(ctx, &escalations.Items[i]); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupAllDenyPolicies deletes all DenyPolicies
func CleanupAllDenyPolicies(ctx context.Context, cli client.Client) error {
	policies := &telekomv1alpha1.DenyPolicyList{}
	if err := cli.List(ctx, policies); err != nil {
		return err
	}

	for i := range policies.Items {
		if err := cli.Delete(ctx, &policies.Items[i]); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupTestResources cleans up all test-related resources with a specific label
func CleanupTestResources(ctx context.Context, cli client.Client, labelKey, labelValue string) error {
	listOpts := []client.ListOption{
		client.MatchingLabels{labelKey: labelValue},
	}

	// Clean sessions
	sessions := &telekomv1alpha1.BreakglassSessionList{}
	if err := cli.List(ctx, sessions, listOpts...); err == nil {
		for i := range sessions.Items {
			_ = cli.Delete(ctx, &sessions.Items[i])
		}
	}

	// Clean escalations
	escalations := &telekomv1alpha1.BreakglassEscalationList{}
	if err := cli.List(ctx, escalations, listOpts...); err == nil {
		for i := range escalations.Items {
			_ = cli.Delete(ctx, &escalations.Items[i])
		}
	}

	// Clean deny policies
	policies := &telekomv1alpha1.DenyPolicyList{}
	if err := cli.List(ctx, policies, listOpts...); err == nil {
		for i := range policies.Items {
			_ = cli.Delete(ctx, &policies.Items[i])
		}
	}

	return nil
}

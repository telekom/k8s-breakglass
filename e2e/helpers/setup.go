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
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestSetup contains all common test setup components.
// Use SetupTest() to create this instead of manually setting up each test.
//
// Example usage:
//
//	func TestMyFeature(t *testing.T) {
//	    s := helpers.SetupTest(t)
//	    // s.Ctx, s.Client, s.Cleanup, s.Namespace, s.Cluster are all ready
//	    escalation := helpers.NewEscalationBuilder("test", s.Namespace).
//	        WithEscalatedGroup("pod-admin").
//	        WithAllowedClusters(s.Cluster).
//	        Build()
//	    s.CreateResource(escalation)
//	}
type TestSetup struct {
	T         *testing.T
	Ctx       context.Context
	cancel    context.CancelFunc
	Client    client.Client
	Cleanup   *Cleanup
	Namespace string
	Cluster   string
	TC        *TestContext
}

// SetupOption configures TestSetup behavior
type SetupOption func(*setupConfig)

type setupConfig struct {
	timeout        time.Duration
	skipE2ECheck   bool
	requireWebhook bool
	requireMetrics bool
	requireAudit   bool
	namespace      string
	cluster        string
}

// WithTimeout sets a custom test timeout (default: MediumTestTimeout)
func WithTimeout(d time.Duration) SetupOption {
	return func(c *setupConfig) {
		c.timeout = d
	}
}

// WithShortTimeout sets a short timeout for quick tests
func WithShortTimeout() SetupOption {
	return func(c *setupConfig) {
		c.timeout = ShortTestTimeout
	}
}

// WithMediumTimeout sets a medium timeout for standard tests
func WithMediumTimeout() SetupOption {
	return func(c *setupConfig) {
		c.timeout = MediumTestTimeout
	}
}

// WithLongTimeout sets a long timeout for complex tests
func WithLongTimeout() SetupOption {
	return func(c *setupConfig) {
		c.timeout = LongTestTimeout
	}
}

// WithNamespace overrides the default test namespace
func WithNamespace(ns string) SetupOption {
	return func(c *setupConfig) {
		c.namespace = ns
	}
}

// WithCluster overrides the default test cluster name
func WithCluster(cluster string) SetupOption {
	return func(c *setupConfig) {
		c.cluster = cluster
	}
}

// WithWebhookRequired skips the test if webhook tests are not enabled
func WithWebhookRequired() SetupOption {
	return func(c *setupConfig) {
		c.requireWebhook = true
	}
}

// WithMetricsRequired skips the test if metrics tests are not enabled
func WithMetricsRequired() SetupOption {
	return func(c *setupConfig) {
		c.requireMetrics = true
	}
}

// WithAuditRequired skips the test if audit tests are not enabled
func WithAuditRequired() SetupOption {
	return func(c *setupConfig) {
		c.requireAudit = true
	}
}

// SkipE2ECheck disables the E2E_TEST environment check (for unit tests)
func SkipE2ECheck() SetupOption {
	return func(c *setupConfig) {
		c.skipE2ECheck = true
	}
}

// SetupTest creates a TestSetup with all common test infrastructure.
// This replaces the common boilerplate found in most E2E tests:
//
//	if !helpers.IsE2EEnabled() { t.Skip(...) }
//	ctx, cancel := context.WithTimeout(...)
//	defer cancel()
//	cli := helpers.GetClient(t)
//	cleanup := helpers.NewCleanup(t, cli)
//	namespace := helpers.GetTestNamespace()
//	clusterName := helpers.GetTestClusterName()
//
// Usage:
//
//	s := helpers.SetupTest(t)
//	// Use s.Ctx, s.Client, s.Cleanup, s.Namespace, s.Cluster
func SetupTest(t *testing.T, opts ...SetupOption) *TestSetup {
	t.Helper()

	// Apply default config
	cfg := &setupConfig{
		timeout:   MediumTestTimeout,
		namespace: GetTestNamespace(),
		cluster:   GetTestClusterName(),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// Check if E2E tests are enabled
	if !cfg.skipE2ECheck && !IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	// Check optional requirements
	if cfg.requireWebhook && !IsWebhookTestEnabled() {
		t.Skip("Skipping webhook test. Set E2E_WEBHOOK_TEST=true to run.")
	}
	if cfg.requireMetrics && !IsMetricsTestEnabled() {
		t.Skip("Skipping metrics test. Set E2E_METRICS_TEST=true to run.")
	}
	if cfg.requireAudit && !IsAuditTestEnabled() {
		t.Skip("Skipping audit test. Set E2E_AUDIT_TEST=true to run.")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)

	// Get client
	cli := GetClient(t)

	// Create cleanup handler
	cleanup := NewCleanup(t, cli)

	// Create test context for API operations
	tc := NewTestContext(t, ctx).WithClient(cli, cfg.namespace)

	// Register cleanup on test completion
	t.Cleanup(func() {
		cancel()
	})

	return &TestSetup{
		T:         t,
		Ctx:       ctx,
		cancel:    cancel,
		Client:    cli,
		Cleanup:   cleanup,
		Namespace: cfg.namespace,
		Cluster:   cfg.cluster,
		TC:        tc,
	}
}

// CreateResource creates a resource and registers it for cleanup.
// This is the recommended way to create test resources - it ensures
// cleanup is only registered after successful creation.
func (s *TestSetup) CreateResource(obj client.Object) error {
	if err := s.Client.Create(s.Ctx, obj); err != nil {
		return err
	}
	s.Cleanup.Add(obj)
	return nil
}

// MustCreateResource creates a resource and registers it for cleanup.
// Fails the test immediately if creation fails.
func (s *TestSetup) MustCreateResource(obj client.Object) {
	s.T.Helper()
	if err := s.CreateResource(obj); err != nil {
		s.T.Fatalf("Failed to create resource %T %s: %v", obj, obj.GetName(), err)
	}
}

// RequesterClient returns an API client authenticated as the requester user
func (s *TestSetup) RequesterClient() *APIClient {
	return s.TC.RequesterClient()
}

// ApproverClient returns an API client authenticated as the approver user
func (s *TestSetup) ApproverClient() *APIClient {
	return s.TC.ApproverClient()
}

// GenerateName generates a unique name with the given prefix
func (s *TestSetup) GenerateName(prefix string) string {
	return GenerateUniqueName(prefix)
}

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

package breakglass

import (
	"context"
	"sync"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MockAuditEmitter is a test double for AuditEmitter.
type MockAuditEmitter struct {
	mu      sync.Mutex
	enabled bool
	events  []*audit.Event
}

// NewMockAuditEmitter creates a new mock audit emitter.
func NewMockAuditEmitter(enabled bool) *MockAuditEmitter {
	return &MockAuditEmitter{
		enabled: enabled,
		events:  make([]*audit.Event, 0),
	}
}

// Emit implements AuditEmitter.
func (m *MockAuditEmitter) Emit(_ context.Context, event *audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

// IsEnabled implements AuditEmitter.
func (m *MockAuditEmitter) IsEnabled() bool {
	return m.enabled
}

// GetEvents returns all emitted events.
func (m *MockAuditEmitter) GetEvents() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*audit.Event{}, m.events...)
}

// Clear clears all events.
func (m *MockAuditEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]*audit.Event, 0)
}

// testEscalationLookup implements EscalationLookup for root tests by wrapping a
// controller-runtime client. It performs the same List+filter that EscalationManager
// does, so tests using pre-seeded fake clients work identically.
type testEscalationLookup struct {
	client.Client
	resolver GroupMemberResolver
}

func (t *testEscalationLookup) GetClusterBreakglassEscalations(ctx context.Context, cluster string) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	var list breakglassv1alpha1.BreakglassEscalationList
	if err := t.Client.List(ctx, &list); err != nil {
		return nil, err
	}
	var out []breakglassv1alpha1.BreakglassEscalation
	for _, e := range list.Items {
		for _, c := range e.Spec.Allowed.Clusters {
			if c == cluster || c == "*" {
				out = append(out, e)
				break
			}
		}
	}
	return out, nil
}

func (t *testEscalationLookup) GetClusterGroupBreakglassEscalations(ctx context.Context, cluster string, groups []string) ([]breakglassv1alpha1.BreakglassEscalation, error) {
	clusterEscalations, err := t.GetClusterBreakglassEscalations(ctx, cluster)
	if err != nil {
		return nil, err
	}
	groupSet := make(map[string]bool)
	for _, g := range groups {
		groupSet[g] = true
	}
	var out []breakglassv1alpha1.BreakglassEscalation
	for _, e := range clusterEscalations {
		for _, g := range e.Spec.Allowed.Groups {
			if groupSet[g] {
				out = append(out, e)
				break
			}
		}
	}
	return out, nil
}

func (t *testEscalationLookup) GetResolver() GroupMemberResolver {
	return t.resolver
}

func (t *testEscalationLookup) SetResolver(resolver GroupMemberResolver) {
	t.resolver = resolver
}

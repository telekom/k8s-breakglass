// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestManager_GlobalEventTypeFiltering(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var received []EventType
	sink := &testSink{
		name: "test",
		writeFunc: func(event *Event) {
			received = append(received, event.Type)
		},
	}
	cfg := DefaultManagerConfig()
	cfg.IncludeEventTypes = []string{"session.*", "access.denied*"}
	cfg.ExcludeEventTypes = []string{string(EventSessionDenied), string(EventAccessDeniedPolicy)}
	manager := NewManager(sink, cfg, logger)
	defer func() { _ = manager.Close() }()

	events := []EventType{
		EventSessionRequested,
		EventSessionDenied,
		EventAccessDenied,
		EventAccessDeniedPolicy,
		EventResourceGet,
	}
	for _, eventType := range events {
		err := manager.EmitSync(context.Background(), &Event{Type: eventType})
		require.NoError(t, err)
	}

	assert.Equal(t, []EventType{EventSessionRequested, EventAccessDenied}, received)
}

func TestFilteredSinkEventTypes(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var sessionEvents []EventType
	var allEvents []EventType
	sessionSink := NewFilteredSink(&testSink{
		name: "sessions",
		writeFunc: func(event *Event) {
			sessionEvents = append(sessionEvents, event.Type)
		},
	}, EventFilterConfig{IncludeEventTypes: []string{"session.*"}})
	allSink := NewFilteredSink(&testSink{
		name: "all",
		writeFunc: func(event *Event) {
			allEvents = append(allEvents, event.Type)
		},
	}, EventFilterConfig{})
	multi := NewMultiSink([]Sink{sessionSink, allSink}, logger)

	err := multi.Write(context.Background(), &Event{Type: EventSessionApproved})
	require.NoError(t, err)
	err = multi.Write(context.Background(), &Event{Type: EventAccessDenied})
	require.NoError(t, err)

	assert.Equal(t, []EventType{EventSessionApproved}, sessionEvents)
	assert.Equal(t, []EventType{EventSessionApproved, EventAccessDenied}, allEvents)
}

func TestFilteredSinkMinSeverity(t *testing.T) {
	var received []EventType
	sink := NewFilteredSink(&testSink{
		name: "warnings",
		writeFunc: func(event *Event) {
			received = append(received, event.Type)
		},
	}, EventFilterConfig{MinSeverity: SeverityWarning})

	for _, eventType := range []EventType{
		EventSessionRequested,
		EventAccessDenied,
		EventSessionRevoked,
	} {
		err := sink.Write(context.Background(), &Event{Type: eventType})
		require.NoError(t, err)
	}

	assert.Equal(t, []EventType{EventAccessDenied, EventSessionRevoked}, received)
}

func TestFilteredSinkAuditFilterFields(t *testing.T) {
	var received []string
	sink := NewFilteredSink(&testSink{
		name: "filtered",
		writeFunc: func(event *Event) {
			received = append(received, event.Target.Name)
		},
	}, EventFilterConfig{
		IncludeUsers: []string{"*@example.com"},
		ExcludeUsers: []string{"system:*"},
		IncludeNamespaces: &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"prod-*"},
		},
		ExcludeNamespaces: &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"prod-kube-*"},
		},
		IncludeResources: []string{"pods", "secrets"},
		ExcludeResources: []string{"secrets"},
	})

	events := []*Event{
		{
			Type:  EventAccessAllowed,
			Actor: Actor{User: "alice@example.com"},
			Target: Target{
				Kind:      "Pod",
				Name:      "allowed",
				Namespace: "prod-app",
			},
		},
		{
			Type:  EventAccessAllowed,
			Actor: Actor{User: "system:serviceaccount:prod-app:controller"},
			Target: Target{
				Kind:      "Pod",
				Name:      "excluded-user",
				Namespace: "prod-app",
			},
		},
		{
			Type:  EventAccessAllowed,
			Actor: Actor{User: "bob@example.com"},
			Target: Target{
				Kind:      "Pod",
				Name:      "excluded-namespace",
				Namespace: "prod-kube-system",
			},
		},
		{
			Type:  EventAccessAllowed,
			Actor: Actor{User: "carol@example.com"},
			Target: Target{
				Kind:      "Secret",
				Name:      "excluded-resource",
				Namespace: "prod-app",
			},
		},
		{
			Type:  EventAccessAllowed,
			Actor: Actor{User: "dan@example.com"},
			Target: Target{
				Kind:      "Deployment",
				Name:      "not-included-resource",
				Namespace: "prod-app",
			},
		},
	}

	for _, event := range events {
		err := sink.Write(context.Background(), event)
		require.NoError(t, err)
	}

	assert.Equal(t, []string{"allowed"}, received)
}

func TestFilteredSinkResourceFilterMatchesSingularPluralAliases(t *testing.T) {
	tests := []struct {
		name            string
		kind            string
		includeResource string
	}{
		{
			name:            "plural lowercase event resource matches title-case singular config",
			kind:            "pods",
			includeResource: "Pod",
		},
		{
			name:            "title-case kind matches lowercase plural config",
			kind:            "Pod",
			includeResource: "pods",
		},
		{
			name:            "ies plural matches singular config",
			kind:            "policies",
			includeResource: "policy",
		},
		{
			name:            "ses plural matches singular config",
			kind:            "ingresses",
			includeResource: "Ingress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var received []string
			sink := NewFilteredSink(&testSink{
				name: "resources",
				writeFunc: func(event *Event) {
					received = append(received, event.Target.Name)
				},
			}, EventFilterConfig{
				IncludeResources: []string{tt.includeResource},
			})

			err := sink.Write(context.Background(), &Event{
				Type: EventAccessAllowed,
				Target: Target{
					Kind: tt.kind,
					Name: "matched",
				},
			})
			require.NoError(t, err)

			assert.Equal(t, []string{"matched"}, received)
		})
	}
}

func TestResourceFilterAllowedSkipsCandidateExpansionWithoutPatterns(t *testing.T) {
	assert.True(t, resourceFilterAllowed("", nil, nil))
	assert.True(t, resourceFilterAllowed("pods", nil, nil))
}

func TestFilteredSinkNamespaceSelectorTermsWhenLabelsArePresent(t *testing.T) {
	var received []string
	sink := NewFilteredSink(&testSink{
		name: "selector",
		writeFunc: func(event *Event) {
			received = append(received, event.Target.Name)
		},
	}, EventFilterConfig{
		IncludeNamespaces: &breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"audit-enabled": "true"}},
			},
		},
	})

	events := []*Event{
		{
			Type: EventSessionRequested,
			Target: Target{
				Name:            "labels-match",
				Namespace:       "app-a",
				NamespaceLabels: map[string]string{"audit-enabled": "true"},
			},
		},
		{
			Type: EventSessionRequested,
			Target: Target{
				Name:      "labels-unavailable",
				Namespace: "app-b",
			},
		},
		{
			Type: EventSessionRequested,
			Target: Target{
				Name:            "labels-do-not-match",
				Namespace:       "app-c",
				NamespaceLabels: map[string]string{"audit-enabled": "false"},
			},
		},
	}

	for _, event := range events {
		err := sink.Write(context.Background(), event)
		require.NoError(t, err)
	}

	assert.Equal(t, []string{"labels-match"}, received)
}

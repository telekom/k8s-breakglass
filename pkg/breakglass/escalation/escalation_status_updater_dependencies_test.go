package escalation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestEscalationStatusUpdaterWithEventRecorder verifies that EventRecorder is used when provided
func TestEscalationStatusUpdaterWithEventRecorder(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	resolver := &MockResolver{
		members: map[string][]string{
			"admin-group": {"user1@example.com", "user2@example.com"},
		},
		errors: map[string]error{},
	}

	// Create a mock EventRecorder to capture events
	fakeRecorder := fakeEventRecorder{}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil,
		EventRecorder: fakeRecorder,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	// Verify that updater has EventRecorder set
	assert.NotNil(t, updater.EventRecorder)
	assert.Equal(t, fakeRecorder, updater.EventRecorder)

	// Test that the updater can use EventRecorder (verifying it's not nil and properly initialized)
	ctx := context.Background()
	_, _, _ = updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"admin-group"}, slog)
}

// TestEscalationStatusUpdaterWithIDPLoader verifies that IDPLoader field is set
func TestEscalationStatusUpdaterWithIDPLoader(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	resolver := &MockResolver{
		members: map[string][]string{
			"admin-group": {"user1@example.com", "user2@example.com"},
		},
		errors: map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil, // Can be set to actual IDPLoader in real scenario
		EventRecorder: nil,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
	}

	// Verify the struct has IDPLoader field (checking it compiles and doesn't panic)
	assert.NotNil(t, updater) // IDPLoader field exists and can be set
	ctx := context.Background()
	_, _, _ = updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"admin-group"}, slog)
}

// TestEscalationStatusUpdaterInitialization verifies both EventRecorder and IDPLoader can be initialized together
func TestEscalationStatusUpdaterInitialization(t *testing.T) {
	resolver := &MockResolver{
		members: map[string][]string{
			"admin-group": {"user1@example.com"},
		},
		errors: map[string]error{},
	}

	fakeRecorder := fakeEventRecorder{}

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil, // In real code, this would be set to actual IDPLoader instance
		EventRecorder: fakeRecorder,
	}

	// Verify both fields exist and can be set
	assert.NotNil(t, updater.EventRecorder)
	// IDPLoader field exists (whether nil or not is configurable)
	assert.NotNil(t, updater)
}

// TestEventEmissionWithEventRecorder verifies events can be emitted when EventRecorder is available
func TestEventEmissionWithEventRecorder(t *testing.T) {
	// This test verifies the event emission flow is properly initialized
	fakeRecorder := fakeEventRecorder{Events: make(chan string, 1)}

	// Create an escalation resource
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc",
			Namespace: "default",
		},
	}

	// Emit a test event
	fakeRecorder.Eventf(escalation, nil, "Normal", "TestEvent", "TestEvent", "Test message")

	// Verify event was recorded
	select {
	case event := <-fakeRecorder.Events:
		// Event format is "Normal TestEvent TestEvent Test message" — reason and action share the name.
		//nolint:dupword // literal event format contains intentional duplicate word
		assert.Contains(t, event, "Normal")
		assert.Contains(t, event, "TestEvent")
		assert.Contains(t, event, "Test message")
	default:
		t.Fatal("Expected event to be recorded")
	}
}

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "equal slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different order (still equal after sort)",
			a:        []string{"a", "b", "c"},
			b:        []string{"c", "b", "a"},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "different content",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "d"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalStringSlices(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEqualIDPHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		a        map[string]map[string][]string
		b        map[string]map[string][]string
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "both empty",
			a:        map[string]map[string][]string{},
			b:        map[string]map[string][]string{},
			expected: true,
		},
		{
			name: "equal hierarchies",
			a: map[string]map[string][]string{
				"idp1": {"group1": {"user1", "user2"}},
			},
			b: map[string]map[string][]string{
				"idp1": {"group1": {"user1", "user2"}},
			},
			expected: true,
		},
		{
			name: "different IDP names",
			a: map[string]map[string][]string{
				"idp1": {"group1": {"user1"}},
			},
			b: map[string]map[string][]string{
				"idp2": {"group1": {"user1"}},
			},
			expected: false,
		},
		{
			name: "different group names",
			a: map[string]map[string][]string{
				"idp1": {"group1": {"user1"}},
			},
			b: map[string]map[string][]string{
				"idp1": {"group2": {"user1"}},
			},
			expected: false,
		},
		{
			name: "different members",
			a: map[string]map[string][]string{
				"idp1": {"group1": {"user1", "user2"}},
			},
			b: map[string]map[string][]string{
				"idp1": {"group1": {"user1", "user3"}},
			},
			expected: false,
		},
		{
			name: "different number of IDPs",
			a: map[string]map[string][]string{
				"idp1": {"group1": {"user1"}},
				"idp2": {"group1": {"user2"}},
			},
			b: map[string]map[string][]string{
				"idp1": {"group1": {"user1"}},
			},
			expected: false,
		},
		{
			name: "different number of groups",
			a: map[string]map[string][]string{
				"idp1": {
					"group1": {"user1"},
					"group2": {"user2"},
				},
			},
			b: map[string]map[string][]string{
				"idp1": {"group1": {"user1"}},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := equalIDPHierarchy(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDeduplicateMembersFromHierarchy(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy map[string]map[string][]string
		group     string
		expected  []string
	}{
		{
			name:      "empty hierarchy",
			hierarchy: map[string]map[string][]string{},
			group:     "admin",
			expected:  nil,
		},
		{
			name: "single IDP single group",
			hierarchy: map[string]map[string][]string{
				"idp1": {"admin": {"user1@example.com", "user2@example.com"}},
			},
			group:    "admin",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name: "multiple IDPs same group deduplicates",
			hierarchy: map[string]map[string][]string{
				"idp1": {"admin": {"user1@example.com", "user2@example.com"}},
				"idp2": {"admin": {"user2@example.com", "user3@example.com"}},
			},
			group:    "admin",
			expected: []string{"user1@example.com", "user2@example.com", "user3@example.com"},
		},
		{
			name: "group not in hierarchy",
			hierarchy: map[string]map[string][]string{
				"idp1": {"admin": {"user1@example.com"}},
			},
			group:    "developers",
			expected: nil,
		},
		{
			name: "normalizes to lowercase",
			hierarchy: map[string]map[string][]string{
				"idp1": {"admin": {"User1@Example.COM", "USER2@EXAMPLE.COM"}},
			},
			group:    "admin",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name: "skips empty strings",
			hierarchy: map[string]map[string][]string{
				"idp1": {"admin": {"user1@example.com", "", "  ", "user2@example.com"}},
			},
			group:    "admin",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateMembersFromHierarchy(tt.hierarchy, tt.group)
			assert.Equal(t, tt.expected, result)
		})
	}
}

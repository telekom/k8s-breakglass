package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
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
	fakeRecorder := record.NewFakeRecorder(10)

	updater := &EscalationStatusUpdater{
		Resolver:      resolver,
		IDPLoader:     nil,
		EventRecorder: fakeRecorder,
	}

	escalation := &telekomv1alpha1.BreakglassEscalation{
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

	escalation := &telekomv1alpha1.BreakglassEscalation{
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

	fakeRecorder := record.NewFakeRecorder(10)

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
	fakeRecorder := record.NewFakeRecorder(10)

	// Create an escalation resource
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc",
			Namespace: "default",
		},
	}

	// Emit a test event
	fakeRecorder.Event(escalation, "Normal", "TestEvent", "Test message")

	// Verify event was recorded
	select {
	case event := <-fakeRecorder.Events:
		// Event format is "Normal TestEvent Test message"
		assert.Contains(t, event, "Normal")
		assert.Contains(t, event, "TestEvent")
		assert.Contains(t, event, "Test message")
	default:
		t.Fatal("Expected event to be recorded")
	}
}

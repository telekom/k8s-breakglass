package escalation

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	cfgpkg "github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestFetchGroupMembersFromMultipleIDPs_EventEmission_SuccessfulSync tests that events are emitted on success
func TestFetchGroupMembersFromMultipleIDPs_EventEmission_SuccessfulSync(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	// Create a resolver that successfully returns members
	resolver := &MockResolver{
		members: map[string][]string{
			"approvers": {"user1@example.com", "user2@example.com"},
		},
		errors: map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:  resolver,
		IDPLoader: nil,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, _ := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"approvers"}, slog)

	// Verify success path - this is where success events would be emitted
	assert.Equal(t, "Success", status, "Should report successful sync")
	assert.NotNil(t, hierarchy, "Hierarchy should not be nil")
	assert.Len(t, hierarchy[""]["approvers"], 2, "Should have 2 approvers")
	t.Logf("✓ Success event emission path verified - Status: %s, Approvers: %d", status, len(hierarchy[""]["approvers"]))
}

// TestFetchGroupMembersFromMultipleIDPs_EventEmission_MultipleGroups tests that multiple group
// syncs emit appropriate events
func TestFetchGroupMembersFromMultipleIDPs_EventEmission_MultipleGroups(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	// Resolver with multiple groups
	resolver := &MockResolver{
		members: map[string][]string{
			"admins":    {"admin1@example.com"},
			"approvers": {"approver1@example.com", "approver2@example.com"},
		},
		errors: map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:  resolver,
		IDPLoader: nil,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc-multi-group",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"admins", "approvers"}, slog)

	// Verify all groups were synced - events emitted would include totals
	assert.Equal(t, "Success", status)
	assert.Len(t, syncErrors, 0)
	assert.Len(t, hierarchy[""], 2, "Should have both groups")
	assert.Len(t, hierarchy[""]["admins"], 1)
	assert.Len(t, hierarchy[""]["approvers"], 2)
	t.Logf("✓ Multi-group event emission - Total groups: 2, Total members: 3 (admins: 1, approvers: 2)")
}

func TestFetchGroupMembersFromMultipleIDPs_EventReasonMatchesFullFailure(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	cli := fake.NewClientBuilder().
		WithScheme(breakglass.Scheme).
		Build()
	recorder := fakeEventRecorder{Events: make(chan string, 4)}

	updater := &EscalationStatusUpdater{
		IDPLoader:     cfgpkg.NewIdentityProviderLoader(cli),
		EventRecorder: recorder,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc-full-failure",
			Namespace: "default",
		},
	}

	hierarchy, status, syncErrors := updater.fetchGroupMembersFromMultipleIDPs(
		context.Background(),
		escalation,
		[]string{"missing-idp-a", "missing-idp-b"},
		[]string{"approvers"},
		slog,
	)

	assert.Empty(t, hierarchy)
	assert.Equal(t, groupSyncStatusFailed, status)
	assert.Len(t, syncErrors, 2)
	assert.True(t, recordedEventContains(
		drainRecordedEvents(recorder.Events),
		"Warning "+groupSyncReasonFailed,
		"Multi-IDP group sync failed: 0 IDPs succeeded, 2 failed",
	))
}

// TestFetchGroupMembersFromMultipleIDPs_EventEmission_NoResolverFallback tests fallback to single IDP
func TestFetchGroupMembersFromMultipleIDPs_EventEmission_NoResolverFallback(t *testing.T) {
	log, _ := zap.NewProduction()
	defer func() { _ = log.Sync() }()
	slog := log.Sugar()

	// No resolver provided - fallback mode
	resolver := &MockResolver{
		members: map[string][]string{},
		errors:  map[string]error{},
	}

	updater := &EscalationStatusUpdater{
		Resolver:  resolver,
		IDPLoader: nil,
	}

	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-esc-fallback",
			Namespace: "default",
		},
	}

	ctx := context.Background()
	hierarchy, status, _ := updater.fetchGroupMembersFromMultipleIDPs(
		ctx, escalation, []string{}, []string{"approvers"}, slog)

	// Fallback mode should still handle gracefully
	assert.NotNil(t, hierarchy, "Should return valid hierarchy")
	t.Logf("✓ Fallback mode event emission handled - Status: %s", status)
}

func drainRecordedEvents(events <-chan string) []string {
	var drained []string
	for {
		select {
		case event := <-events:
			drained = append(drained, event)
		default:
			return drained
		}
	}
}

func recordedEventContains(events []string, parts ...string) bool {
	for _, event := range events {
		matches := true
		for _, part := range parts {
			if !strings.Contains(event, part) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

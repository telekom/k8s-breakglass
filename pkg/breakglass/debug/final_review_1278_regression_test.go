package debug

import (
	"context"
	"strconv"
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFinalReviewDigestRejectsDifferentArgs(t *testing.T) {
	a := desiredEphemeralContainerForIntent("debugger", "busybox", []string{"sh"}, nil)
	b := a.DeepCopy()
	b.Args = []string{"-c", "different command"}
	if ephemeralContainerDigest(&a) == ephemeralContainerDigest(b) {
		t.Fatal("different execution args accepted as exact intent")
	}
}
func TestFinalReviewFreshIntentSurvivesCleanup(t *testing.T) {
	ds := newEphemeralOperationTestSession()
	ds.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{ID: "fresh", Kind: kubectlDebugOperationKindEphemeralContainer, State: breakglassv1alpha1.KubectlDebugOperationPrepared, PreparedAt: metav1.Now()}}}
	scheme := newKubectlTestScheme()
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	target := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": target}})
	if err := h.CleanupKubectlDebugResources(context.Background(), ds); err != nil {
		t.Fatal(err)
	}
	if findKubectlDebugOperation(&ds.Status, "fresh") == nil {
		t.Fatal("fresh durable intent erased by cleanup")
	}
}
func TestFinalReviewNodeAffinityRejectsGtMismatch(t *testing.T) {
	selector := &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "size", Operator: corev1.NodeSelectorOpGt, Values: []string{"10"}}}}}}
	if nodeMatchesRequiredSelectorForNode(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", Labels: map[string]string{"size": "1"}}}, selector) {
		t.Fatal("node failing required Gt constraint accepted")
	}
}

func TestFinalReviewDigestRejectsVolumeMount(t *testing.T) {
	a := desiredEphemeralContainerForIntent("debugger", "busybox", nil, nil)
	b := a.DeepCopy()
	b.VolumeMounts = []corev1.VolumeMount{{Name: "credentials", MountPath: "/credentials"}}
	if ephemeralContainerDigest(&a) == ephemeralContainerDigest(b) {
		t.Fatal("different volume access accepted as exact request")
	}
}

func TestFinalReviewDigestRejectsVolumeDevice(t *testing.T) {
	a := desiredEphemeralContainerForIntent("debugger", "busybox", nil, nil)
	b := a.DeepCopy()
	b.VolumeDevices = []corev1.VolumeDevice{{Name: "data", DevicePath: "/dev/data"}}
	if ephemeralContainerDigest(&a) == ephemeralContainerDigest(b) {
		t.Fatal("different block-device access accepted as exact request")
	}
}

func TestFinalReviewShortSessionDoesNotPanic(t *testing.T) {
	ds := newEphemeralOperationTestSession()
	ds.Name = "short"
	ds.Status.ResolvedTemplate.KubectlDebug.PodCopy = &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "default"}
	scheme := newKubectlTestScheme()
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ds).WithStatusSubresource(ds).Build()
	target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "pod"}},
	).Build()
	h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": target}})
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("short valid session name panics: %v", recovered)
		}
	}()
	_, _ = h.CreatePodCopy(context.Background(), ds, "default", "target", "busybox", ds.Spec.RequestedBy)
}

func TestFinalReviewStatusRetryReadsThroughLiveReader(t *testing.T) {
	live := newEphemeralOperationTestSession()
	live.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{ID: "live"}}}
	cached := live.DeepCopy()
	cached.Status.KubectlDebugStatus = nil
	scheme := newKubectlTestScheme()
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cached).WithStatusSubresource(cached).Build()
	liveClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).WithStatusSubresource(live).Build()
	h := NewKubectlDebugHandler(cachedClient, nil).WithAPIReader(liveClient)
	err := h.patchDebugSessionStatusWithRetry(context.Background(), cached, func(status *breakglassv1alpha1.DebugSessionStatus) {
		ensureKubectlDebugStatus(status).Operations = append(ensureKubectlDebugStatus(status).Operations, breakglassv1alpha1.KubectlDebugOperation{ID: "new"})
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := &breakglassv1alpha1.DebugSession{}
	if err := cachedClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(cached), stored); err != nil {
		t.Fatal(err)
	}
	if findKubectlDebugOperation(&stored.Status, "live") == nil {
		t.Fatal("status retry discarded live operation evidence")
	}
}

func TestFinalReviewKubectlStatusMergeRetainsOperationsOnly(t *testing.T) {
	operation := breakglassv1alpha1.KubectlDebugOperation{ID: "operation-only", State: breakglassv1alpha1.KubectlDebugOperationUnknown}
	merged := mergeKubectlDebugStatus(
		&breakglassv1alpha1.KubectlDebugStatus{},
		&breakglassv1alpha1.KubectlDebugStatus{},
		&breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{operation}},
	)
	if merged == nil || findKubectlDebugOperation(&breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: merged}, operation.ID) == nil {
		t.Fatal("operations-only status evidence was discarded")
	}
}

func TestFinalReviewKubectlStatusMergeRetainsConcurrentTerminalOutcome(t *testing.T) {
	baseline := &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{ID: "racing", State: breakglassv1alpha1.KubectlDebugOperationPrepared}}}
	current := &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{ID: "racing", State: breakglassv1alpha1.KubectlDebugOperationCompleted}}}
	merged := mergeKubectlDebugStatus(baseline, &breakglassv1alpha1.KubectlDebugStatus{}, current)
	operation := findKubectlDebugOperation(&breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: merged}, "racing")
	if operation == nil || operation.State != breakglassv1alpha1.KubectlDebugOperationCompleted {
		t.Fatal("concurrent terminal operation outcome was discarded")
	}
}

func assertOperationMergeAdmission(t *testing.T, current, merged []breakglassv1alpha1.KubectlDebugOperation) {
	t.Helper()
	before := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "alice"}, Status: breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{Operations: current}}}
	after := before.DeepCopy()
	after.Status.KubectlDebugStatus.Operations = merged
	if _, err := after.ValidateUpdate(context.Background(), before, after); err != nil {
		t.Fatalf("merged status rejected by admission: %v", err)
	}
}

func TestFinalReviewKubectlStatusMergePreservesCurrentOrderAndCompaction(t *testing.T) {
	// The baseline Prepared operation completed and was compacted before this stale writer retried.
	baseline := []breakglassv1alpha1.KubectlDebugOperation{{ID: "compacted-prepared", State: breakglassv1alpha1.KubectlDebugOperationPrepared}}
	current := []breakglassv1alpha1.KubectlDebugOperation{{ID: "newer-terminal", State: breakglassv1alpha1.KubectlDebugOperationCompleted}}
	merged := mergeKubectlDebugOperations(baseline, baseline, current)
	if len(merged) != 1 || merged[0].ID != "newer-terminal" {
		t.Fatalf("stale Prepared operation resurrected: %#v", merged)
	}
	assertOperationMergeAdmission(t, current, merged)
}

func TestFinalReviewKubectlStatusMergeDefersConcurrentFinalization(t *testing.T) {
	baseline := []breakglassv1alpha1.KubectlDebugOperation{
		{ID: "prepared", State: breakglassv1alpha1.KubectlDebugOperationPrepared, PreparedAt: metav1.Now()},
		{ID: "old-terminal", State: breakglassv1alpha1.KubectlDebugOperationCompleted},
	}
	desired := append([]breakglassv1alpha1.KubectlDebugOperation{}, baseline...)
	desired[0].State = breakglassv1alpha1.KubectlDebugOperationCompleted
	desired[0].CompletedAt = debugPtrTime(metav1.Now())
	merged := mergeKubectlDebugOperations(baseline, desired, baseline)
	if len(merged) != 2 || merged[0].ID != "old-terminal" || merged[1].ID != "prepared" || merged[1].State != breakglassv1alpha1.KubectlDebugOperationCompleted {
		t.Fatalf("merged operation order = %#v, want retained terminal followed by finalized operation", merged)
	}
	assertOperationMergeAdmission(t, baseline, merged)
}

func TestFinalReviewKubectlOperationHistoryBoundsTerminalEvidence(t *testing.T) {
	operations := []breakglassv1alpha1.KubectlDebugOperation{{
		ID: "prepared", State: breakglassv1alpha1.KubectlDebugOperationPrepared,
	}}
	for i := 0; i < breakglassv1alpha1.MaxKubectlDebugOperationHistory+3; i++ {
		operations = append(operations, breakglassv1alpha1.KubectlDebugOperation{
			ID: "terminal-" + strconv.Itoa(i), State: breakglassv1alpha1.KubectlDebugOperationCompleted,
		})
	}
	retained := terminalKubectlDebugOperations(operations)
	if len(retained) != breakglassv1alpha1.MaxKubectlDebugOperationHistory+1 {
		t.Fatalf("retained %d operations, want %d", len(retained), breakglassv1alpha1.MaxKubectlDebugOperationHistory+1)
	}
	if retained[0].ID != "prepared" || retained[1].ID != "terminal-3" {
		t.Fatalf("retained operation order = %#v, want prepared followed by newest terminal evidence", retained)
	}
}

func TestFinalReviewCompletionRetainsNewlyFinalizedOperationAtHistoryLimit(t *testing.T) {
	session := newEphemeralOperationTestSession()
	prepared := breakglassv1alpha1.KubectlDebugOperation{ID: "prepared", Kind: kubectlDebugOperationKindEphemeralContainer, State: breakglassv1alpha1.KubectlDebugOperationPrepared, PreparedAt: metav1.Now()}
	operations := []breakglassv1alpha1.KubectlDebugOperation{prepared}
	for i := 0; i < breakglassv1alpha1.MaxKubectlDebugOperationHistory; i++ {
		operations = append(operations, breakglassv1alpha1.KubectlDebugOperation{ID: "terminal-" + strconv.Itoa(i), State: breakglassv1alpha1.KubectlDebugOperationCompleted, CompletedAt: debugPtrTime(metav1.Now())})
	}
	session.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: operations}
	scheme := newKubectlTestScheme()
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	h := NewKubectlDebugHandler(hub, nil)
	before := &breakglassv1alpha1.DebugSession{}
	if err := hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), before); err != nil {
		t.Fatal(err)
	}
	if err := h.completeEphemeralContainerOperation(context.Background(), session, prepared.ID, breakglassv1alpha1.KubectlDebugOperationFailed, "failed", nil); err != nil {
		t.Fatal(err)
	}
	stored := &breakglassv1alpha1.DebugSession{}
	if err := hub.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored); err != nil {
		t.Fatal(err)
	}
	assertOperationMergeAdmission(t, before.Status.KubectlDebugStatus.Operations, stored.Status.KubectlDebugStatus.Operations)
	if findKubectlDebugOperation(&stored.Status, prepared.ID) == nil {
		t.Fatal("newly finalized operation was compacted")
	}
	if len(stored.Status.KubectlDebugStatus.Operations) != breakglassv1alpha1.MaxKubectlDebugOperationHistory {
		t.Fatalf("terminal history length = %d, want %d", len(stored.Status.KubectlDebugStatus.Operations), breakglassv1alpha1.MaxKubectlDebugOperationHistory)
	}
}

func debugPtrTime(value metav1.Time) *metav1.Time { return &value }

func TestFinalReviewRecoveryGraceCoversSlowMutationRequest(t *testing.T) {
	session := newEphemeralOperationTestSession()
	session.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{
		ID: "slow-request", Kind: kubectlDebugOperationKindEphemeralContainer, State: breakglassv1alpha1.KubectlDebugOperationPrepared,
		PreparedAt: metav1.NewTime(time.Now().Add(-ephemeralOperationRecoveryGrace + time.Second)),
	}}}
	scheme := newKubectlTestScheme()
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	target := fake.NewClientBuilder().WithScheme(scheme).Build()
	h := NewKubectlDebugHandler(hub, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": target}})
	if err := h.RecoverPendingKubectlDebugOperations(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if operation := findKubectlDebugOperation(&session.Status, "slow-request"); operation == nil || operation.State != breakglassv1alpha1.KubectlDebugOperationPrepared {
		t.Fatal("recovery finalized an operation while its API mutation grace was still active")
	}
}

func TestFinalReviewReconcilerKubectlRecoveryUsesLiveReader(t *testing.T) {
	scheme := newKubectlTestScheme()
	cached := fake.NewClientBuilder().WithScheme(scheme).Build()
	live := fake.NewClientBuilder().WithScheme(scheme).Build()
	controller := &DebugSessionController{client: cached, reader: live, apiReader: live}
	handler := controller.newKubectlDebugHandler()
	if handler.reader != live {
		t.Fatal("reconciler kubectl recovery is still wired to the cache reader")
	}
}

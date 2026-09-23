package v1alpha1

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func testKubectlOperation(id string, state KubectlDebugOperationState) KubectlDebugOperation {
	return KubectlDebugOperation{
		ID: id, Kind: "ephemeral-container", State: state,
		TargetPod:          KubectlDebugOperationTargetPod{Namespace: "default", Name: "pod", UID: types.UID("pod-uid")},
		EphemeralContainer: KubectlDebugEphemeralContainerIntent{Name: "debugger", Image: "busybox", ContainerDigest: "container-digest", SecurityContextDigest: "security-digest"},
		RequestedBy:        "alice", PreparedAt: metav1.Now(),
	}
}

func validateOperationUpdate(t *testing.T, oldOperations, newOperations []KubectlDebugOperation) error {
	t.Helper()
	oldSession := &DebugSession{Spec: DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "alice"}, Status: DebugSessionStatus{KubectlDebugStatus: &KubectlDebugStatus{Operations: oldOperations}}}
	newSession := oldSession.DeepCopy()
	newSession.Status.KubectlDebugStatus.Operations = newOperations
	_, err := newSession.ValidateUpdate(context.Background(), oldSession, newSession)
	return err
}

func TestDebugSessionValidateUpdateKubectlOperationsAdmission(t *testing.T) {
	prepared := testKubectlOperation("prepared", KubectlDebugOperationPrepared)
	terminal := prepared
	terminal.State = KubectlDebugOperationCompleted
	terminal.CompletedAt = ptrTime(metav1.Now())

	tests := []struct {
		name string
		old  []KubectlDebugOperation
		new  []KubectlDebugOperation
		want bool
	}{
		{"prepared deletion", []KubectlDebugOperation{prepared}, nil, true},
		{"prepared intent mutation", []KubectlDebugOperation{prepared}, []KubectlDebugOperation{{ID: prepared.ID, Kind: prepared.Kind, State: KubectlDebugOperationPrepared, TargetPod: prepared.TargetPod, EphemeralContainer: prepared.EphemeralContainer, RequestedBy: "mallory", PreparedAt: prepared.PreparedAt}}, true},
		{"new terminal", nil, []KubectlDebugOperation{terminal}, true},
		{"duplicate IDs", []KubectlDebugOperation{prepared}, []KubectlDebugOperation{prepared, prepared}, true},
		{"valid completion", []KubectlDebugOperation{prepared}, []KubectlDebugOperation{terminal}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateOperationUpdate(t, tt.old, tt.new); (err != nil) != tt.want {
				t.Fatalf("ValidateUpdate() error = %v, want error %v", err, tt.want)
			}
		})
	}
}

func TestDebugSessionValidateUpdateKubectlOperationCompaction(t *testing.T) {
	old := make([]KubectlDebugOperation, 0, MaxKubectlDebugOperationHistory)
	for i := 0; i < MaxKubectlDebugOperationHistory; i++ {
		old = append(old, testKubectlOperation(string(rune('a'+i)), KubectlDebugOperationCompleted))
	}
	prepared := testKubectlOperation("prepared", KubectlDebugOperationPrepared)
	old = append(old, prepared)
	completed := prepared
	completed.State = KubectlDebugOperationCompleted
	completed.CompletedAt = ptrTime(metav1.Now())
	newOperations := append([]KubectlDebugOperation{}, old[1:]...)
	newOperations[len(newOperations)-1] = completed
	if err := validateOperationUpdate(t, old, newOperations); err != nil {
		t.Fatalf("valid oldest-terminal compaction rejected: %v", err)
	}
	nonPrefix := append([]KubectlDebugOperation{}, old[:1]...)
	nonPrefix = append(nonPrefix, old[2:]...)
	nonPrefix[len(nonPrefix)-1] = completed
	if err := validateOperationUpdate(t, old, nonPrefix); err == nil {
		t.Fatal("non-prefix terminal compaction accepted")
	}
}

func TestDebugSessionValidateUpdateKubectlOperationCleanupRaceResult(t *testing.T) {
	oldTerminals := make([]KubectlDebugOperation, 0, MaxKubectlDebugOperationHistory+1)
	for i := 0; i < MaxKubectlDebugOperationHistory+1; i++ {
		oldTerminals = append(oldTerminals, testKubectlOperation("terminal-"+string(rune('a'+i)), KubectlDebugOperationCompleted))
	}
	prepared := testKubectlOperation("prepared", KubectlDebugOperationPrepared)
	completed := prepared
	completed.State = KubectlDebugOperationCompleted
	completed.CompletedAt = ptrTime(metav1.Now())
	old := append(append([]KubectlDebugOperation{}, oldTerminals...), prepared)
	current := append(append([]KubectlDebugOperation{}, oldTerminals[2:]...), completed)
	if err := validateOperationUpdate(t, old, current); err != nil {
		t.Fatalf("cleanup race completion rejected: %v", err)
	}
	if err := validateOperationUpdate(t, old, append([]KubectlDebugOperation{completed}, oldTerminals[2:]...)); err == nil {
		t.Fatal("cleanup race reordered retained terminal evidence")
	}
}

func ptrTime(value metav1.Time) *metav1.Time { return &value }

func TestDebugSessionValidateUpdateRejectsTerminalSwapWithoutCompaction(t *testing.T) {
	first := testKubectlOperation("first", KubectlDebugOperationCompleted)
	second := testKubectlOperation("second", KubectlDebugOperationCompleted)
	old := []KubectlDebugOperation{first, second}
	if err := validateOperationUpdate(t, old, old); err != nil {
		t.Fatalf("unchanged history rejected: %v", err)
	}
	if err := validateOperationUpdate(t, old, []KubectlDebugOperation{second, first}); err == nil {
		t.Fatal("retained terminal swap accepted without compaction")
	}
}

func TestDebugSessionValidateUpdateExpiredOperationOutcomeOnly(t *testing.T) {
	old := &DebugSession{
		Spec: DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "alice"},
		Status: DebugSessionStatus{
			State:     DebugSessionStateActive,
			ExpiresAt: ptrTime(metav1.NewTime(time.Now().Add(-time.Minute))),
			KubectlDebugStatus: &KubectlDebugStatus{Operations: []KubectlDebugOperation{
				testKubectlOperation("failed", KubectlDebugOperationPrepared),
				testKubectlOperation("still-prepared", KubectlDebugOperationPrepared),
			}},
		},
	}
	valid := old.DeepCopy()
	valid.Status.KubectlDebugStatus.Operations[0].State = KubectlDebugOperationFailed
	valid.Status.KubectlDebugStatus.Operations[0].CompletedAt = ptrTime(metav1.Now())
	valid.Status.KubectlDebugStatus.Operations[0].Message = "expired before target write"
	tests := []struct {
		name   string
		mutate func(*DebugSession)
	}{
		{"session message", func(s *DebugSession) { s.Status.Message = "changed" }},
		{"expiry", func(s *DebugSession) { s.Status.ExpiresAt = ptrTime(metav1.NewTime(time.Now().Add(time.Hour))) }},
		{"participant", func(s *DebugSession) { s.Status.Participants = []DebugSessionParticipant{{User: "mallory"}} }},
		{"subsecond expiry", func(s *DebugSession) {
			s.Status.ExpiresAt = ptrTime(metav1.NewTime(s.Status.ExpiresAt.Add(time.Nanosecond)))
		}},
		{"allowed pod", func(s *DebugSession) { s.Status.AllowedPods = []AllowedPodRef{{Name: "another", Namespace: "default"}} }},
		{"injected reference", func(s *DebugSession) {
			s.Status.KubectlDebugStatus.EphemeralContainersInjected = []EphemeralContainerRef{{ContainerName: "another"}}
		}},
		{"copied reference", func(s *DebugSession) { s.Status.KubectlDebugStatus.CopiedPods = []CopiedPodRef{{}} }},
		{"new prepared", func(s *DebugSession) {
			s.Status.KubectlDebugStatus.Operations = append(s.Status.KubectlDebugStatus.Operations, testKubectlOperation("new", KubectlDebugOperationPrepared))
		}},
		{"missing completion timestamp", func(s *DebugSession) { s.Status.KubectlDebugStatus.Operations[0].CompletedAt = nil }},
		{"changed intent", func(s *DebugSession) { s.Status.KubectlDebugStatus.Operations[0].RequestedBy = "mallory" }},
		{"retained prepared message", func(s *DebugSession) { s.Status.KubectlDebugStatus.Operations[1].Message = "changed" }},
		{"retained prepared timestamp", func(s *DebugSession) { s.Status.KubectlDebugStatus.Operations[1].CompletedAt = ptrTime(metav1.Now()) }},
		{"spec", func(s *DebugSession) { s.Spec.RequestedBy = "mallory" }},
	}
	for _, outcome := range []KubectlDebugOperationState{KubectlDebugOperationFailed, KubectlDebugOperationUnknown, KubectlDebugOperationCompleted} {
		candidate := valid.DeepCopy()
		candidate.Status.KubectlDebugStatus.Operations[0].State = outcome
		if _, err := candidate.ValidateUpdate(context.Background(), old, candidate); err != nil {
			t.Fatalf("evidence-only %s rejected: %v", outcome, err)
		}
		if AllowsExpiredActiveEphemeralOperationFailure(old.Status, candidate.Status, time.Now()) != (outcome == KubectlDebugOperationFailed) {
			t.Fatal("failure-only compatibility predicate changed")
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid := valid.DeepCopy()
			tt.mutate(invalid)
			if _, err := invalid.ValidateUpdate(context.Background(), old, invalid); err == nil {
				t.Fatal("unrelated change accepted alongside expired operation failure")
			}
		})
	}
}

func TestDebugSessionValidateUpdateExpiredFailureCompaction(t *testing.T) {
	old := &DebugSession{
		Spec:   DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "alice"},
		Status: DebugSessionStatus{State: DebugSessionStateActive, ExpiresAt: ptrTime(metav1.NewTime(time.Now().Add(-time.Minute))), KubectlDebugStatus: &KubectlDebugStatus{}},
	}
	for i := 0; i < MaxKubectlDebugOperationHistory; i++ {
		old.Status.KubectlDebugStatus.Operations = append(old.Status.KubectlDebugStatus.Operations, testKubectlOperation(string(rune('a'+i)), KubectlDebugOperationCompleted))
	}
	prepared := testKubectlOperation("prepared", KubectlDebugOperationPrepared)
	old.Status.KubectlDebugStatus.Operations = append(old.Status.KubectlDebugStatus.Operations, prepared)
	valid := old.DeepCopy()
	valid.Status.KubectlDebugStatus.Operations = valid.Status.KubectlDebugStatus.Operations[1:]
	finalized := &valid.Status.KubectlDebugStatus.Operations[len(valid.Status.KubectlDebugStatus.Operations)-1]
	finalized.State = KubectlDebugOperationFailed
	finalized.CompletedAt = ptrTime(metav1.Now())
	if _, err := valid.ValidateUpdate(context.Background(), old, valid); err != nil {
		t.Fatalf("valid oldest-terminal compaction rejected: %v", err)
	}
	invalid := valid.DeepCopy()
	invalid.Status.KubectlDebugStatus.Operations[0], invalid.Status.KubectlDebugStatus.Operations[1] = invalid.Status.KubectlDebugStatus.Operations[1], invalid.Status.KubectlDebugStatus.Operations[0]
	if _, err := invalid.ValidateUpdate(context.Background(), old, invalid); err == nil {
		t.Fatal("terminal reorder accepted with expired operation failure")
	}
}

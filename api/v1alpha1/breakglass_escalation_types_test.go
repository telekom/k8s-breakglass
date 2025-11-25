package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBreakglassEscalation_ValidateCreate_MissingFields(t *testing.T) {
	be := &BreakglassEscalation{}
	_, err := be.ValidateCreate(context.Background(), be)
	if err == nil {
		t.Fatalf("expected ValidateCreate to fail when required fields missing")
	}
}

func TestBreakglassEscalation_ValidateCreate_Success(t *testing.T) {
	be := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "some-group",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"cluster-a"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	_, err := be.ValidateCreate(context.Background(), be)
	if err != nil {
		t.Fatalf("expected ValidateCreate to succeed, got %v", err)
	}
}

func TestBreakglassEscalation_ValidateUpdate_Immutable(t *testing.T) {
	old := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-2"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "g1",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"c1"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}
	modified := old.DeepCopy()
	modified.Spec.EscalatedGroup = "g2"
	// spec immutability no longer enforced; update should succeed
	_, err := modified.ValidateUpdate(context.Background(), old, modified)
	if err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec changed, got %v", err)
	}
	_, err = old.ValidateUpdate(context.Background(), old, old)
	if err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec unchanged, got %v", err)
	}
}

func TestBreakglassEscalationSetAndGetCondition(t *testing.T) {
	be := &BreakglassEscalation{}
	cond := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Init"}

	be.SetCondition(cond)
	if got := be.GetCondition("Ready"); got == nil || got.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready condition to be stored, got %#v", got)
	}

	updated := metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "NotReady"}
	be.SetCondition(updated)
	got := be.GetCondition("Ready")
	if got == nil || got.Status != metav1.ConditionFalse || got.Reason != "NotReady" {
		t.Fatalf("expected updated Ready condition, got %#v", got)
	}
}

func TestBreakglassEscalationGetConditionMissing(t *testing.T) {
	be := &BreakglassEscalation{}
	if be.GetCondition("Unknown") != nil {
		t.Fatal("expected missing condition to return nil")
	}
}

func TestBreakglassEscalationValidateDelete(t *testing.T) {
	esc := &BreakglassEscalation{}
	warnings, err := esc.ValidateDelete(context.Background(), esc)
	if err != nil || warnings != nil {
		t.Fatalf("expected ValidateDelete to allow deletes, warnings=%v err=%v", warnings, err)
	}
}

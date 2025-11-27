package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

func TestBreakglassEscalationClusterConfigRefsSatisfyClusterRequirement(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "team-a"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "kc", Namespace: "system"},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clusterConfig).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup:    "ops",
			Allowed:           BreakglassEscalationAllowed{},
			Approvers:         BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			ClusterConfigRefs: []string{"cluster-a"},
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected ValidateCreate to succeed when clusterConfigRefs present, got %v", err)
	}
}

func TestBreakglassEscalationClusterConfigRefsMissingAreDeferredToController(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed:        BreakglassEscalationAllowed{Groups: []string{"requesters"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			// intentionally reference a ClusterConfig that doesn't exist yet
			ClusterConfigRefs: []string{"cluster-a"},
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected webhook to accept missing clusterConfigRefs, got %v", err)
	}
}

func TestBreakglassEscalationDenyPolicyRefsAreDeferredToController(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			DenyPolicyRefs: []string{"missing"},
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected webhook to accept missing denyPolicyRefs, got %v", err)
	}
}

func TestBreakglassEscalationDenyPolicyRefsClusterScoped(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	policy := &DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			DenyPolicyRefs: []string{"policy-a"},
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected success when referencing cluster-scoped DenyPolicy, got %v", err)
	}
}

func TestBreakglassEscalationMailProviderCanBeMissingDuringAdmission(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-a"},
			},
			Approvers:    BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			MailProvider: "mail-custom",
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected webhook to accept missing mailProvider reference, got %v", err)
	}
}

func TestBreakglassEscalationMailProviderDisabledIsDeferredToController(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	disabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-disabled"},
		Spec: MailProviderSpec{
			Disabled: true,
			SMTP:     SMTPConfig{Host: "smtp.disabled", Port: 587},
			Sender:   SenderConfig{Address: "noreply@disabled"},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledMail).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"cluster-a"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			MailProvider:   "mail-disabled",
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected webhook to accept disabled MailProvider reference, got %v", err)
	}
}

func TestBreakglassEscalationMailProviderHappyPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	enabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-enabled"},
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.enabled", Port: 587},
			Sender: SenderConfig{Address: "noreply@enabled"},
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledMail).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	esc := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "team-a"},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "ops",
			Allowed:        BreakglassEscalationAllowed{Clusters: []string{"cluster-a"}},
			Approvers:      BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			MailProvider:   "mail-enabled",
		},
	}

	if _, err := esc.ValidateCreate(context.Background(), esc); err != nil {
		t.Fatalf("expected success when referencing enabled MailProvider, got %v", err)
	}
}

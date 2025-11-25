package v1alpha1

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestClusterConfig_ValidateCreate_MissingSecretRef(t *testing.T) {
	cc := &ClusterConfig{}
	_, err := cc.ValidateCreate(context.Background(), cc)
	if err == nil {
		t.Fatalf("expected ValidateCreate to fail when kubeconfig secret ref missing")
	}
}

func TestClusterConfig_ValidateCreate_Success(t *testing.T) {
	cc := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-1"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
		},
	}
	_, err := cc.ValidateCreate(context.Background(), cc)
	if err != nil {
		t.Fatalf("expected ValidateCreate to succeed, got %v", err)
	}
}

func TestClusterConfig_ValidateCreate_DuplicateIdentityProviderRefs(t *testing.T) {
	cc := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-dup"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef:  SecretKeyReference{Name: "k", Namespace: "ns"},
			IdentityProviderRefs: []string{"idp-a", "idp-a"},
		},
	}

	_, err := cc.ValidateCreate(context.Background(), cc)
	if err == nil {
		t.Fatalf("expected ValidateCreate to fail due to duplicate identityProviderRefs")
	}
}

func TestClusterConfig_ValidateCreate_InvalidApproverDomains(t *testing.T) {
	cc := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-domain"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef:    SecretKeyReference{Name: "k", Namespace: "ns"},
			AllowedApproverDomains: []string{"invalid_domain"},
		},
	}

	_, err := cc.ValidateCreate(context.Background(), cc)
	if err == nil {
		t.Fatalf("expected ValidateCreate to fail due to invalid approver domain")
	}
}

func TestClusterConfig_ValidateCreate_MailProviderReference(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	enabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-enabled"},
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 587},
			Sender: SenderConfig{Address: "noreply@example.com"},
		},
	}

	disabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-disabled"},
		Spec: MailProviderSpec{
			Disabled: true,
			SMTP:     SMTPConfig{Host: "smtp.disabled.com", Port: 587},
			Sender:   SenderConfig{Address: "noreply-disabled@example.com"},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledMail, disabledMail).Build()
	webhookClient = client
	defer func() {
		webhookClient = nil
		webhookCache = nil
	}()

	valid := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-mail-valid"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
			MailProvider:        "mail-enabled",
		},
	}

	if _, err := valid.ValidateCreate(context.Background(), valid); err != nil {
		t.Fatalf("expected valid mail provider reference, got error: %v", err)
	}

	disabled := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-mail-disabled"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
			MailProvider:        "mail-disabled",
		},
	}

	if _, err := disabled.ValidateCreate(context.Background(), disabled); err == nil {
		t.Fatalf("expected error when referencing disabled MailProvider")
	}

	missing := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-mail-missing"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
			MailProvider:        "does-not-exist",
		},
	}

	if _, err := missing.ValidateCreate(context.Background(), missing); err == nil {
		t.Fatalf("expected error when referencing non-existent MailProvider")
	}
}

func TestClusterConfig_ValidateUpdate_Immutable(t *testing.T) {
	old := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cc-2"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{Name: "k", Namespace: "ns"},
		},
	}
	modified := old.DeepCopy()
	modified.Spec.QPS = func() *int32 { v := int32(10); return &v }()
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

func TestClusterConfigSetAndGetCondition(t *testing.T) {
	cc := &ClusterConfig{}
	cond := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue}
	cc.SetCondition(cond)
	if got := cc.GetCondition("Ready"); got == nil || got.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready condition to be stored, got %#v", got)
	}
	cc.SetCondition(metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse})
	if got := cc.GetCondition("Ready"); got == nil || got.Status != metav1.ConditionFalse {
		t.Fatalf("expected Ready condition to be updated, got %#v", got)
	}
}

func TestClusterConfigGetConditionMissing(t *testing.T) {
	cc := &ClusterConfig{}
	if cc.GetCondition("does-not-exist") != nil {
		t.Fatal("expected missing condition to return nil")
	}
}

func TestClusterConfigValidateDelete(t *testing.T) {
	cc := &ClusterConfig{}
	warnings, err := cc.ValidateDelete(context.Background(), cc)
	if err != nil || warnings != nil {
		t.Fatalf("expected ValidateDelete to allow deletes, warnings=%v err=%v", warnings, err)
	}
}

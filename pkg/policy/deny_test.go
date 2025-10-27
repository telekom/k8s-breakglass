package policy

import (
	"context"
	"testing"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEvaluatorMatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{}
	pol.Name = "deny-secrets"
	pol.Spec = telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{
		Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: []string{"*"},
	}}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	log := zap.NewNop().Sugar()
	eval := NewEvaluator(c, log)

	denied, name, err := eval.Match(context.Background(), Action{Verb: "get", APIGroup: "", Resource: "secrets", Namespace: "foo"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !denied {
		t.Fatalf("expected denied")
	}
	if name != "deny-secrets" {
		t.Fatalf("expected policy name deny-secrets got %s", name)
	}

	denied, _, err = eval.Match(context.Background(), Action{Verb: "list", APIGroup: "", Resource: "secrets", Namespace: "foo"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if denied {
		t.Fatalf("expected allowed")
	}
}

func TestEvaluatorWildcards(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)
	// Build multiple policies exercising wildcard semantics.
	pols := []runtime.Object{
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-verb-secret"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: []string{"ops-*"}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-configmap-specific-name"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"prod-*"}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-subresource-status"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"update"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Subresources: []string{"status"}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-resource"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"delete"}, APIGroups: []string{"*"}, Resources: []string{"*"}, Namespaces: []string{"*"}}}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(pols...).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	cases := []struct {
		name    string
		act     Action
		want    bool
		wantPol string
	}{
		{"secret any verb wildcard ns match", Action{Verb: "list", APIGroup: "", Resource: "secrets", Namespace: "ops-eu1"}, true, "deny-any-verb-secret"},
		{"secret different ns no match", Action{Verb: "get", APIGroup: "", Resource: "secrets", Namespace: "team-a"}, false, ""},
		{"configmap resource name wildcard", Action{Verb: "get", APIGroup: "", Resource: "configmaps", Namespace: "default", Name: "prod-config"}, true, "deny-configmap-specific-name"},
		{"configmap resource name no match", Action{Verb: "get", APIGroup: "", Resource: "configmaps", Namespace: "default", Name: "dev-config"}, false, ""},
		{"deployment status subresource", Action{Verb: "update", APIGroup: "apps", Resource: "deployments", Namespace: "default", Subresource: "status"}, true, "deny-any-subresource-status"},
		{"deployment main resource not status", Action{Verb: "update", APIGroup: "apps", Resource: "deployments", Namespace: "default"}, false, ""},
		{"any resource delete wildcard", Action{Verb: "delete", APIGroup: "batch", Resource: "jobs", Namespace: "ns1"}, true, "deny-any-resource"},
	}
	for _, tc := range cases {
		denied, pol, err := eval.Match(context.Background(), tc.act)
		if err != nil {
			t.Fatalf("%s: unexpected err: %v", tc.name, err)
		}
		if denied != tc.want {
			t.Fatalf("%s: expected denied=%v got %v (policy %s)", tc.name, tc.want, denied, pol)
		}
		if pol != tc.wantPol {
			t.Fatalf("%s: expected policy %q got %q", tc.name, tc.wantPol, pol)
		}
	}
}

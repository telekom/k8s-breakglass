package policy

import (
	"context"
	"strings"
	"testing"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEvaluatorMatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{}
	pol.Name = "deny-secrets"
	pol.Spec = telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{
		Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"*"}},
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
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-verb-secret"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"ops-*"}}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-configmap-specific-name"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"prod-*"}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-subresource-status"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"update"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Subresources: []string{"status"}}}}},
		&telekomv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-resource"}, Spec: telekomv1alpha1.DenyPolicySpec{Rules: []telekomv1alpha1.DenyRule{{Verbs: []string{"delete"}, APIGroups: []string{"*"}, Resources: []string{"*"}, Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"*"}}}}}},
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

func TestEvaluatorCalculateRiskScore(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	defaultRiskFactors := telekomv1alpha1.RiskFactors{
		HostNetwork:         10,
		HostPID:             15,
		HostIPC:             10,
		PrivilegedContainer: 50,
		HostPathWritable:    25,
		HostPathReadOnly:    5,
		RunAsRoot:           20,
		Capabilities:        map[string]int{"NET_ADMIN": 30, "SYS_ADMIN": 40},
	}

	tests := []struct {
		name      string
		pod       *corev1.Pod
		rf        telekomv1alpha1.RiskFactors
		wantScore int
	}{
		{
			name: "safe pod returns 0",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:latest",
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 0,
		},
		{
			name: "host network adds score",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers:  []corev1.Container{{Name: "app"}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 10,
		},
		{
			name: "privileged container adds score",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true),
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 50,
		},
		{
			name: "multiple risk factors accumulate",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					HostNetwork: true, // +10
					HostPID:     true, // +15
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true), // +50
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 75, // 10+15+50
		},
		{
			name: "hostPath read-write volume",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						VolumeMounts: []corev1.VolumeMount{{
							Name:     "data",
							ReadOnly: false,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/log",
							},
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 25,
		},
		{
			name: "hostPath read-only volume",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						VolumeMounts: []corev1.VolumeMount{{
							Name:     "data",
							ReadOnly: true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "data",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/log",
							},
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 5,
		},
		{
			name: "run as root user in container",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							RunAsUser: ptr.To(int64(0)),
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 20,
		},
		{
			name: "container with NET_ADMIN capability",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"NET_ADMIN"},
							},
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 30,
		},
		{
			name: "container with SYS_ADMIN capability",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"SYS_ADMIN"},
							},
						},
					}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 40,
		},
		{
			name: "init container also evaluated",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name: "init",
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true),
						},
					}},
					Containers: []corev1.Container{{Name: "app"}},
				},
			},
			rf:        defaultRiskFactors,
			wantScore: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eval.calculateRiskScore(tt.pod, tt.rf)
			if got != tt.wantScore {
				t.Errorf("calculateRiskScore() = %v, want %v", got, tt.wantScore)
			}
		})
	}
}

func TestEvaluatorShouldEvaluateSubresource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	tests := []struct {
		subresource string
		scope       *telekomv1alpha1.PodSecurityScope
		want        bool
	}{
		{"exec", nil, true},
		{"attach", nil, true},
		{"portforward", nil, true},
		{"log", nil, false},
		{"status", nil, false},
		{"", nil, false},
		{"proxy", nil, false},
		// Custom scope
		{"exec", &telekomv1alpha1.PodSecurityScope{Subresources: []string{"exec"}}, true},
		{"attach", &telekomv1alpha1.PodSecurityScope{Subresources: []string{"exec"}}, false},
	}

	for _, tt := range tests {
		name := tt.subresource
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			if got := eval.shouldEvaluateSubresource(tt.subresource, tt.scope); got != tt.want {
				t.Errorf("shouldEvaluateSubresource(%q) = %v, want %v", tt.subresource, got, tt.want)
			}
		})
	}
}

func TestEvaluatorPodSecurityRules(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Policy with pod security rules
	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-risky-exec"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
					HostNetwork:         10,
					RunAsRoot:           20,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "warn"},
					{MaxScore: 50, Action: "allow"},
				},
				FailMode: "open",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	log := zap.NewNop().Sugar()
	eval := NewEvaluator(c, log)

	// Test safe pod - no denial
	safePod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Name:        "test-pod",
		Pod:         safePod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected safe pod exec to be allowed")
	}

	// Test risky pod with score exceeding all thresholds - should be denied
	riskyPod := &corev1.Pod{
		Spec: corev1.PodSpec{
			HostNetwork: true, // +10
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true), // +50
				},
			}},
		},
	}
	denied, policyName, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Name:        "risky-pod",
		Pod:         riskyPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Score is 60 (10+50) which exceeds all thresholds - should be denied
	if !denied {
		t.Fatalf("expected risky pod exec to be denied (score exceeds all thresholds)")
	}
	// Policy name may include additional info about the denial reason
	if !strings.Contains(policyName, "deny-risky-exec") {
		t.Fatalf("expected policy name to contain 'deny-risky-exec' got %q", policyName)
	}
}

func TestEvaluatorPodSecurityExemptions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-with-exemptions"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
					PodLabels:  map[string]string{"exempt": "true"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Exempt namespace should be allowed despite privileged
	exemptByNsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exempt-pod",
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "kube-system",
		Pod:         exemptByNsPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected exempt namespace pod to be allowed")
	}

	// Exempt by label should be allowed
	exemptByLabelPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "labeled-pod",
			Namespace: "default",
			Labels:    map[string]string{"exempt": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         exemptByLabelPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected exempt label pod to be allowed")
	}

	// Non-exempt pod should be denied
	nonExemptPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "risky-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         nonExemptPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected non-exempt privileged pod to be denied")
	}
}

func TestEvaluatorPodSecurityBlockFactors(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-with-blocks"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 10, // low score
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"}, // would normally allow
				},
				BlockFactors: []string{"privilegedContainer"}, // but this blocks
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Privileged pod should be blocked despite low score
	blockedPod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         blockedPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected blocked factor pod to be denied")
	}
}

func TestEvaluatorPodSecurityOverrides(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-high-risk"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 30,
					HostNetwork:         20,
					HostPID:             15,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "allow"},
					{MaxScore: 50, Action: "deny", Reason: "risk too high"},
				},
				BlockFactors: []string{"hostPID"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Create a privileged pod (score 30, normally denied)
	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priv-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Test 1: Without override - should be denied
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         privilegedPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected privileged pod without override to be denied")
	}

	// Test 2: With override raising max score - should be allowed
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         privilegedPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(50),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected privileged pod with high-score override to be allowed")
	}

	// Test 3: Override with namespace scope - only applies to matching namespaces
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         privilegedPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(50),
			NamespaceScope:  &telekomv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "monitoring"}}, // not default
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected override with non-matching namespace to be denied")
	}

	// Test 4: Override with matching namespace scope
	monitoringPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priv-pod",
			Namespace: "monitoring",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "monitoring",
		Pod:         monitoringPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(50),
			NamespaceScope:  &telekomv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "monitoring"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected override with matching namespace to be allowed")
	}
}

func TestEvaluatorPodSecurityOverridesExemptFactors(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-host-access"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork: 30,
					HostPID:     40,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"},
				},
				BlockFactors: []string{"hostNetwork", "hostPID"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with host network (blocked factor)
	hostNetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host-net-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "app"}},
		},
	}

	// Test 1: Without override - blocked by factor
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         hostNetPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected host network pod without override to be denied")
	}

	// Test 2: With exempt factors override - hostNetwork exempted
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         hostNetPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:       true,
			ExemptFactors: []string{"hostNetwork"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected host network pod with exempt factor to be allowed")
	}

	// Test 3: Pod with hostPID - still blocked (not exempted)
	hostPIDPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host-pid-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostPID:    true,
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         hostPIDPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:       true,
			ExemptFactors: []string{"hostNetwork"}, // only exempts hostNetwork, not hostPID
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected host PID pod without its factor exempted to be denied")
	}
}

func TestEvaluatorPodSecurityOverridesDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-risky"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 30,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "allow"},
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priv-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Override present but Enabled=false - should be ignored
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         privilegedPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         false, // disabled
			MaxAllowedScore: ptr.To(100),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected disabled override to have no effect")
	}
}

// =============================================================================
// Fail Mode Tests
// =============================================================================

func TestEvaluatorPodSecurityFailModeClosed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-fail-closed"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"},
				},
				FailMode: "closed", // explicit fail-closed
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod is nil - should deny with fail-closed
	denied, policyName, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         nil, // no pod available
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected fail-closed to deny when pod is nil")
	}
	if !strings.Contains(policyName, "fail-closed") {
		t.Fatalf("expected denial reason to mention fail-closed, got: %s", policyName)
	}
}

func TestEvaluatorPodSecurityFailModeOpen(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-fail-open"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "deny"}, // would deny if evaluated
				},
				FailMode: "open", // fail-open
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod is nil - should allow with fail-open
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         nil, // no pod available
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected fail-open to allow when pod is nil")
	}
}

func TestEvaluatorPodSecurityFailModeDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-fail-default"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"},
				},
				// FailMode not set - should default to "closed"
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod is nil - should deny with default fail-closed behavior
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected default fail mode (closed) to deny when pod is nil")
	}
}

// =============================================================================
// Edge Case Tests: Empty/Nil Configurations
// =============================================================================

func TestEvaluatorPodSecurityEmptyThresholds(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-no-thresholds"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{}, // empty thresholds
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Any pod with a score should be denied (exceeds all thresholds = none)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected empty thresholds to deny (score exceeds all)")
	}
}

func TestEvaluatorPodSecurityZeroScorePod(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-zero-score"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 0, Action: "allow"}, // only score 0 allowed
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Safe pod with score 0 - should be allowed
	safePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         safePod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected zero-score pod to be allowed")
	}
}

func TestEvaluatorPodSecurityNilRiskFactors(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-nil-factors"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				// RiskFactors with all zero values
				RiskFactors: telekomv1alpha1.RiskFactors{},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 0, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Even a privileged pod scores 0 if risk factors are all zero
	riskyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "risky-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			HostPID:     true,
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         riskyPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected pod to be allowed when all risk factors are zero")
	}
}

// =============================================================================
// Complex Risk Scoring Tests
// =============================================================================

func TestEvaluatorPodSecurityMultipleCapabilities(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-capabilities"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					Capabilities: map[string]int{
						"NET_ADMIN":  10,
						"SYS_ADMIN":  20,
						"SYS_PTRACE": 15,
						"NET_RAW":    5,
					},
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 20, Action: "allow"},
					{MaxScore: 40, Action: "warn"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with multiple capabilities - scores should accumulate
	multiCapPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-cap-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"}, // 10+20+15=45
					},
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         multiCapPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Score 45 falls in deny threshold (>40)
	if !denied {
		t.Fatalf("expected pod with multiple capabilities (score 45) to be denied")
	}
}

func TestEvaluatorPodSecurityMultipleContainers(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-multi-container"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 30, // counted once per pod, not per container
					RunAsRoot:           20, // counted once per pod
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 40, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with multiple privileged containers - should only count privileged once
	multiContainerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-container-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app1",
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
						RunAsUser:  ptr.To(int64(0)),
					},
				},
				{
					Name: "app2",
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
						RunAsUser:  ptr.To(int64(0)),
					},
				},
				{
					Name: "sidecar",
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
					},
				},
			},
		},
	}

	// Score should be 30 (privileged) + 20 (runAsRoot) = 50, not 90+60
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         multiContainerPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Score 50 > 40, should be denied
	if !denied {
		t.Fatalf("expected multi-container pod to be denied (score 50)")
	}
}

func TestEvaluatorPodSecurityInitContainersCombined(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-init-containers"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 30,
					Capabilities: map[string]int{
						"NET_ADMIN": 15,
					},
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Init container is privileged, main container has NET_ADMIN
	mixedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "mixed-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name: "init",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_ADMIN"},
					},
				},
			}},
		},
	}

	// Score: 30 (privileged from init) + 15 (NET_ADMIN from main) = 45
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         mixedPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected pod with init+main container risks to be denied")
	}
}

func TestEvaluatorPodSecurityMultipleHostPathVolumes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-hostpath"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostPathWritable: 25,
					HostPathReadOnly: 10,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with multiple hostPath volumes (some RW, some RO)
	multiVolPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-vol-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "logs", MountPath: "/var/log", ReadOnly: false},     // writable
					{Name: "config", MountPath: "/etc/config", ReadOnly: true}, // readonly
					{Name: "data", MountPath: "/data", ReadOnly: false},        // writable
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
				{Name: "config", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc/config"}}},
				{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}},
			},
		},
	}

	// Score: 25 (logs writable) + 10 (config readonly) + 25 (data writable) = 60
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         multiVolPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected pod with multiple hostPath volumes to be denied (score 60)")
	}
}

func TestEvaluatorPodSecurityAllFactorsCombined(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all-factors"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         10,
					HostPID:             15,
					HostIPC:             10,
					PrivilegedContainer: 50,
					HostPathWritable:    25,
					RunAsRoot:           20,
					Capabilities: map[string]int{
						"NET_ADMIN": 30,
					},
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "warn"},
					{MaxScore: 200, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Maximum risk pod
	maxRiskPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "max-risk-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // +10
			HostPID:     true, // +15
			HostIPC:     true, // +10
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),     // +50
					RunAsUser:  ptr.To(int64(0)), // +20
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_ADMIN"}, // +30
					},
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name: "host", MountPath: "/host", ReadOnly: false, // +25
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "host",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/"},
				},
			}},
		},
	}

	// Total: 10+15+10+50+20+30+25 = 160
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         maxRiskPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected maximum risk pod to be denied (score 160)")
	}
}

// =============================================================================
// Exemption Edge Case Tests
// =============================================================================

func TestEvaluatorPodSecurityExemptionPartialLabelMatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-partial-labels"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					PodLabels: map[string]string{
						"exempt": "true",
						"team":   "platform",
					}, // Both labels must match
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with only one matching label - should NOT be exempt
	partialMatchPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "partial-pod",
			Namespace: "default",
			Labels: map[string]string{
				"exempt": "true", // matches
				"team":   "dev",  // doesn't match
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         partialMatchPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected partial label match to NOT exempt pod")
	}

	// Pod with all matching labels - should be exempt
	fullMatchPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-match-pod",
			Namespace: "default",
			Labels: map[string]string{
				"exempt": "true",
				"team":   "platform",
				"extra":  "label", // extra labels are fine
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         fullMatchPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected full label match to exempt pod")
	}
}

func TestEvaluatorPodSecurityExemptionMultipleNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-multi-ns"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "kube-public", "monitoring"}},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := func(ns string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: ns},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged: ptr.To(true),
					},
				}},
			},
		}
	}

	testCases := []struct {
		namespace string
		wantDeny  bool
	}{
		{"kube-system", false},   // exempt
		{"kube-public", false},   // exempt
		{"monitoring", false},    // exempt
		{"default", true},        // not exempt
		{"production", true},     // not exempt
		{"kube-something", true}, // not exempt (partial match doesn't count)
	}

	for _, tc := range testCases {
		t.Run(tc.namespace, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   tc.namespace,
				Pod:         privilegedPod(tc.namespace),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("namespace %s: expected denied=%v, got %v", tc.namespace, tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityExemptionNilExemptions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-no-exemptions"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
				// Exemptions is nil
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Even pods in kube-system should be denied when no exemptions defined
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priv-pod",
			Namespace: "kube-system",
			Labels:    map[string]string{"exempt": "true"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "kube-system",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected pod to be denied when exemptions are nil")
	}
}

func TestEvaluatorPodSecurityExemptionEmptyLabels(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-empty-labels"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					PodLabels: map[string]string{}, // empty map
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Empty label exemption should NOT exempt any pod
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected pod to be denied with empty label exemptions")
	}
}

// =============================================================================
// Block Factor Combination Tests
// =============================================================================

func TestEvaluatorPodSecurityMultipleBlockFactors(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-multi-block"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         10,
					HostPID:             10,
					PrivilegedContainer: 10,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"}, // would allow all
				},
				BlockFactors: []string{"hostNetwork", "hostPID", "privilegedContainer"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	testCases := []struct {
		name     string
		pod      *corev1.Pod
		wantDeny bool
	}{
		{
			name: "hostNetwork blocked",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "host-net", Namespace: "default"},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers:  []corev1.Container{{Name: "app"}},
				},
			},
			wantDeny: true,
		},
		{
			name: "hostPID blocked",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "host-pid", Namespace: "default"},
				Spec: corev1.PodSpec{
					HostPID:    true,
					Containers: []corev1.Container{{Name: "app"}},
				},
			},
			wantDeny: true,
		},
		{
			name: "privileged blocked",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "default"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						SecurityContext: &corev1.SecurityContext{
							Privileged: ptr.To(true),
						},
					}},
				},
			},
			wantDeny: true,
		},
		{
			name: "safe pod allowed",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "safe", Namespace: "default"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app"}},
				},
			},
			wantDeny: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Pod:         tc.pod,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("expected denied=%v, got %v", tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityBlockFactorWithOverride(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-block-override"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         10,
					HostPID:             10,
					PrivilegedContainer: 10,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"},
				},
				BlockFactors: []string{"hostNetwork", "hostPID", "privilegedContainer"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with multiple block factors
	multiBlockPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-block", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			HostPID:     true,
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Test: Override exempts hostNetwork and hostPID, but not privileged
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         multiBlockPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:       true,
			ExemptFactors: []string{"hostNetwork", "hostPID"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected pod to still be blocked by privilegedContainer")
	}

	// Test: Override exempts ALL block factors
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         multiBlockPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:       true,
			ExemptFactors: []string{"hostNetwork", "hostPID", "privilegedContainer"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected pod to be allowed when all block factors are exempted")
	}
}

func TestEvaluatorPodSecurityBlockFactorPrecedence(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Block factor should take precedence over threshold
	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-block-precedence"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 5, // Very low score
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"}, // Would allow score 5
				},
				BlockFactors: []string{"privilegedContainer"}, // But blocks anyway
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, policyName, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected block factor to take precedence over threshold")
	}
	if !strings.Contains(policyName, "blocked") {
		t.Fatalf("expected denial reason to mention blocked factor, got: %s", policyName)
	}
}

// =============================================================================
// Override Boundary Condition Tests
// =============================================================================

func TestEvaluatorPodSecurityOverrideScoreExactBoundary(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-boundary"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true), // score 50
				},
			}},
		},
	}

	// Test: Override exactly at score boundary (50 <= 50)
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(50), // exactly equals score
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected score at exact boundary (50 <= 50) to be allowed")
	}

	// Test: Override one below score (49 < 50)
	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(49), // one below score
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected score above boundary (50 > 49) to be denied")
	}
}

func TestEvaluatorPodSecurityOverrideNilMaxScore(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-nil-max"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Override with nil MaxAllowedScore (only exempt factors, no score override)
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: nil, // no score override
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected nil MaxAllowedScore to not override threshold (still denied)")
	}
}

func TestEvaluatorPodSecurityOverrideCombinedOptions(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-combined"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         20,
					PrivilegedContainer: 30,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 20, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
				BlockFactors: []string{"hostNetwork"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with both hostNetwork (blocked) and privileged (high score)
	complexPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "complex-pod", Namespace: "monitoring"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // blocked + score 20
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true), // score 30
				},
			}},
		},
	}

	// Combined: exempt hostNetwork block factor AND raise score threshold
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "monitoring",
		Pod:         complexPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(60),                                                         // allows score 50 (20+30)
			ExemptFactors:   []string{"hostNetwork"},                                            // bypasses block
			NamespaceScope:  &telekomv1alpha1.NamespaceFilter{Patterns: []string{"monitoring"}}, // only in monitoring
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected combined overrides to allow pod")
	}

	// Same override but in different namespace - should fail
	differentNsPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "complex-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, _, err = eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         differentNsPod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(60),
			ExemptFactors:   []string{"hostNetwork"},
			NamespaceScope:  &telekomv1alpha1.NamespaceFilter{Patterns: []string{"monitoring"}}, // doesn't include default
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected override to not apply in different namespace")
	}
}

func TestEvaluatorPodSecurityOverrideZeroMaxScore(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-zero-override"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "deny"}, // denies everything
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Safe pod with score 0
	safePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	// Override with MaxAllowedScore=0 - only allows score 0
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         safePod,
		PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: ptr.To(0),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected score 0 to be allowed with MaxAllowedScore=0")
	}
}

// =============================================================================
// MatchWithDetails and Warn Action Tests
// =============================================================================

func TestEvaluatorMatchWithDetailsWarnAction(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-warn"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork: 25,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "allow"},
					{MaxScore: 50, Action: "warn", Reason: "Elevated risk: {{.Factors}}"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Pod with score 25 - falls in warn threshold
	warnPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "warn-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // score 25
			Containers:  []corev1.Container{{Name: "app"}},
		},
	}

	denied, policyName, result, err := eval.MatchWithDetails(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         warnPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected warn action to not deny")
	}
	if policyName != "" {
		t.Fatalf("expected no policy name for non-denied request, got: %s", policyName)
	}
	if result == nil {
		t.Fatalf("expected result for warn action")
	}
	if result.Action != "warn" {
		t.Fatalf("expected action=warn, got: %s", result.Action)
	}
	if result.Score != 25 {
		t.Fatalf("expected score=25, got: %d", result.Score)
	}
	if len(result.Factors) == 0 || result.Factors[0] != "hostNetwork" {
		t.Fatalf("expected factors to include hostNetwork, got: %v", result.Factors)
	}
}

func TestEvaluatorMatchWithDetailsDenyAction(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-detailed"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 60,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny", Reason: "Risk score {{.Score}} too high"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true), // score 60
				},
			}},
		},
	}

	denied, policyName, result, err := eval.MatchWithDetails(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected deny action to deny")
	}
	if policyName != "deny-detailed" {
		t.Fatalf("expected policy name, got: %s", policyName)
	}
	if result == nil {
		t.Fatalf("expected result for deny action")
	}
	if result.Action != "deny" {
		t.Fatalf("expected action=deny, got: %s", result.Action)
	}
	if !result.Denied {
		t.Fatalf("expected result.Denied=true")
	}
}

func TestEvaluatorMatchWithDetailsAllowAction(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-allow"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork: 10,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	// Safe pod with score 0
	safePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	denied, policyName, result, err := eval.MatchWithDetails(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         safePod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected allow action to not deny")
	}
	if policyName != "" {
		t.Fatalf("expected no policy name, got: %s", policyName)
	}
	// Allow action doesn't return details (only warn does)
	if result != nil {
		t.Fatalf("expected no result for allow action, got: %+v", result)
	}
}

func TestEvaluatorMatchWithDetailsNoPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// No policies at all
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "any-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			HostPID:     true,
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, policyName, result, err := eval.MatchWithDetails(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if denied {
		t.Fatalf("expected no denial without policies")
	}
	if policyName != "" {
		t.Fatalf("expected no policy name, got: %s", policyName)
	}
	if result != nil {
		t.Fatalf("expected no result without policies")
	}
}

// =============================================================================
// Reason Template Rendering Tests
// =============================================================================

func TestEvaluatorReasonTemplateRendering(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-template"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         20,
					PrivilegedContainer: 30,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "allow"},
					{MaxScore: 100, Action: "deny", Reason: "Pod {{.Pod}} in {{.Namespace}} denied (score={{.Score}}, factors={{.Factors}})"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pod", Namespace: "production"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // +20
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true), // +30
				},
			}},
		},
	}

	denied, policyName, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "production",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected denial")
	}

	// Check template variables were substituted
	if !strings.Contains(policyName, "my-pod") {
		t.Errorf("expected reason to contain pod name 'my-pod', got: %s", policyName)
	}
	if !strings.Contains(policyName, "production") {
		t.Errorf("expected reason to contain namespace 'production', got: %s", policyName)
	}
	if !strings.Contains(policyName, "50") {
		t.Errorf("expected reason to contain score '50', got: %s", policyName)
	}
	if !strings.Contains(policyName, "hostNetwork") {
		t.Errorf("expected reason to contain factor 'hostNetwork', got: %s", policyName)
	}
}

func TestEvaluatorReasonTemplateEmptyReason(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-no-reason"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "deny"}, // no reason specified
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	denied, policyName, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected denial")
	}
	// Should have default reason when empty
	if !strings.Contains(policyName, "risk score") {
		t.Errorf("expected default reason message, got: %s", policyName)
	}
}

func TestEvaluatorReasonTemplateInvalidTemplate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-bad-template"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "deny", Reason: "Invalid template {{.Unknown}}"}, // invalid field
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Should not panic with invalid template
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected denial even with bad template")
	}
}

// =============================================================================
// Scope Matching Tests
// =============================================================================

func TestEvaluatorPodSecurityScopeCluster(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-prod-cluster"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			AppliesTo: &telekomv1alpha1.DenyPolicyScope{
				Clusters: []string{"prod-cluster-1", "prod-cluster-2"},
			},
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	testCases := []struct {
		clusterID string
		wantDeny  bool
	}{
		{"prod-cluster-1", true},   // in scope
		{"prod-cluster-2", true},   // in scope
		{"staging-cluster", false}, // not in scope
		{"dev-cluster", false},     // not in scope
		{"", false},                // empty cluster ID
	}

	for _, tc := range testCases {
		t.Run(tc.clusterID, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				ClusterID:   tc.clusterID,
				Pod:         privilegedPod,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("cluster %q: expected denied=%v, got %v", tc.clusterID, tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityScopeTenant(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-tenant-a"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			AppliesTo: &telekomv1alpha1.DenyPolicyScope{
				Tenants: []string{"tenant-a", "tenant-b"},
			},
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	testCases := []struct {
		tenant   string
		wantDeny bool
	}{
		{"tenant-a", true},  // in scope
		{"tenant-b", true},  // in scope
		{"tenant-c", false}, // not in scope
		{"", false},         // empty tenant
	}

	for _, tc := range testCases {
		t.Run(tc.tenant, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Tenant:      tc.tenant,
				Pod:         privilegedPod,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("tenant %q: expected denied=%v, got %v", tc.tenant, tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityScopeSession(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-specific-sessions"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			AppliesTo: &telekomv1alpha1.DenyPolicyScope{
				Sessions: []string{"emergency-session-1"},
			},
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	testCases := []struct {
		session  string
		wantDeny bool
	}{
		{"emergency-session-1", true}, // in scope
		{"other-session", false},      // not in scope
		{"", false},                   // empty session
	}

	for _, tc := range testCases {
		t.Run(tc.session, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Session:     tc.session,
				Pod:         privilegedPod,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("session %q: expected denied=%v, got %v", tc.session, tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityScopeCombined(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Policy requires BOTH cluster AND tenant to match
	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-combined-scope"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			AppliesTo: &telekomv1alpha1.DenyPolicyScope{
				Clusters: []string{"prod-cluster"},
				Tenants:  []string{"tenant-a"},
			},
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	testCases := []struct {
		name      string
		clusterID string
		tenant    string
		wantDeny  bool
	}{
		{"both match", "prod-cluster", "tenant-a", true},
		{"only cluster matches", "prod-cluster", "tenant-b", false},
		{"only tenant matches", "dev-cluster", "tenant-a", false},
		{"neither matches", "dev-cluster", "tenant-b", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:        "create",
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				ClusterID:   tc.clusterID,
				Tenant:      tc.tenant,
				Pod:         privilegedPod,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tc.wantDeny {
				t.Fatalf("expected denied=%v, got %v", tc.wantDeny, denied)
			}
		})
	}
}

func TestEvaluatorPodSecurityScopeNil(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Policy with no AppliesTo - should be global
	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-global"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			// AppliesTo is nil - global scope
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr.To(true),
				},
			}},
		},
	}

	// Should deny regardless of cluster/tenant/session
	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		ClusterID:   "any-cluster",
		Tenant:      "any-tenant",
		Session:     "any-session",
		Pod:         privilegedPod,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !denied {
		t.Fatalf("expected global policy to deny")
	}
}

// TestEvaluatorNamespaceSelectorTerms tests DenyPolicy matching with namespace label selectors.
func TestEvaluatorNamespaceSelectorTerms(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create policies with different namespace selector configurations
	policies := []runtime.Object{
		// Policy with label selector only (no patterns)
		&telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-prod-env"},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"services"},
					Namespaces: &telekomv1alpha1.NamespaceFilter{
						SelectorTerms: []telekomv1alpha1.NamespaceSelectorTerm{{
							MatchLabels: map[string]string{"env": "production"},
						}},
					},
				}},
			},
		},
		// Policy with matchExpressions
		&telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-critical-tier"},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Namespaces: &telekomv1alpha1.NamespaceFilter{
						SelectorTerms: []telekomv1alpha1.NamespaceSelectorTerm{{
							MatchExpressions: []telekomv1alpha1.NamespaceSelectorRequirement{{
								Key:      "tier",
								Operator: telekomv1alpha1.NamespaceSelectorOpIn,
								Values:   []string{"critical", "high"},
							}},
						}},
					},
				}},
			},
		},
		// Policy with both patterns and selectors (OR semantics)
		&telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "deny-mixed"},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Namespaces: &telekomv1alpha1.NamespaceFilter{
						Patterns: []string{"kube-*"},
						SelectorTerms: []telekomv1alpha1.NamespaceSelectorTerm{{
							MatchLabels: map[string]string{"restricted": "true"},
						}},
					},
				}},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(policies...).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	tests := []struct {
		name     string
		action   Action
		wantDeny bool
		wantPol  string
	}{
		// Label selector only tests
		{
			name: "label selector matches production env",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "services",
				Namespace:       "my-prod-ns",
				NamespaceLabels: map[string]string{"env": "production", "team": "alpha"},
			},
			wantDeny: true,
			wantPol:  "deny-prod-env",
		},
		{
			name: "label selector does not match staging env",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "services",
				Namespace:       "my-staging-ns",
				NamespaceLabels: map[string]string{"env": "staging", "team": "alpha"},
			},
			wantDeny: false,
			wantPol:  "",
		},
		{
			name: "label selector without namespace labels - cannot evaluate",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "services",
				Namespace:       "unknown-ns",
				NamespaceLabels: nil, // No labels provided
			},
			wantDeny: false, // Cannot evaluate selector-only rules without labels
			wantPol:  "",
		},
		// matchExpressions tests
		{
			name: "matchExpressions In operator matches critical tier",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "configmaps",
				Namespace:       "critical-ns",
				NamespaceLabels: map[string]string{"tier": "critical"},
			},
			wantDeny: true,
			wantPol:  "deny-critical-tier",
		},
		{
			name: "matchExpressions In operator matches high tier",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "configmaps",
				Namespace:       "high-ns",
				NamespaceLabels: map[string]string{"tier": "high"},
			},
			wantDeny: true,
			wantPol:  "deny-critical-tier",
		},
		{
			name: "matchExpressions In operator does not match low tier",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "configmaps",
				Namespace:       "low-ns",
				NamespaceLabels: map[string]string{"tier": "low"},
			},
			wantDeny: false,
			wantPol:  "",
		},
		// Mixed patterns and selectors tests (OR semantics)
		{
			name: "mixed policy matches by pattern (kube-system)",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "secrets",
				Namespace:       "kube-system",
				NamespaceLabels: map[string]string{"env": "system"}, // Labels don't match selector
			},
			wantDeny: true,
			wantPol:  "deny-mixed",
		},
		{
			name: "mixed policy matches by label selector",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "secrets",
				Namespace:       "my-restricted-ns", // Pattern doesn't match
				NamespaceLabels: map[string]string{"restricted": "true"},
			},
			wantDeny: true,
			wantPol:  "deny-mixed",
		},
		{
			name: "mixed policy no match - neither pattern nor label",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "secrets",
				Namespace:       "my-normal-ns",
				NamespaceLabels: map[string]string{"restricted": "false"},
			},
			wantDeny: false,
			wantPol:  "",
		},
		{
			name: "mixed policy matches pattern even without labels",
			action: Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "secrets",
				Namespace:       "kube-public",
				NamespaceLabels: nil, // No labels, but pattern matches
			},
			wantDeny: true,
			wantPol:  "deny-mixed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denied, pol, err := eval.Match(context.Background(), tt.action)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tt.wantDeny {
				t.Errorf("denied = %v, want %v (policy: %s)", denied, tt.wantDeny, pol)
			}
			if pol != tt.wantPol {
				t.Errorf("policy = %q, want %q", pol, tt.wantPol)
			}
		})
	}
}

// TestEvaluatorNamespaceSelectorMatchExpressionOperators tests all selector operators.
func TestEvaluatorNamespaceSelectorMatchExpressionOperators(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name     string
		operator telekomv1alpha1.NamespaceSelectorOperator
		key      string
		values   []string
		labels   map[string]string
		want     bool
	}{
		// In operator
		{"In - value present", telekomv1alpha1.NamespaceSelectorOpIn, "env", []string{"prod", "staging"}, map[string]string{"env": "prod"}, true},
		{"In - value not present", telekomv1alpha1.NamespaceSelectorOpIn, "env", []string{"prod", "staging"}, map[string]string{"env": "dev"}, false},
		{"In - key missing", telekomv1alpha1.NamespaceSelectorOpIn, "env", []string{"prod"}, map[string]string{"tier": "critical"}, false},
		// NotIn operator
		{"NotIn - value not in list", telekomv1alpha1.NamespaceSelectorOpNotIn, "env", []string{"prod", "staging"}, map[string]string{"env": "dev"}, true},
		{"NotIn - value in list", telekomv1alpha1.NamespaceSelectorOpNotIn, "env", []string{"prod", "staging"}, map[string]string{"env": "prod"}, false},
		{"NotIn - key missing (passes)", telekomv1alpha1.NamespaceSelectorOpNotIn, "env", []string{"prod"}, map[string]string{"tier": "critical"}, true},
		// Exists operator
		{"Exists - key present", telekomv1alpha1.NamespaceSelectorOpExists, "env", nil, map[string]string{"env": "any"}, true},
		{"Exists - key missing", telekomv1alpha1.NamespaceSelectorOpExists, "env", nil, map[string]string{"tier": "critical"}, false},
		// DoesNotExist operator
		{"DoesNotExist - key missing", telekomv1alpha1.NamespaceSelectorOpDoesNotExist, "env", nil, map[string]string{"tier": "critical"}, true},
		{"DoesNotExist - key present", telekomv1alpha1.NamespaceSelectorOpDoesNotExist, "env", nil, map[string]string{"env": "any"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &telekomv1alpha1.DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
				Spec: telekomv1alpha1.DenyPolicySpec{
					Rules: []telekomv1alpha1.DenyRule{{
						Verbs:     []string{"get"},
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Namespaces: &telekomv1alpha1.NamespaceFilter{
							SelectorTerms: []telekomv1alpha1.NamespaceSelectorTerm{{
								MatchExpressions: []telekomv1alpha1.NamespaceSelectorRequirement{{
									Key:      tt.key,
									Operator: tt.operator,
									Values:   tt.values,
								}},
							}},
						},
					}},
				},
			}

			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
			eval := NewEvaluator(c, zap.NewNop().Sugar())

			denied, _, err := eval.Match(context.Background(), Action{
				Verb:            "get",
				APIGroup:        "",
				Resource:        "pods",
				Namespace:       "test-ns",
				NamespaceLabels: tt.labels,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tt.want {
				t.Errorf("denied = %v, want %v", denied, tt.want)
			}
		})
	}
}

// TestEvaluatorNamespaceSelectorMultipleTerms tests OR semantics between selector terms.
func TestEvaluatorNamespaceSelectorMultipleTerms(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	pol := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-term-policy"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{{
				Verbs:     []string{"delete"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Namespaces: &telekomv1alpha1.NamespaceFilter{
					SelectorTerms: []telekomv1alpha1.NamespaceSelectorTerm{
						// Term 1: env=prod
						{MatchLabels: map[string]string{"env": "prod"}},
						// Term 2: tier=critical (OR semantics)
						{MatchLabels: map[string]string{"tier": "critical"}},
					},
				},
			}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pol).Build()
	eval := NewEvaluator(c, zap.NewNop().Sugar())

	tests := []struct {
		name     string
		labels   map[string]string
		wantDeny bool
	}{
		{"matches first term only", map[string]string{"env": "prod"}, true},
		{"matches second term only", map[string]string{"tier": "critical"}, true},
		{"matches both terms", map[string]string{"env": "prod", "tier": "critical"}, true},
		{"matches neither term", map[string]string{"env": "dev", "tier": "low"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denied, _, err := eval.Match(context.Background(), Action{
				Verb:            "delete",
				APIGroup:        "",
				Resource:        "pods",
				Namespace:       "test-ns",
				NamespaceLabels: tt.labels,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if denied != tt.wantDeny {
				t.Errorf("denied = %v, want %v", denied, tt.wantDeny)
			}
		})
	}
}

// TestEvaluatorPodSecurityWarnActionReason tests that warn action populates the Reason field.
func TestEvaluatorPodSecurityWarnActionReason(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	policy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "warn-test-policy"},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork: 50,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 30, Action: "allow"},
					{MaxScore: 70, Action: "warn", Reason: "Warning: Pod has risk score {{.Score}} due to {{.Factors}}"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	log := zap.NewNop().Sugar()
	eval := NewEvaluator(c, log)

	// Create a pod with hostNetwork=true (score 50, triggers warn threshold)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{
				{Name: "test", Image: "busybox"},
			},
		},
	}

	act := Action{
		Verb:        "create",
		APIGroup:    "",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
		ClusterID:   "test-cluster",
	}

	result := eval.evaluatePodSecurity(act, policy.Spec.PodSecurityRules)

	// Verify the warn action populates the Reason field
	if result.Action != "warn" {
		t.Fatalf("expected action 'warn', got '%s'", result.Action)
	}
	if result.Denied {
		t.Error("expected Denied=false for warn action")
	}
	if result.Reason == "" {
		t.Error("expected Reason to be populated for warn action, got empty string")
	}
	if result.Score != 50 {
		t.Errorf("expected score 50, got %d", result.Score)
	}
	// Verify the reason contains expected parts
	if !strings.Contains(result.Reason, "50") {
		t.Errorf("expected reason to contain score '50', got: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "hostNetwork") {
		t.Errorf("expected reason to contain factor 'hostNetwork', got: %s", result.Reason)
	}
}

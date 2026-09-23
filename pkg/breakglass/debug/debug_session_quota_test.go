// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestEnsureTargetNamespaceHonorsCreationAndFailMode(t *testing.T) {
	for _, tt := range []struct {
		name        string
		failMode    string
		constraints *breakglassv1alpha1.NamespaceConstraints
		wantError   bool
		wantCreate  bool
		wantReady   bool
	}{
		{name: "creates missing namespace", constraints: &breakglassv1alpha1.NamespaceConstraints{CreateIfNotExists: true, NamespaceLabels: map[string]string{"owner": "breakglass"}}, wantCreate: true, wantReady: true},
		{name: "fail open skips missing namespace", failMode: "open"},
		{name: "fail closed rejects missing namespace", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
			controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil)
			ready, err := controller.ensureTargetNamespace(t.Context(), cli, "debug-target", tt.failMode, tt.constraints)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantReady, ready)

			ns := &corev1.Namespace{}
			err = cli.Get(t.Context(), client.ObjectKey{Name: "debug-target"}, ns)
			if tt.wantCreate {
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"owner": "breakglass"}, ns.Labels)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestEnsureTargetNamespaceFencesCreation(t *testing.T) {
	cli := fake.NewClientBuilder().WithScheme(Scheme).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil)
	called := false
	ready, err := controller.ensureTargetNamespace(t.Context(), cli, "debug-target", "", &breakglassv1alpha1.NamespaceConstraints{CreateIfNotExists: true}, func() error {
		called = true
		return fmt.Errorf("session expired")
	})
	require.Error(t, err)
	assert.False(t, ready)
	assert.True(t, called)
	ns := &corev1.Namespace{}
	assert.Error(t, cli.Get(t.Context(), client.ObjectKey{Name: "debug-target"}, ns))
}

func TestEffectiveNamespaceConstraintsBindingOverridesTemplate(t *testing.T) {
	templateConstraints := &breakglassv1alpha1.NamespaceConstraints{DefaultNamespace: "template-debug", NamespaceLabels: map[string]string{"source": "template"}}
	bindingConstraints := &breakglassv1alpha1.NamespaceConstraints{DefaultNamespace: "binding-debug", CreateIfNotExists: true, NamespaceLabels: map[string]string{"source": "binding"}}
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{NamespaceConstraints: templateConstraints}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{NamespaceConstraints: bindingConstraints}}

	assert.Same(t, bindingConstraints, effectiveNamespaceConstraints(template, binding))
	assert.Same(t, templateConstraints, effectiveNamespaceConstraints(template, nil))
	assert.Same(t, templateConstraints, effectiveNamespaceConstraints(template, &breakglassv1alpha1.DebugSessionClusterBinding{}))
}

func TestDeployDebugResourcesFailOpenSkipsSpokeWrites(t *testing.T) {
	var writes int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes++
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/missing-debug" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	defer server.Close()
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")

	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		APIVersion: "v1", Kind: "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"spoke": {Server: server.URL}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"controller": {}},
		Contexts:       map[string]*clientcmdapi.Context{"default": {Cluster: "spoke", AuthInfo: "controller"}},
		CurrentContext: "default",
	})
	require.NoError(t, err)
	clusterConfig := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: "default", UID: "spoke-uid"}, Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "spoke-kubeconfig", Namespace: "default"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: "default"}, Data: map[string][]byte{"value": kubeconfig}}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{FailMode: "open", TargetNamespace: "missing-debug", ResourceQuota: &breakglassv1alpha1.DebugResourceQuotaConfig{MaxPods: int32Ptr(1)}}}
	session := newTestDebugSession("fail-open", template.Name, clusterConfig.Name, "user@example.com")
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(clusterConfig, secret, template).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).WithAPIReader(hub)

	require.NoError(t, controller.deployDebugResources(t.Context(), session, template))
	assert.Zero(t, writes, "fail-open must stop deployment after a missing namespace")
}

func TestDebugQuotaScopesAcrossNamespacesAndBindings(t *testing.T) {
	one := int32(1)
	for _, scope := range []string{"template", "binding-total", "binding-user"} {
		t.Run(scope, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template-uid"}}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "bindings", UID: "binding-one"}}
			other := binding.DeepCopy()
			other.Name = "other"
			other.UID = "binding-two"
			switch scope {
			case "template":
				template.Spec.Constraints = &breakglassv1alpha1.DebugSessionConstraints{MaxConcurrentSessions: 1}
			case "binding-total":
				binding.Spec.MaxActiveSessionsTotal = &one
			case "binding-user":
				binding.Spec.MaxActiveSessionsPerUser = &one
			}
			candidate := func(name, ns, user string) *breakglassv1alpha1.DebugSession {
				return &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(name), Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, RequestedBy: user, RequestedByEmail: "shared@example.com", BindingRef: &breakglassv1alpha1.BindingReference{Name: binding.Name, Namespace: binding.Namespace}}}
			}
			a := candidate("first", "sessions-one", "username-one")
			b := candidate("second", "sessions-two", "username-two")
			if scope == "template" {
				b.Spec.BindingRef.Name = other.Name
			}
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(template, binding, other, a, b).Build()
			c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(a), a))
			require.NoError(t, c.admitDebugSession(t.Context(), a))
			restarted := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(b), b))
			require.ErrorIs(t, restarted.admitDebugSession(t.Context(), b), quotas.ErrFull)
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(b), b))
			assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, b.Status.State)
			assert.Equal(t, "Session quota reached", b.Status.Message)
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(a), a))
			require.NoError(t, restarted.admitDebugSession(t.Context(), a))
		})
	}
}

func TestDebugQuotaBootstrapsLegacyResolvedBinding(t *testing.T) {
	one := int32(1)
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "bindings", UID: "binding"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{MaxActiveSessionsTotal: &one}}
	legacy := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "old", UID: "legacy"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ResolvedBinding: &breakglassv1alpha1.ResolvedBindingRef{Name: binding.Name, Namespace: binding.Namespace}}}
	candidate := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "new", UID: "new", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, BindingRef: &breakglassv1alpha1.BindingReference{Name: binding.Name, Namespace: binding.Namespace}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(template, binding, legacy, candidate).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(candidate), candidate))
	require.ErrorIs(t, c.admitDebugSession(t.Context(), candidate), quotas.ErrFull)
}

func TestDebugQuotaStatusCannotReviveTerminalSession(t *testing.T) {
	current := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "uid", Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Ready}}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(current).Build()
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(current), current))
	stale := current.DeepCopy()
	current.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	require.NoError(t, cli.Status().Update(t.Context(), current))
	stale.Status.State = breakglassv1alpha1.DebugSessionStateActive
	err := breakglass.ApplyDebugSessionStatus(t.Context(), cli, stale)
	require.True(t, apierrors.IsConflict(err), "late activation must be fenced: %v", err)
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(current), current))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, current.Status.State)
}

func TestDebugQuotaReservedSessionSurvivesDeletedPolicy(t *testing.T) {
	old := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "old", UID: "old-template"}}
	next := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "next", UID: "next-template"}}
	candidate := func(name, template string) *breakglassv1alpha1.DebugSession {
		return &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name), Annotations: map[string]string{quotas.AdmissionAnnotation: quotas.Pending}}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template}}
	}
	first := candidate("first", old.Name)
	second := candidate("second", next.Name)
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(old, next, first, second).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(first), first))
	require.NoError(t, c.admitDebugSession(t.Context(), first))
	require.NoError(t, cli.Delete(t.Context(), old))
	require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(second), second))
	require.NoError(t, c.admitDebugSession(t.Context(), second))
}

type failQuotaClusterConfigReader struct{ client.Reader }

func (r failQuotaClusterConfigReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*breakglassv1alpha1.ClusterConfigList); ok {
		return fmt.Errorf("cluster config unavailable")
	}
	return r.Reader.List(ctx, list, opts...)
}
func TestDebugQuotaLegacyBindingDiscoveryFailsClosed(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(failQuotaClusterConfigReader{Reader: cli}).WithQuotaNamespace("controller")
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "session"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
	_, _, _, err := c.debugQuotaPolicy(t.Context(), session)
	require.ErrorContains(t, err, "cluster config unavailable")
}

func TestDebugQuotaLegacySelectorRequiresClusterConfig(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "ns", UID: "binding"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "prod"}}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template, binding).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(cli).WithQuotaNamespace("controller")
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "session"}, Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name, Cluster: "missing"}}
	_, _, _, err := c.debugQuotaPolicy(t.Context(), session)
	require.ErrorContains(t, err, "cluster config required")
}

func TestDebugLifecycleDoesNotIgnoreBindingDiscoveryFailure(t *testing.T) {
	for _, approved := range []bool{false, true} {
		t.Run(fmt.Sprint(approved), func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template).Build()
			c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(failQuotaClusterConfigReader{Reader: cli}).WithQuotaNamespace("controller")
			session := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
			if approved {
				now := metav1.Now()
				session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{ApprovedAt: &now}
				_, err := c.handlePendingApproval(t.Context(), session)
				require.ErrorContains(t, err, "cluster config unavailable")
			} else {
				_, err := c.handlePending(t.Context(), session)
				require.ErrorContains(t, err, "cluster config unavailable")
			}
			require.Empty(t, session.Status.State)
			require.Empty(t, session.Annotations)
		})
	}
}

func TestDebugWorkloadBindingResolutionFailsClosed(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(template).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithAPIReader(failQuotaClusterConfigReader{Reader: cli}).WithQuotaNamespace("controller")
	session := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: template.Name}}
	require.ErrorContains(t, c.deployDebugResources(t.Context(), session, template), "cluster config unavailable")
	session.Spec.BindingRef = &breakglassv1alpha1.BindingReference{Name: "missing", Namespace: "ns"}
	require.ErrorContains(t, c.deployDebugResources(t.Context(), session, template), "resolve workload binding")
	require.Nil(t, session.Status.ResolvedBinding)
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestAllowedPodsRefreshRetriesConcurrentReplicas(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "three replicas publish", true: "terminal transition fences retry"}[terminal], func(t *testing.T) {
			ctx := context.Background()
			session := newTestDebugSession("refresh", "template", "spoke", "owner")
			session.UID = "session-uid"
			session.Status.State = breakglassv1alpha1.DebugSessionStateActive
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			session.Status.ExpiresAt = &expiry
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "debug", UID: "pod-uid", Labels: map[string]string{DebugSessionLabelKey: session.Name}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
			session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace, UID: string(pod.UID), Source: "debug-pod"}}
			var lists atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var response any
				switch r.URL.Path {
				case "/api":
					response = metav1.APIVersions{Versions: []string{"v1"}}
				case "/apis":
					response = metav1.APIGroupList{}
				case "/api/v1":
					response = metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}}}}
				case "/api/v1/pods":
					lists.Add(1)
					response = corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, Items: []corev1.Pod{pod}}
				default:
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			kubeconfig, err := clientcmd.Write(clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"spoke": {Server: server.URL}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"test": {}}, Contexts: map[string]*clientcmdapi.Context{"test": {Cluster: "spoke", AuthInfo: "test"}}, CurrentContext: "test"})
			require.NoError(t, err)
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: session.Namespace}, Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "spoke", Namespace: session.Namespace}}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: session.Namespace}, Data: map[string][]byte{"value": kubeconfig}}
			var patches atomic.Int32
			barrier := make(chan struct{})
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(session, cc, secret).WithStatusSubresource(session).WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.SubResourcePatchOption) error {
				if name == "status" {
					n := patches.Add(1)
					if !terminal && n <= 3 {
						if n == 3 {
							close(barrier)
						}
						<-barrier
					}
					if terminal && n == 1 {
						current := &breakglassv1alpha1.DebugSession{}
						if err := cl.Get(ctx, ctrlclient.ObjectKeyFromObject(session), current); err != nil {
							return err
						}
						current.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
						if err := cl.Status().Update(ctx, current); err != nil {
							return err
						}
					}
				}
				return cl.SubResource(name).Patch(ctx, obj, patch, opts...)
			}}).Build()
			replicas := 3
			if terminal {
				replicas = 1
			}
			errors := make(chan error, replicas)
			var wg sync.WaitGroup
			for range replicas {
				wg.Add(1)
				go func() {
					defer wg.Done()
					controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
					controller.reader = hub
					errors <- controller.updateAllowedPods(ctx, session.DeepCopy())
				}()
			}
			wg.Wait()
			close(errors)
			for err := range errors {
				if terminal {
					require.ErrorContains(t, err, "no longer authorizes")
				} else {
					require.NoError(t, err)
				}
			}
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, hub.Get(ctx, ctrlclient.ObjectKeyFromObject(session), live))
			if terminal {
				require.Empty(t, live.Status.AllowedPods)
				require.Equal(t, int32(1), lists.Load())
				return
			}
			require.Greater(t, lists.Load(), int32(3), "conflicts must recompute Pod identities through target API")
			require.Len(t, live.Status.AllowedPods, 1)
			require.Equal(t, "pod-uid", live.Status.AllowedPods[0].UID)
			require.True(t, live.Status.AllowedPods[0].Ready)
		})
	}
}

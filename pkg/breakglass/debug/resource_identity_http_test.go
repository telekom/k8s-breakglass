// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRecoverTypedDeploymentHTTP(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same approved content", true: "changed image rejected"}[changed], func(t *testing.T) {
			desired := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "debug"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "approved:1"}}}}}}
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "session-uid"}}
			_, err := stampCreateOperation(desired, session)
			require.NoError(t, err)
			existing := desired.DeepCopy()
			existing.UID = "original-uid"
			existing.ResourceVersion = "123"
			if changed {
				existing.Spec.Template.Spec.Containers[0].Image = "unapproved:2"
			}
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodPost:
					writes++
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"AlreadyExists","code":409}`))
				case http.MethodGet:
					require.NoError(t, json.NewEncoder(w).Encode(existing))
				default:
					t.Errorf("unexpected request %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer server.Close()
			scheme := runtime.NewScheme()
			require.NoError(t, appsv1.AddToScheme(scheme))
			mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{appsv1.SchemeGroupVersion})
			mapper.Add(appsv1.SchemeGroupVersion.WithKind("Deployment"), meta.RESTScopeNamespace)
			target, err := client.New(&rest.Config{Host: server.URL}, client.Options{Scheme: scheme, Mapper: mapper})
			require.NoError(t, err)
			err = createOrRecoverTargetObject(context.Background(), target, desired, session)
			if changed {
				require.ErrorContains(t, err, "different desired content")
				require.Empty(t, desired.UID)
			} else {
				require.NoError(t, err)
				require.EqualValues(t, "original-uid", desired.UID)
				require.Equal(t, "123", desired.ResourceVersion)
			}
			require.Equal(t, 1, writes)
		})
	}
}

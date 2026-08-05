/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clusterconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestReportCASecretKeyState_DetectsLegacyKeyMismatch is the regression test for
// the silent half of findings #249/#222. The pre-flight checker used to look for
// exactly one key and, when it was missing, log Info "TOFU will attempt to
// discover and persist" — so a Secret holding the CA under the legacy read key
// produced no signal at all, and nothing ever surfaced that pinning was inert.
// The checker must now emit a Warning event naming both keys.
func TestReportCASecretKeyState_DetectsLegacyKeyMismatch(t *testing.T) {
	caPEM := []byte("-----BEGIN CERTIFICATE-----\npinned\n-----END CERTIFICATE-----")

	tests := map[string]struct {
		data      map[string][]byte
		key       string
		wantEvent bool
	}{
		"pin under legacy key with no explicit key": {
			data:      map[string][]byte{breakglassv1alpha1.LegacyCASecretKey: caPEM},
			wantEvent: true,
		},
		"pin under canonical key": {
			data:      map[string][]byte{breakglassv1alpha1.DefaultCASecretKey: caPEM},
			wantEvent: false,
		},
		"pin under explicitly configured key": {
			data:      map[string][]byte{"my-ca": caPEM},
			key:       "my-ca",
			wantEvent: false,
		},
		"explicit key set, CA only under legacy key: no legacy fallback, no event": {
			data:      map[string][]byte{breakglassv1alpha1.LegacyCASecretKey: caPEM},
			key:       "my-ca",
			wantEvent: false,
		},
		"no pin at all": {
			data:      nil,
			wantEvent: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			events := make(chan string, 4)
			checker := ClusterConfigChecker{
				Log:      zap.NewNop().Sugar(),
				Client:   newTestFakeClient(),
				Recorder: fakeEventRecorder{Events: events},
			}
			cc := &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "default"},
			}
			secretRef := &breakglassv1alpha1.SecretKeyReference{
				Name: "cluster-ca", Namespace: "default", Key: tc.key,
			}
			caSec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster-ca", Namespace: "default"},
				Data:       tc.data,
			}

			checker.reportCASecretKeyState(cc, secretRef, caSec, checker.Log)

			if !tc.wantEvent {
				assert.Empty(t, events, "checker must stay quiet for a consistent configuration")
				return
			}
			require.Len(t, events, 1, "checker must surface the key mismatch")
			ev := <-events
			assert.Contains(t, ev, corev1.EventTypeWarning)
			assert.Contains(t, ev, "ClusterCASecretLegacyKey")
			assert.Contains(t, ev, breakglassv1alpha1.LegacyCASecretKey)
			assert.Contains(t, ev, breakglassv1alpha1.DefaultCASecretKey)
		})
	}
}

// TestReportCASecretKeyState_NeverFailsTheCheck pins the emergency-access
// requirement: surfacing a key mismatch must not block spoke access. The helper
// has no error return, so this is a compile-time-plus-behaviour guard that a
// mismatch produces a signal and nothing else.
func TestReportCASecretKeyState_NeverFailsTheCheck(t *testing.T) {
	events := make(chan string, 4)
	checker := ClusterConfigChecker{
		Log:      zap.NewNop().Sugar(),
		Client:   newTestFakeClient(),
		Recorder: fakeEventRecorder{Events: events},
	}
	checker.reportCASecretKeyState(
		&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-a"}},
		&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default"},
		&corev1.Secret{Data: map[string][]byte{breakglassv1alpha1.LegacyCASecretKey: []byte("ca")}},
		checker.Log,
	)
	assert.Len(t, events, 1)
}

// TestReportCASecretKeyState_NilRecorder guards the optional-recorder path.
func TestReportCASecretKeyState_NilRecorder(t *testing.T) {
	checker := ClusterConfigChecker{Log: zap.NewNop().Sugar(), Client: newTestFakeClient()}
	checker.reportCASecretKeyState(
		&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster-a"}},
		&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default"},
		&corev1.Secret{Data: map[string][]byte{breakglassv1alpha1.LegacyCASecretKey: []byte("ca")}},
		checker.Log,
	)
}

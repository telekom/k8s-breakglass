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

package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// ephemeralRiskFactors mirrors the shape used by the existing scoring tests.
func ephemeralRiskFactors() breakglassv1alpha1.RiskFactors {
	return breakglassv1alpha1.RiskFactors{
		HostNetwork:         10,
		HostPID:             15,
		HostIPC:             10,
		PrivilegedContainer: 50,
		HostPathWritable:    25,
		HostPathReadOnly:    5,
		RunAsRoot:           20,
		Capabilities:        map[string]int{"NET_ADMIN": 30, "SYS_ADMIN": 40},
	}
}

func newEphemeralTestEvaluator(t *testing.T, objs ...client.Object) *Evaluator {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return NewEvaluator(c, zap.NewNop().Sugar())
}

// ephemeral builds a corev1.EphemeralContainer with the given common spec. Ephemeral
// containers are exactly what a DebugSession injects, which is why DenyPolicy must
// score them.
func ephemeral(name string, sc *corev1.SecurityContext, mounts ...corev1.VolumeMount) corev1.EphemeralContainer {
	return corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            name,
			Image:           "busybox:latest",
			SecurityContext: sc,
			VolumeMounts:    mounts,
		},
	}
}

// TestDetectRiskFactors_InspectsEphemeralContainers covers loop 1 (detectRiskFactors).
// Before the fix allContainers was built from Containers ++ InitContainers only, so a
// privileged / root / capability-carrying EPHEMERAL container produced no risk factors
// at all — the debug primitive was exempt from the guardrail meant to police it.
func TestDetectRiskFactors_InspectsEphemeralContainers(t *testing.T) {
	eval := newEphemeralTestEvaluator(t)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"},
		Spec: corev1.PodSpec{
			// The workload itself is entirely benign.
			Containers: []corev1.Container{{Name: "app", Image: "nginx:latest"}},
			EphemeralContainers: []corev1.EphemeralContainer{
				ephemeral("debugger", &corev1.SecurityContext{
					Privileged: ptr.To(true),
					RunAsUser:  ptr.To(int64(0)),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"SYS_ADMIN"},
					},
				}),
			},
		},
	}

	factors := eval.detectRiskFactors(pod, ephemeralRiskFactors())

	assert.Contains(t, factors, "privilegedContainer:debugger",
		"privileged ephemeral container was not detected")
	assert.Contains(t, factors, "runAsRoot:debugger",
		"root ephemeral container was not detected")
	assert.Contains(t, factors, "capability:SYS_ADMIN:debugger",
		"ephemeral container capability was not detected")
}

// TestCalculateRiskScore_ScoresEphemeralContainers covers loop 2 (calculateRiskScore).
// An understated score is what flips deny into allow at the threshold comparison, so
// scoring — not just factor naming — has to include ephemeral containers.
func TestCalculateRiskScore_ScoresEphemeralContainers(t *testing.T) {
	eval := newEphemeralTestEvaluator(t)
	rf := ephemeralRiskFactors()

	benign := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx:latest"}},
		},
	}
	require.Equal(t, 0, eval.calculateRiskScore(benign, rf),
		"precondition: the workload on its own scores zero")

	withEphemeral := benign.DeepCopy()
	withEphemeral.Spec.EphemeralContainers = []corev1.EphemeralContainer{
		ephemeral("debugger", &corev1.SecurityContext{
			Privileged: ptr.To(true),     // +50
			RunAsUser:  ptr.To(int64(0)), // +20
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"}, // +30
			},
		}),
	}

	assert.Equal(t, 100, eval.calculateRiskScore(withEphemeral, rf),
		"ephemeral container risk was not scored (privileged 50 + root 20 + NET_ADMIN 30)")
}

// TestIsHostPathWritable_InspectsEphemeralContainers covers loop 3 (isHostPathWritable).
// The volume is declared on the pod but mounted read-write ONLY by the ephemeral
// container: before the fix the mount was invisible, so the hostPath scored as
// read-only (5) instead of writable (25).
func TestIsHostPathWritable_InspectsEphemeralContainers(t *testing.T) {
	eval := newEphemeralTestEvaluator(t)
	rf := ephemeralRiskFactors()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				// The workload mounts nothing.
			}},
			EphemeralContainers: []corev1.EphemeralContainer{
				ephemeral("debugger", nil, corev1.VolumeMount{
					Name:      "hostroot",
					MountPath: "/host",
					ReadOnly:  false,
				}),
			},
			Volumes: []corev1.Volume{{
				Name: "hostroot",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/"},
				},
			}},
		},
	}

	assert.True(t, eval.isHostPathWritable(pod, "hostroot"),
		"a read-write hostPath mount in an ephemeral container was treated as read-only")

	factors := eval.detectRiskFactors(pod, rf)
	assert.Contains(t, factors, "hostPathWritable:hostroot")
	assert.NotContains(t, factors, "hostPathReadOnly:hostroot")
	assert.Equal(t, 25, eval.calculateRiskScore(pod, rf),
		"writable hostPath via ephemeral container must score HostPathWritable, not HostPathReadOnly")
}

// TestMatch_DeniesViaEphemeralContainerRisk is the end-to-end guardrail assertion:
// a DenyPolicy whose threshold sits between the benign and the ephemeral-inclusive
// score must now deny. This is the behaviour CHANGE documented under "Upgrade impact".
func TestMatch_DeniesViaEphemeralContainerRisk(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-high-risk"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
				RiskFactors: breakglassv1alpha1.RiskFactors{PrivilegedContainer: 50},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 10, Action: "allow"},
					{MaxScore: 100, Action: "deny"},
				},
			},
		},
	}
	eval := newEphemeralTestEvaluator(t, pol)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx:latest"}},
			EphemeralContainers: []corev1.EphemeralContainer{
				ephemeral("debugger", &corev1.SecurityContext{Privileged: ptr.To(true)}),
			},
		},
	}

	denied, _, err := eval.Match(context.Background(), Action{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   "default",
		Pod:         pod,
	})
	require.NoError(t, err)
	assert.True(t, denied,
		"a privileged ephemeral container must be denied by the DenyPolicy guardrail")
}

// TestEphemeralContainers_NoBehaviourChangeWithoutEphemeral proves backwards
// compatibility: for every pod that carries NO ephemeral containers, the new flattening
// helper produces exactly the old Containers ++ InitContainers slice, so scores and
// factors are byte-identical to the previous implementation.
func TestEphemeralContainers_NoBehaviourChangeWithoutEphemeral(t *testing.T) {
	eval := newEphemeralTestEvaluator(t)
	rf := ephemeralRiskFactors()

	pods := map[string]*corev1.Pod{
		"empty spec": {ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}},
		"regular container only": {
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "app",
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
			}}},
		},
		"init and regular containers": {
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:            "init",
					SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(int64(0))},
				}},
				Containers: []corev1.Container{{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_ADMIN"},
					}},
				}},
			},
		},
	}

	// Expected values computed from the pre-fix semantics (Containers ++ InitContainers).
	want := map[string]int{
		"empty spec":                  0,
		"regular container only":      50,
		"init and regular containers": 50, // root 20 + NET_ADMIN 30
	}

	for name, pod := range pods {
		t.Run(name, func(t *testing.T) {
			flattened := allPodContainers(pod)
			assert.Len(t, flattened,
				len(pod.Spec.Containers)+len(pod.Spec.InitContainers),
				"flattening must not invent containers when EphemeralContainers is empty")
			assert.Equal(t, want[name], eval.calculateRiskScore(pod, rf))
		})
	}
}

// TestAllPodContainers_NilPod guards the helper against a nil pod, which several
// DenyPolicy paths tolerate.
func TestAllPodContainers_NilPod(t *testing.T) {
	assert.Nil(t, allPodContainers(nil))
}

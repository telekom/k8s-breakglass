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

package debug

import (
	"context"
	"errors"
	"net/url"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCleanupOwnershipPreservesReplacementPodTemplateResource(t *testing.T) {
	session := newTestDebugSession("cleanup-owned-pod-template", "template", "cluster", "user@example.com")
	session.UID = types.UID("session-uid")
	session.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{{
		Kind: "ConfigMap", APIVersion: "v1", ResourceName: "script", Namespace: "default", Created: true, UID: "old-uid",
	}}
	replacement := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "script", Namespace: "default", UID: "new-uid"}}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	if err := controller.cleanupPodTemplateResources(context.Background(), session, cl); err == nil {
		t.Fatal("expected UID mismatch to prevent deletion")
	}
	if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), replacement); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupOwnershipPreservesReplacementAuxiliaryResource(t *testing.T) {
	session := newTestDebugSession("cleanup-owned-auxiliary", "template", "cluster", "user@example.com")
	session.UID = types.UID("session-uid")
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{
		Name: "config", Kind: "ConfigMap", APIVersion: "v1", ResourceName: "config", Namespace: "default", Created: true, UID: "old-uid",
	}}
	replacement := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "default", UID: "new-uid"}}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
	mgr := NewAuxiliaryResourceManager(zap.NewNop().Sugar(), nil)

	if err := mgr.CleanupAuxiliaryResources(context.Background(), session, cl); err == nil {
		t.Fatal("expected UID mismatch to prevent deletion")
	}
	if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), replacement); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupOwnershipPreservesReplacementWorkload(t *testing.T) {
	session := newTestDebugSession("cleanup-owned-workload", "template", "cluster", "user@example.com")
	session.UID = types.UID("session-uid")
	session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{
		Kind: "Deployment", APIVersion: "apps/v1", Name: "debug-workload", Namespace: "default", Source: "debug-pod", UID: "old-uid",
	}}
	replacement := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "debug-workload", Namespace: "default", UID: "new-uid"}}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	if err := controller.cleanupDeployedResources(context.Background(), session, cl, false, false); err == nil {
		t.Fatal("expected UID mismatch to prevent deletion")
	}
	if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), replacement); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupOwnershipPreservesReplacementQuotaAndPDB(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
		api  string
		obj  ctrlclient.Object
	}{
		{name: "quota", kind: "ResourceQuota", api: "v1", obj: &corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "debug-rq", Namespace: "default", UID: "new-uid"}}},
		{name: "pdb", kind: "PodDisruptionBudget", api: "policy/v1", obj: &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "debug-pdb", Namespace: "default", UID: "new-uid"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := newTestDebugSession("cleanup-owned-"+tc.name, "template", "cluster", "user@example.com")
			session.UID = types.UID("session-uid")
			session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{
				Kind: tc.kind, APIVersion: tc.api, Name: tc.obj.GetName(), Namespace: tc.obj.GetNamespace(), Source: "debug-" + tc.name, UID: "old-uid",
			}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(tc.obj).Build()
			controller := &DebugSessionController{log: zap.NewNop().Sugar()}
			err := controller.cleanupDeployedResources(context.Background(), session, cl, false, false)
			if err == nil {
				t.Fatal("expected UID mismatch to prevent deletion")
			}
			if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(tc.obj), tc.obj); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCleanupOwnershipDeletesOwnedNodeDebugPod(t *testing.T) {
	session := newTestDebugSession("cleanup-owned-node-pod", "template", "cluster", "user@example.com")
	session.UID = types.UID("session-uid")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:        "node-debugger-worker-debug",
		Namespace:   "default",
		UID:         "node-pod-uid",
		Annotations: map[string]string{sourceSessionUIDAnnotation: string(session.UID)},
	}}
	session.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{
		Kind: "Pod", APIVersion: "v1", Name: pod.Name, Namespace: pod.Namespace, Source: "debug-node", UID: string(pod.UID),
	}}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).Build()
	controller := &DebugSessionController{log: zap.NewNop().Sugar()}

	if err := controller.cleanupDeployedResources(context.Background(), session, cl, false, false); err != nil {
		t.Fatal(err)
	}
	if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(pod), pod); err == nil {
		t.Fatal("expected owned node debug pod to be deleted")
	}
}

func TestCleanupOwnershipPreservesReplacementCopiedPod(t *testing.T) {
	session := newTestDebugSession("cleanup-owned-copy", "template", "cluster", "user@example.com")
	session.UID = types.UID("session-uid")
	copyRef := breakglassv1alpha1.CopiedPodRef{CopyName: "debug-copy", CopyNamespace: "default", UID: "old-copy-uid"}
	replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: copyRef.CopyName, Namespace: copyRef.CopyNamespace, UID: "new-copy-uid"}}
	cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: copyRef.CopyName, Namespace: copyRef.CopyNamespace}}

	if err := deleteOwnedResource(context.Background(), cl, pod, copyRef.UID, session); err == nil {
		t.Fatal("expected copied-pod UID mismatch to prevent deletion")
	}
	if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), replacement); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupOwnershipRefusesUnidentifiedLegacyObjects(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sessionUID types.UID
		objectUID  types.UID
	}{
		{name: "both empty"},
		{name: "missing marker", sessionUID: types.UID("session-uid"), objectUID: types.UID("object-uid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := newTestDebugSession("cleanup-unidentified", "template", "cluster", "user@example.com")
			session.UID = tc.sessionUID
			obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "default", UID: tc.objectUID}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(obj).Build()
			candidate := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: obj.Name, Namespace: obj.Namespace}}
			if err := deleteOwnedResource(context.Background(), cl, candidate, "", session); err == nil {
				t.Fatal("expected unidentified object to be preserved")
			}
			if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeleteOrphanedPodPreservesReplacements(t *testing.T) {
	sessionUID := types.UID("session-uid")
	for _, name := range []string{"copied-pod", "node-debug-pod"} {
		t.Run(name, func(t *testing.T) {
			replacement := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: "default", UID: "replacement-uid",
				Annotations: map[string]string{sourceSessionUIDAnnotation: string(sessionUID)},
			}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(replacement).Build()
			orphan := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: "default", UID: "original-uid",
				Annotations: map[string]string{sourceSessionUIDAnnotation: string(sessionUID)},
			}}
			h := &KubectlDebugHandler{}
			h.deleteOrphanedPod(context.Background(), cl, orphan, errors.New("status patch failed"))
			if err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(replacement), replacement); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoverAmbiguousCreatedPod(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		createErr   error
		wantGone    bool
	}{
		{name: "accepted response lost", annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}, createErr: &url.Error{Op: "POST", URL: "https://api.invalid", Err: errors.New("connection reset")}, wantGone: true},
		{name: "already exists preserved", annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}, createErr: apierrors.NewAlreadyExists(corev1.Resource("pods"), "copy"), wantGone: false},
		{name: "forbidden preserved", annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}, createErr: apierrors.NewForbidden(corev1.Resource("pods"), "copy", errors.New("denied")), wantGone: false},
		{name: "invalid preserved", annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}, createErr: apierrors.NewInvalid(schema.GroupKind{Kind: "Pod"}, "copy", nil), wantGone: false},
		{name: "unowned preserved", annotations: map[string]string{sourceSessionUIDAnnotation: "other-session"}, createErr: &url.Error{Op: "POST", URL: "https://api.invalid", Err: errors.New("connection reset")}, wantGone: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "copy", Namespace: "default", UID: "created-uid", Annotations: tc.annotations}}
			cl := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pod).Build()
			h := &KubectlDebugHandler{}
			h.recoverAmbiguousCreatedPod(context.Background(), cl, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "copy", Namespace: "default", Annotations: map[string]string{sourceSessionUIDAnnotation: "session-uid"}}}, tc.createErr)
			var got corev1.Pod
			err := cl.Get(context.Background(), ctrlclient.ObjectKeyFromObject(pod), &got)
			if (err == nil) != !tc.wantGone {
				t.Fatalf("pod presence=%v, wantGone=%v, err=%v", err == nil, tc.wantGone, err)
			}
		})
	}
}

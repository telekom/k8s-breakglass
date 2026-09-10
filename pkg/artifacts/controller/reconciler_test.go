// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func artifactForValidation() breakglassv1alpha1.DebugSessionArtifact {
	return breakglassv1alpha1.DebugSessionArtifact{
		ObjectMeta: metav1.ObjectMeta{Name: "dsa-000000000000000000000000", Namespace: "breakglass", UID: types.UID("artifact-uid")},
		Spec:       breakglassv1alpha1.DebugSessionArtifactSpec{ArtifactID: "dsa-000000000000000000000000", SessionRef: breakglassv1alpha1.ArtifactSessionReference{Namespace: "breakglass", Name: "session", UID: "session-uid"}},
		Status:     breakglassv1alpha1.DebugSessionArtifactStatus{},
	}
}

func TestValidateTokenSecretRequiresArtifactOwnerAndImmutableToken(t *testing.T) {
	artifact := artifactForValidation()
	controller := true
	valid := corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: artifact.Namespace, OwnerReferences: []metav1.OwnerReference{{Kind: "DebugSessionArtifact", UID: artifact.UID, Controller: &controller}}}, Immutable: boolPtr(true), Data: map[string][]byte{"token": []byte("signed")}}
	if err := validateTokenSecret(valid, artifact); err != nil {
		t.Fatalf("valid token Secret rejected: %v", err)
	}
	for name, mutate := range map[string]func(*corev1.Secret){
		"mutable":       func(secret *corev1.Secret) { secret.Immutable = boolPtr(false) },
		"missing token": func(secret *corev1.Secret) { delete(secret.Data, "token") },
		"wrong owner":   func(secret *corev1.Secret) { secret.OwnerReferences[0].UID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := valid.DeepCopy()
			mutate(copy)
			if err := validateTokenSecret(*copy, artifact); err == nil {
				t.Fatal("invalid token Secret accepted")
			}
		})
	}
}

func TestValidateCollectorJobRequiresMatchingArtifactOwnership(t *testing.T) {
	artifact := artifactForValidation()
	controller := true
	group := int64(65532)
	valid := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: artifact.Namespace, Annotations: map[string]string{"breakglass.t-caas.telekom.com/plan-sha256": artifact.Spec.PlanDigest}, Labels: map[string]string{"breakglass.t-caas.telekom.com/artifact": artifact.Spec.ArtifactID, "breakglass.t-caas.telekom.com/session-uid": string(artifact.Spec.SessionRef.UID)}, OwnerReferences: []metav1.OwnerReference{{Kind: "DebugSessionArtifact", UID: artifact.UID, Controller: &controller}}}, Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"breakglass.t-caas.telekom.com/plan-sha256": artifact.Spec.PlanDigest}}, Spec: corev1.PodSpec{AutomountServiceAccountToken: boolPtr(false), SecurityContext: &corev1.PodSecurityContext{FSGroup: &group}, InitContainers: []corev1.Container{{Name: "collector"}}, Containers: []corev1.Container{{Name: "uploader"}}}}}}
	if err := validateCollectorJob(valid, artifact); err != nil {
		t.Fatalf("valid collector Job rejected: %v", err)
	}
	for name, mutate := range map[string]func(*batchv1.Job){
		"wrong artifact label":    func(job *batchv1.Job) { job.Labels["breakglass.t-caas.telekom.com/artifact"] = "other" },
		"wrong owner":             func(job *batchv1.Job) { job.OwnerReferences[0].UID = "other" },
		"wrong namespace":         func(job *batchv1.Job) { job.Namespace = "other" },
		"side-by-side containers": func(job *batchv1.Job) { job.Spec.Template.Spec.InitContainers = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copy := valid.DeepCopy()
			mutate(copy)
			if err := validateCollectorJob(*copy, artifact); err == nil {
				t.Fatal("invalid collector Job accepted")
			}
		})
	}
}

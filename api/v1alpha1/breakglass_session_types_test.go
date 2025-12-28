/*
Copyright 2024.

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

package v1alpha1

import (
	"context"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestValidateCreate_MissingFields(t *testing.T) {
	bs := &BreakglassSession{}
	_, err := bs.ValidateCreate(context.Background(), bs)
	if err == nil {
		t.Fatalf("expected ValidateCreate to return error for missing required fields")
	}
}

func TestValidateCreate_Success(t *testing.T) {
	bs := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s1"},
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			User:         "user@example.com",
			GrantedGroup: "some-group",
		},
	}
	_, err := bs.ValidateCreate(context.Background(), bs)
	if err != nil {
		t.Fatalf("expected ValidateCreate to succeed but got error: %v", err)
	}
}

func TestValidateUpdate_ImmutableSpec(t *testing.T) {
	old := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s2"},
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			User:         "user@example.com",
			GrantedGroup: "group-a",
		},
	}
	// modified spec should fail
	modified := old.DeepCopy()
	modified.Spec.GrantedGroup = "group-b"
	_, err := modified.ValidateUpdate(context.Background(), old, modified)
	if err == nil {
		t.Fatalf("expected ValidateUpdate to return error when spec changed")
	}

	// identical spec should succeed
	same := old.DeepCopy()
	_, err = same.ValidateUpdate(context.Background(), old, same)
	if err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec unchanged, got: %v", err)
	}

	// also ensure DeepCopy produced equal spec
	if !reflect.DeepEqual(old.Spec, same.Spec) {
		t.Fatalf("sanity: deep copy produced different spec")
	}
}

func TestBreakglassSessionSetCondition(t *testing.T) {
	bs := &BreakglassSession{}
	cond := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue}
	bs.SetCondition(cond)
	if len(bs.Status.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(bs.Status.Conditions))
	}
	bs.SetCondition(metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse})
	got := bs.GetCondition("Ready")
	if got == nil || got.Status != metav1.ConditionFalse {
		t.Fatalf("expected Ready condition to be updated, got %#v", got)
	}
}

func TestBreakglassSessionGetConditionMissing(t *testing.T) {
	bs := &BreakglassSession{}
	if bs.GetCondition("does-not-exist") != nil {
		t.Fatal("expected missing condition to return nil")
	}
}

func TestBreakglassSessionValidateDelete(t *testing.T) {
	bs := &BreakglassSession{}
	warnings, err := bs.ValidateDelete(context.Background(), bs)
	if err != nil || warnings != nil {
		t.Fatalf("expected ValidateDelete to allow delete, warnings=%v err=%v", warnings, err)
	}
}

func TestBreakglassSessionClusterConfigRefMissingIsAccepted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: "team-a"},
		Spec: BreakglassSessionSpec{
			Cluster:          "cluster1",
			User:             "user@example.com",
			GrantedGroup:     "team",
			ClusterConfigRef: "cluster-a",
		},
	}

	if _, err := session.ValidateCreate(context.Background(), session); err != nil {
		t.Fatalf("expected webhook to accept missing clusterConfigRef, got %v", err)
	}
}

func TestBreakglassSessionClusterConfigRefCrossNamespaceAccepted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "team-b"},
		Spec:       ClusterConfigSpec{KubeconfigSecretRef: SecretKeyReference{Name: "kc", Namespace: "system"}},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clusterConfig).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: "team-a"},
		Spec: BreakglassSessionSpec{
			Cluster:          "cluster1",
			User:             "user@example.com",
			GrantedGroup:     "team",
			ClusterConfigRef: "cluster-a",
		},
	}

	if _, err := session.ValidateCreate(context.Background(), session); err != nil {
		t.Fatalf("expected webhook to accept cross-namespace clusterConfigRef, got %v", err)
	}
}

func TestBreakglassSessionClusterConfigRefHappyPath(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "team-a"},
		Spec:       ClusterConfigSpec{KubeconfigSecretRef: SecretKeyReference{Name: "kc", Namespace: "system"}},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clusterConfig).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: "team-a"},
		Spec: BreakglassSessionSpec{
			Cluster:          "cluster1",
			User:             "user@example.com",
			GrantedGroup:     "team",
			ClusterConfigRef: "cluster-a",
		},
	}

	if _, err := session.ValidateCreate(context.Background(), session); err != nil {
		t.Fatalf("expected success when clusterConfigRef exists in namespace, got %v", err)
	}
}

func TestBreakglassSessionDenyPolicyRefsValidationDeferred(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	policy := &DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy-a"}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build()
	origClient := webhookClient
	defer func() { webhookClient = origClient }()
	webhookClient = client

	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess", Namespace: "team-a"},
		Spec: BreakglassSessionSpec{
			Cluster:        "cluster1",
			User:           "user@example.com",
			GrantedGroup:   "team",
			DenyPolicyRefs: []string{"policy-a"},
		},
	}

	if _, err := session.ValidateCreate(context.Background(), session); err != nil {
		t.Fatalf("expected success when denyPolicyRefs exist, got %v", err)
	}

	session.Spec.DenyPolicyRefs = []string{"missing"}
	if _, err := session.ValidateCreate(context.Background(), session); err != nil {
		t.Fatalf("expected webhook to accept missing denyPolicyRefs, got %v", err)
	}
}

func TestBreakglassSession_ValidateCreate_WrongType(t *testing.T) {
	session := &BreakglassSession{}
	wrongType := &ClusterConfig{}
	_, err := session.ValidateCreate(context.Background(), wrongType)
	if err == nil {
		t.Fatal("expected error when obj is wrong type")
	}
}

func TestBreakglassSession_ValidateCreate_MissingCluster(t *testing.T) {
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			User:         "user@example.com",
			GrantedGroup: "group",
			// Cluster is missing
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when cluster is missing")
	}
}

func TestBreakglassSession_ValidateCreate_MissingUser(t *testing.T) {
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			GrantedGroup: "group",
			// User is missing
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when user is missing")
	}
}

func TestBreakglassSession_ValidateCreate_MissingGrantedGroup(t *testing.T) {
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster: "cluster1",
			User:    "user@example.com",
			// GrantedGroup is missing
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when grantedGroup is missing")
	}
}

func TestBreakglassSession_ValidateCreate_ScheduledStartTimePast(t *testing.T) {
	pastTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:            "cluster1",
			User:               "user@example.com",
			GrantedGroup:       "group",
			ScheduledStartTime: &pastTime,
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when scheduledStartTime is in the past")
	}
}

func TestBreakglassSession_ValidateCreate_ScheduledStartTimeTooSoon(t *testing.T) {
	soonTime := metav1.NewTime(time.Now().Add(1 * time.Minute))
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:            "cluster1",
			User:               "user@example.com",
			GrantedGroup:       "group",
			ScheduledStartTime: &soonTime,
		},
	}
	_, err := session.ValidateCreate(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when scheduledStartTime is less than 5 minutes in the future")
	}
}

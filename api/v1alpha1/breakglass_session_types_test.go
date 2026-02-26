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

func TestValidateUpdate_StateTransitionValidation(t *testing.T) {
	base := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s3"},
		Spec: BreakglassSessionSpec{
			Cluster:      "cluster1",
			User:         "user@example.com",
			GrantedGroup: "group-a",
		},
	}

	cases := []struct {
		name    string
		from    BreakglassSessionState
		to      BreakglassSessionState
		wantErr bool
	}{
		// Valid transitions
		{name: "empty to pending", from: "", to: SessionStatePending, wantErr: false},
		{name: "pending to approved", from: SessionStatePending, to: SessionStateApproved, wantErr: false},
		{name: "pending to waiting", from: SessionStatePending, to: SessionStateWaitingForScheduledTime, wantErr: false},
		{name: "pending to rejected", from: SessionStatePending, to: SessionStateRejected, wantErr: false},
		{name: "pending to withdrawn", from: SessionStatePending, to: SessionStateWithdrawn, wantErr: false},
		{name: "pending to timeout", from: SessionStatePending, to: SessionStateTimeout, wantErr: false},
		{name: "waiting to approved", from: SessionStateWaitingForScheduledTime, to: SessionStateApproved, wantErr: false},
		{name: "waiting to withdrawn", from: SessionStateWaitingForScheduledTime, to: SessionStateWithdrawn, wantErr: false},
		{name: "approved to expired", from: SessionStateApproved, to: SessionStateExpired, wantErr: false},
		{name: "approved to idleExpired", from: SessionStateApproved, to: SessionStateIdleExpired, wantErr: false},
		// Same-state transitions (idempotent reconciliation)
		{name: "pending to pending", from: SessionStatePending, to: SessionStatePending, wantErr: false},
		{name: "approved to approved", from: SessionStateApproved, to: SessionStateApproved, wantErr: false},
		{name: "rejected to rejected", from: SessionStateRejected, to: SessionStateRejected, wantErr: false},
		{name: "expired to expired", from: SessionStateExpired, to: SessionStateExpired, wantErr: false},
		{name: "withdrawn to withdrawn", from: SessionStateWithdrawn, to: SessionStateWithdrawn, wantErr: false},
		{name: "timeout to timeout", from: SessionStateTimeout, to: SessionStateTimeout, wantErr: false},
		{name: "idleExpired to idleExpired", from: SessionStateIdleExpired, to: SessionStateIdleExpired, wantErr: false},
		// Invalid transitions
		{name: "approved to pending", from: SessionStateApproved, to: SessionStatePending, wantErr: true},
		{name: "rejected to approved", from: SessionStateRejected, to: SessionStateApproved, wantErr: true},
		{name: "rejected to pending", from: SessionStateRejected, to: SessionStatePending, wantErr: true},
		{name: "withdrawn to approved", from: SessionStateWithdrawn, to: SessionStateApproved, wantErr: true},
		{name: "withdrawn to pending", from: SessionStateWithdrawn, to: SessionStatePending, wantErr: true},
		{name: "expired to approved", from: SessionStateExpired, to: SessionStateApproved, wantErr: true},
		{name: "expired to pending", from: SessionStateExpired, to: SessionStatePending, wantErr: true},
		{name: "timeout to approved", from: SessionStateTimeout, to: SessionStateApproved, wantErr: true},
		{name: "timeout to pending", from: SessionStateTimeout, to: SessionStatePending, wantErr: true},
		// IdleExpired is terminal
		{name: "idleExpired to approved", from: SessionStateIdleExpired, to: SessionStateApproved, wantErr: true},
		{name: "idleExpired to pending", from: SessionStateIdleExpired, to: SessionStatePending, wantErr: true},
		// Cannot idle-expire from non-approved states
		{name: "pending to idleExpired", from: SessionStatePending, to: SessionStateIdleExpired, wantErr: true},
		{name: "rejected to idleExpired", from: SessionStateRejected, to: SessionStateIdleExpired, wantErr: true},
		// Invalid transition from waiting (cannot go to rejected)
		{name: "waiting to rejected", from: SessionStateWaitingForScheduledTime, to: SessionStateRejected, wantErr: true},
		{name: "waiting to pending", from: SessionStateWaitingForScheduledTime, to: SessionStatePending, wantErr: true},
		// Unknown state falls through to default (invalid)
		{name: "unknown to pending", from: BreakglassSessionState("unknown"), to: SessionStatePending, wantErr: true},
		{name: "empty to approved", from: "", to: SessionStateApproved, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := base.DeepCopy()
			old.Status.State = tc.from
			updated := base.DeepCopy()
			updated.Status.State = tc.to

			_, err := updated.ValidateUpdate(context.Background(), old, updated)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for transition %q -> %q", tc.from, tc.to)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for transition %q -> %q: %v", tc.from, tc.to, err)
			}
		})
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
		Spec:       ClusterConfigSpec{KubeconfigSecretRef: &SecretKeyReference{Name: "kc", Namespace: "system"}},
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
		Spec:       ClusterConfigSpec{KubeconfigSecretRef: &SecretKeyReference{Name: "kc", Namespace: "system"}},
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

func TestValidateUpdate_MonotonicActivityCount(t *testing.T) {
	spec := BreakglassSessionSpec{Cluster: "c", User: "u", GrantedGroup: "g"}

	t.Run("increasing activityCount is allowed", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, ActivityCount: 5,
		}}
		updated := old.DeepCopy()
		updated.Status.ActivityCount = 10
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err != nil {
			t.Fatalf("expected no error for increasing activityCount, got: %v", err)
		}
	})

	t.Run("same activityCount is allowed", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, ActivityCount: 5,
		}}
		updated := old.DeepCopy()
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err != nil {
			t.Fatalf("expected no error for same activityCount, got: %v", err)
		}
	})

	t.Run("decreasing activityCount is rejected", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, ActivityCount: 10,
		}}
		updated := old.DeepCopy()
		updated.Status.ActivityCount = 5
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err == nil {
			t.Fatal("expected error for decreasing activityCount")
		}
	})
}

func TestValidateUpdate_MonotonicLastActivity(t *testing.T) {
	spec := BreakglassSessionSpec{Cluster: "c", User: "u", GrantedGroup: "g"}
	now := metav1.Now()
	earlier := metav1.NewTime(now.Add(-10 * time.Minute))
	later := metav1.NewTime(now.Add(10 * time.Minute))

	t.Run("advancing lastActivity is allowed", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, LastActivity: &earlier,
		}}
		updated := old.DeepCopy()
		updated.Status.LastActivity = &later
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err != nil {
			t.Fatalf("expected no error for advancing lastActivity, got: %v", err)
		}
	})

	t.Run("same lastActivity is allowed", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, LastActivity: &now,
		}}
		updated := old.DeepCopy()
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err != nil {
			t.Fatalf("expected no error for same lastActivity, got: %v", err)
		}
	})

	t.Run("regressing lastActivity is rejected", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, LastActivity: &later,
		}}
		updated := old.DeepCopy()
		updated.Status.LastActivity = &earlier
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err == nil {
			t.Fatal("expected error for regressing lastActivity")
		}
	})

	t.Run("nil to set lastActivity is allowed", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved,
		}}
		updated := old.DeepCopy()
		updated.Status.LastActivity = &now
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err != nil {
			t.Fatalf("expected no error for nil-to-set lastActivity, got: %v", err)
		}
	})

	t.Run("clearing lastActivity is rejected", func(t *testing.T) {
		old := &BreakglassSession{Spec: spec, Status: BreakglassSessionStatus{
			State: SessionStateApproved, LastActivity: &now,
		}}
		updated := old.DeepCopy()
		updated.Status.LastActivity = nil
		_, err := updated.ValidateUpdate(context.Background(), old, updated)
		if err == nil {
			t.Fatal("expected error for clearing lastActivity")
		}
	})
}

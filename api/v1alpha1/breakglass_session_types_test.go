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
	"encoding/json"
	"reflect"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
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
			// Access-bearing transitions are valid only with a live lease. For
			// scheduled activation the lease was initialized before entering
			// WaitingForScheduledTime; for approval it is established by the
			// approval update itself.
			if (tc.from == SessionStatePending &&
				(tc.to == SessionStateApproved || tc.to == SessionStateWaitingForScheduledTime)) ||
				(tc.from == SessionStateWaitingForScheduledTime && tc.to == SessionStateApproved) {
				old.Status.ExpiresAt = metav1.NewTime(time.Now().Add(time.Hour))
				// Promotion out of Pending is valid only while its approval
				// deadline is still live.
				old.Status.TimeoutAt = metav1.NewTime(time.Now().Add(time.Hour))
				updated.Status.ExpiresAt = old.Status.ExpiresAt
				updated.Status.TimeoutAt = old.Status.TimeoutAt
			}

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

func TestValidateUpdate_ExpiryCannotResurrectApprovedSession(t *testing.T) {
	now := time.Now()
	base := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expiry-guard"},
		Spec:       BreakglassSessionSpec{Cluster: "cluster1", User: "user@example.com", GrantedGroup: "group-a"},
		Status: BreakglassSessionStatus{
			State: SessionStateApproved, ExpiresAt: metav1.NewTime(now.Add(-time.Minute)),
		},
	}

	postBoundary := base.DeepCopy()
	postBoundary.Status.ExpiresAt = metav1.NewTime(now.Add(time.Hour))
	if _, err := postBoundary.ValidateUpdate(context.Background(), base, postBoundary); err == nil {
		t.Fatal("expected post-boundary future expiry write to be rejected")
	}

	shortened := base.DeepCopy()
	shortened.Status.ExpiresAt = metav1.NewTime(now.Add(-2 * time.Minute))
	if _, err := shortened.ValidateUpdate(context.Background(), base, shortened); err != nil {
		t.Fatalf("expected active expiry shortening to remain valid: %v", err)
	}

	terminal := postBoundary.DeepCopy()
	terminal.Status.State = SessionStateExpired
	terminal.Status.ExpiresAt = metav1.NewTime(now)
	if _, err := terminal.ValidateUpdate(context.Background(), postBoundary, terminal); err != nil {
		t.Fatalf("expected terminal revocation with shortened expiry to remain valid: %v", err)
	}

	staleTerminal := base.DeepCopy()
	staleTerminal.Status.State = SessionStateExpired
	staleTerminal.Status.ExpiresAt = metav1.NewTime(now)
	if _, err := staleTerminal.ValidateUpdate(context.Background(), base, staleTerminal); err == nil {
		t.Fatal("expected terminal transition after the old boundary to retain the elapsed expiry")
	}

	pending := base.DeepCopy()
	pending.Status.State = SessionStatePending
	pending.Status.ExpiresAt = metav1.Time{}
	pending.Status.TimeoutAt = metav1.NewTime(now.Add(time.Minute))
	approved := pending.DeepCopy()
	approved.Status.State = SessionStateApproved
	approved.Status.ExpiresAt = metav1.NewTime(now.Add(time.Hour))
	if _, err := approved.ValidateUpdate(context.Background(), pending, approved); err != nil {
		t.Fatalf("expected initial pre-boundary approval expiry to be valid: %v", err)
	}
	missingTimeout := pending.DeepCopy()
	missingTimeout.Status.TimeoutAt = metav1.Time{}
	if _, err := approved.ValidateUpdate(context.Background(), missingTimeout, approved); err == nil {
		t.Fatal("expected pending promotion without TimeoutAt to be rejected")
	}
	expiredTimeout := pending.DeepCopy()
	expiredTimeout.Status.TimeoutAt = metav1.NewTime(now)
	if _, err := approved.ValidateUpdate(context.Background(), expiredTimeout, approved); err == nil {
		t.Fatal("expected pending promotion at TimeoutAt boundary to be rejected")
	}

	waiting := pending.DeepCopy()
	waiting.Status.State = SessionStateWaitingForScheduledTime
	waiting.Status.ExpiresAt = metav1.NewTime(now.Add(time.Minute))
	waitingExpired := waiting.DeepCopy()
	waitingExpired.Status.ExpiresAt = metav1.NewTime(now.Add(-time.Minute))
	if _, err := waitingExpired.ValidateUpdate(context.Background(), waiting, waitingExpired); err != nil {
		t.Fatalf("expected scheduled lease shortening to remain valid: %v", err)
	}
	waitingFuture := waiting.DeepCopy()
	waitingFuture.Status.ExpiresAt = metav1.NewTime(now.Add(time.Hour))
	if _, err := waitingFuture.ValidateUpdate(context.Background(), waiting, waitingFuture); err == nil {
		t.Fatal("expected scheduled lease extension to be rejected")
	}
	waitingRevive := waiting.DeepCopy()
	waitingRevive.Status.ExpiresAt = metav1.NewTime(now.Add(-time.Minute))
	waitingRevive.Status.State = SessionStateApproved
	if _, err := waitingRevive.ValidateUpdate(context.Background(), waitingExpired, waitingRevive); err == nil {
		t.Fatal("expected expired scheduled session activation to be rejected")
	}

	terminalZero := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "terminal-zero"},
		Spec:       BreakglassSessionSpec{Cluster: "cluster1", User: "user@example.com", GrantedGroup: "group-a"},
		Status:     BreakglassSessionStatus{State: SessionStateExpired},
	}
	terminalFuture := terminalZero.DeepCopy()
	terminalFuture.Status.ExpiresAt = metav1.NewTime(now.Add(time.Hour))
	if _, err := terminalFuture.ValidateUpdate(context.Background(), terminalZero, terminalFuture); err == nil {
		t.Fatal("expected terminal zero-expiry future write to be rejected")
	}

	// A malformed Pending object must not be promoted into an access-bearing
	// state with a missing or already-elapsed lease.
	for _, state := range []BreakglassSessionState{SessionStateApproved, SessionStateWaitingForScheduledTime} {
		pendingExpired := pending.DeepCopy()
		pendingExpired.Status.ExpiresAt = metav1.NewTime(now.Add(-time.Second))
		promoted := pendingExpired.DeepCopy()
		promoted.Status.State = state
		if _, err := promoted.ValidateUpdate(context.Background(), pendingExpired, promoted); err == nil {
			t.Fatalf("expected pending -> %s with an expired lease to be rejected", state)
		}

		pendingZero := pending.DeepCopy()
		promotedZero := pendingZero.DeepCopy()
		promotedZero.Status.State = state
		if _, err := promotedZero.ValidateUpdate(context.Background(), pendingZero, promotedZero); err == nil {
			t.Fatalf("expected pending -> %s with a missing lease to be rejected", state)
		}
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

func TestBreakglassSessionValidateDeleteBlocksPendingDuplicateAudit(t *testing.T) {
	bs := &BreakglassSession{Status: BreakglassSessionStatus{State: SessionStateWithdrawn}}
	bs.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeDuplicateCleanupAuditComplete),
		Status:             metav1.ConditionFalse,
		Reason:             "PendingDelivery",
		LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	})
	if _, err := bs.ValidateDelete(context.Background(), bs); err == nil {
		t.Fatal("expected deletion to be blocked while duplicate cleanup audit is pending")
	}

	bs.SetCondition(metav1.Condition{
		Type:   string(SessionConditionTypeDuplicateCleanupAuditComplete),
		Status: metav1.ConditionTrue,
		Reason: "EmissionAccepted",
	})
	if _, err := bs.ValidateDelete(context.Background(), bs); err != nil {
		t.Fatalf("expected acknowledged audit to permit deletion: %v", err)
	}
}

func TestBreakglassSessionDeleteAllowsForgedDuplicateAudit(t *testing.T) {
	for _, condition := range []metav1.Condition{
		{Type: string(SessionConditionTypeDuplicateCleanupAuditComplete), Status: metav1.ConditionUnknown, Reason: "WithdrawDecision", LastTransitionTime: metav1.NewTime(time.Unix(100, 0))},
		{Type: string(SessionConditionTypeDuplicateCleanupAuditComplete), Status: metav1.ConditionFalse, Reason: "Forged", LastTransitionTime: metav1.NewTime(time.Unix(100, 0))},
		{Type: string(SessionConditionTypeDuplicateCleanupAuditComplete), Status: metav1.ConditionFalse, Reason: "WithdrawDecision"},
	} {
		bs := &BreakglassSession{Status: BreakglassSessionStatus{State: SessionStateWithdrawn, Conditions: []metav1.Condition{condition}}}
		if _, err := bs.ValidateDelete(context.Background(), bs); err != nil {
			t.Fatalf("expected a duplicate audit condition that is not genuinely pending to permit deletion: %v", err)
		}
	}
}

func TestBreakglassSessionValidateDeleteBlocksPendingExpiryNotificationIntent(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(100, 0))
	bs := &BreakglassSession{Status: BreakglassSessionStatus{State: SessionStateExpired}}
	bs.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeExpired),
		Status:             metav1.ConditionTrue,
		Reason:             "ExpiredByTime",
		LastTransitionTime: intentTime,
	})
	bs.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeExpiryNotificationIntent),
		Status:             metav1.ConditionFalse,
		Reason:             "PendingEnqueue",
		LastTransitionTime: intentTime,
	})
	if _, err := bs.ValidateDelete(context.Background(), bs); err == nil {
		t.Fatal("expected deletion to be blocked while expiry notification is pending")
	}

	bs.SetCondition(metav1.Condition{
		Type:   string(SessionConditionTypeExpiryNotificationIntent),
		Status: metav1.ConditionTrue,
		Reason: "QueueAccepted",
	})
	if _, err := bs.ValidateDelete(context.Background(), bs); err != nil {
		t.Fatalf("expected acknowledged expiry notification to permit deletion: %v", err)
	}
}

func TestBreakglassSessionDeleteAllowsForgedExpiryNotificationCondition(t *testing.T) {
	for _, condition := range []metav1.Condition{
		{Type: string(SessionConditionTypeExpiryNotificationIntent), Status: metav1.ConditionUnknown, Reason: "PendingEnqueue", LastTransitionTime: metav1.NewTime(time.Unix(100, 0))},
		{Type: string(SessionConditionTypeExpiryNotificationIntent), Status: metav1.ConditionFalse, Reason: "Forged", LastTransitionTime: metav1.NewTime(time.Unix(100, 0))},
		{Type: string(SessionConditionTypeExpiryNotificationIntent), Status: metav1.ConditionFalse, Reason: "PendingEnqueue"},
	} {
		bs := &BreakglassSession{Status: BreakglassSessionStatus{Conditions: []metav1.Condition{condition}}}
		if _, err := bs.ValidateDelete(context.Background(), bs); err != nil {
			t.Fatalf("expected a condition that is not genuinely pending to permit deletion: %v", err)
		}
	}

	intentTime := metav1.NewTime(time.Unix(100, 0))
	forgedActive := &BreakglassSession{Status: BreakglassSessionStatus{
		State: SessionStateApproved,
		Conditions: []metav1.Condition{
			{Type: string(SessionConditionTypeExpired), Status: metav1.ConditionTrue, LastTransitionTime: intentTime},
			{Type: string(SessionConditionTypeExpiryNotificationIntent), Status: metav1.ConditionFalse, Reason: "PendingEnqueue", LastTransitionTime: intentTime},
		},
	}}
	if _, err := forgedActive.ValidateDelete(context.Background(), forgedActive); err != nil {
		t.Fatalf("expected an active forged condition not to block deletion: %v", err)
	}
}

func TestValidateExpiryNotificationIntent(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(100, 0))
	oldObj := &BreakglassSession{Status: BreakglassSessionStatus{State: SessionStateApproved}}
	pending := oldObj.DeepCopy()
	pending.Status.State = SessionStateExpired
	pending.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeExpired),
		Status:             metav1.ConditionTrue,
		Reason:             "ExpiredByTime",
		LastTransitionTime: intentTime,
	})
	pending.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeExpiryNotificationIntent),
		Status:             metav1.ConditionFalse,
		Reason:             "PendingEnqueue",
		LastTransitionTime: intentTime,
	})
	if errs := validateExpiryNotificationIntent(oldObj, pending); len(errs) != 0 {
		t.Fatalf("expected terminal expiry and notification intent to be created together: %v", errs)
	}

	for _, reason := range []string{"QueueAccepted", "NotificationsDisabled"} {
		acknowledged := pending.DeepCopy()
		condition := acknowledged.GetCondition(string(SessionConditionTypeExpiryNotificationIntent))
		condition.Status = metav1.ConditionTrue
		condition.Reason = reason
		if errs := validateExpiryNotificationIntent(pending, acknowledged); len(errs) != 0 {
			t.Fatalf("expected %s acknowledgement to be valid: %v", reason, errs)
		}
	}

	invalidChanges := map[string]func(*BreakglassSession){
		"remove intent": func(obj *BreakglassSession) {
			obj.Status.Conditions = obj.Status.Conditions[:1]
		},
		"change timestamp": func(obj *BreakglassSession) {
			obj.GetCondition(string(SessionConditionTypeExpiryNotificationIntent)).LastTransitionTime = metav1.NewTime(intentTime.Add(time.Second))
		},
		"forge reason": func(obj *BreakglassSession) {
			obj.GetCondition(string(SessionConditionTypeExpiryNotificationIntent)).Reason = "Delivered"
		},
		"change message": func(obj *BreakglassSession) {
			obj.GetCondition(string(SessionConditionTypeExpiryNotificationIntent)).Message = "forged"
		},
	}
	for name, mutate := range invalidChanges {
		t.Run(name, func(t *testing.T) {
			changed := pending.DeepCopy()
			mutate(changed)
			if errs := validateExpiryNotificationIntent(pending, changed); len(errs) == 0 {
				t.Fatal("expected invalid intent change to be rejected")
			}
		})
	}

	acknowledged := pending.DeepCopy()
	condition := acknowledged.GetCondition(string(SessionConditionTypeExpiryNotificationIntent))
	condition.Status = metav1.ConditionTrue
	condition.Reason = "QueueAccepted"
	reopened := acknowledged.DeepCopy()
	reopenedCondition := reopened.GetCondition(string(SessionConditionTypeExpiryNotificationIntent))
	reopenedCondition.Status = metav1.ConditionFalse
	reopenedCondition.Reason = "PendingEnqueue"
	if errs := validateExpiryNotificationIntent(acknowledged, reopened); len(errs) == 0 {
		t.Fatal("expected acknowledged intent reopening to be rejected")
	}

	forgedOld := pending.DeepCopy()
	forgedOldCondition := forgedOld.GetCondition(string(SessionConditionTypeExpiryNotificationIntent))
	forgedOldCondition.Status = metav1.ConditionUnknown
	if errs := validateExpiryNotificationIntent(forgedOld, forgedOld.DeepCopy()); len(errs) == 0 {
		t.Fatal("expected a forged existing intent to be rejected")
	}
}

func TestBreakglassSessionCreateRejectsExpiryNotificationIntent(t *testing.T) {
	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "forged-intent", Namespace: "default"},
		Spec:       BreakglassSessionSpec{Cluster: "cluster", User: "user@example.com", GrantedGroup: "admin"},
		Status: BreakglassSessionStatus{
			State: SessionStateExpired,
			Conditions: []metav1.Condition{{
				Type:               string(SessionConditionTypeExpiryNotificationIntent),
				Status:             metav1.ConditionTrue,
				Reason:             "QueueAccepted",
				LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
			}},
		},
	}
	if _, err := session.ValidateCreate(context.Background(), session); err == nil {
		t.Fatal("expected expiry notification status on object creation to be rejected")
	}
}

func TestBreakglassSessionDeleteAdmissionBlocksPendingDuplicateAudit(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("register scheme: %v", err)
	}
	obj := &BreakglassSession{
		TypeMeta:   metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "BreakglassSession"},
		ObjectMeta: metav1.ObjectMeta{Name: "pending-audit", Namespace: "default"},
	}
	obj.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeDuplicateCleanupAuditComplete),
		Status:             metav1.ConditionFalse,
		Reason:             "PendingDelivery",
		LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	})
	obj.Status.State = SessionStateWithdrawn
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal delete object: %v", err)
	}

	validator := admission.WithValidator[*BreakglassSession](scheme, &BreakglassSession{})
	request := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Delete,
		OldObject: runtime.RawExtension{Raw: raw},
	}}
	response := validator.Handle(context.Background(), request)
	if response.Allowed {
		t.Fatal("expected the actual custom-validator delete admission path to deny pending audit deletion")
	}

	obj.SetCondition(metav1.Condition{
		Type:   string(SessionConditionTypeDuplicateCleanupAuditComplete),
		Status: metav1.ConditionTrue,
		Reason: "EmissionAccepted",
	})
	raw, err = json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal acknowledged delete object: %v", err)
	}
	request.OldObject = runtime.RawExtension{Raw: raw}
	response = validator.Handle(context.Background(), request)
	if !response.Allowed {
		t.Fatalf("expected acknowledged audit deletion to be allowed, response=%+v", response.Result)
	}
}

func TestValidateDuplicateCleanupAuditIntentIsImmutable(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(100, 0))
	oldObj := &BreakglassSession{Status: BreakglassSessionStatus{
		State: SessionStateWithdrawn,
		Conditions: []metav1.Condition{{
			Type:               string(SessionConditionTypeDuplicateCleanupAuditComplete),
			Status:             metav1.ConditionFalse,
			Reason:             "WithdrawDecision",
			LastTransitionTime: intentTime,
		}},
	}}

	mutated := oldObj.DeepCopy()
	mutated.Status.Conditions[0].Reason = "ExpireDecision"
	if errs := validateDuplicateCleanupAuditIntent(oldObj, mutated); len(errs) == 0 {
		t.Fatal("expected terminal decision mutation to be rejected")
	}

	committed := oldObj.DeepCopy()
	committed.Status.Conditions[0].Status = metav1.ConditionTrue
	if errs := validateDuplicateCleanupAuditIntent(oldObj, committed); len(errs) != 0 {
		t.Fatalf("expected matching acknowledgement and terminal commit to be valid: %v", errs)
	}

	wrongCommit := oldObj.DeepCopy()
	wrongCommit.Status.State = SessionStateExpired
	wrongCommit.Status.Conditions[0].Status = metav1.ConditionTrue
	if errs := validateDuplicateCleanupAuditIntent(oldObj, wrongCommit); len(errs) == 0 {
		t.Fatal("expected acknowledgement with a different terminal decision to be rejected")
	}
}

func TestValidateDuplicateCleanupAuditDisabledAcknowledgement(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(100, 0))
	for _, test := range []struct {
		name      string
		oldState  BreakglassSessionState
		oldReason string
		newState  BreakglassSessionState
	}{
		{name: "current expire intent", oldState: SessionStateExpired, oldReason: "ExpireDecision", newState: SessionStateExpired},
		{name: "current withdraw intent", oldState: SessionStateWithdrawn, oldReason: "WithdrawDecision", newState: SessionStateWithdrawn},
		{name: "legacy terminal delivery", oldState: SessionStateExpired, oldReason: "PendingDelivery", newState: SessionStateExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldObj := &BreakglassSession{Status: BreakglassSessionStatus{
				State: test.oldState,
				Conditions: []metav1.Condition{{
					Type:               string(SessionConditionTypeDuplicateCleanupAuditComplete),
					Status:             metav1.ConditionFalse,
					Reason:             test.oldReason,
					LastTransitionTime: intentTime,
				}},
			}}
			acknowledged := oldObj.DeepCopy()
			acknowledged.Status.State = test.newState
			acknowledged.Status.Conditions[0].Status = metav1.ConditionTrue
			acknowledged.Status.Conditions[0].Reason = "AuditingDisabledAtCommit"

			if errs := validateDuplicateCleanupAuditIntent(oldObj, acknowledged); len(errs) != 0 {
				t.Fatalf("expected exact disabled audit acknowledgement to be valid: %v", errs)
			}

			wrongDecision := acknowledged.DeepCopy()
			wrongDecision.Status.State = SessionStateRejected
			if errs := validateDuplicateCleanupAuditIntent(oldObj, wrongDecision); len(errs) == 0 {
				t.Fatal("expected a different terminal decision to be rejected")
			}

			rewrittenTime := acknowledged.DeepCopy()
			rewrittenTime.Status.Conditions[0].LastTransitionTime = metav1.NewTime(intentTime.Add(time.Second))
			if errs := validateDuplicateCleanupAuditIntent(oldObj, rewrittenTime); len(errs) == 0 {
				t.Fatal("expected the persisted decision time to remain immutable")
			}
		})
	}
}

func TestValidateDuplicateCleanupAuditIntentCreationRequiresExactPendingTuple(t *testing.T) {
	now := metav1.NewTime(time.Unix(100, 0))
	oldObj := &BreakglassSession{Status: BreakglassSessionStatus{State: SessionStateApproved}}
	valid := oldObj.DeepCopy()
	valid.Status.State = SessionStateExpired
	valid.SetCondition(metav1.Condition{
		Type:               string(SessionConditionTypeDuplicateCleanupAuditComplete),
		Status:             metav1.ConditionFalse,
		Reason:             "ExpireDecision",
		LastTransitionTime: now,
	})
	if errs := validateDuplicateCleanupAuditIntent(oldObj, valid); len(errs) != 0 {
		t.Fatalf("expected the exact pending expire intent to be valid: %v", errs)
	}

	for _, test := range []struct {
		name   string
		mutate func(*BreakglassSession)
	}{
		{name: "status is not false", mutate: func(obj *BreakglassSession) { obj.Status.Conditions[0].Status = metav1.ConditionTrue }},
		{name: "reason does not match approved source", mutate: func(obj *BreakglassSession) { obj.Status.Conditions[0].Reason = "WithdrawDecision" }},
		{name: "timestamp is zero", mutate: func(obj *BreakglassSession) { obj.Status.Conditions[0].LastTransitionTime = metav1.Time{} }},
		{name: "state stays active", mutate: func(obj *BreakglassSession) { obj.Status.State = SessionStateApproved }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := valid.DeepCopy()
			test.mutate(invalid)
			if errs := validateDuplicateCleanupAuditIntent(oldObj, invalid); len(errs) == 0 {
				t.Fatal("expected invalid initial intent to be rejected")
			}
		})
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

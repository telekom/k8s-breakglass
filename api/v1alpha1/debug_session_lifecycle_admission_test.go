// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package v1alpha1

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLifecycleLimitsDirectAdmission(t *testing.T) {
	for _, field := range []string{"idleTimeout", "retainFor"} {
		for _, duration := range []string{"", "1h", "invalid", "0s", "-1m"} {
			t.Run(field+"/"+duration, func(t *testing.T) {
				constraints := &DebugSessionConstraints{}
				if field == "idleTimeout" {
					constraints.IdleTimeout = duration
				} else {
					constraints.RetainFor = duration
				}
				template := &DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: DebugSessionTemplateSpec{Mode: DebugSessionModeWorkload, PodTemplateRef: &DebugPodTemplateReference{Name: "pod"}, Constraints: constraints}}
				binding := &DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"}, Spec: DebugSessionClusterBindingSpec{TemplateRef: &TemplateReference{Name: "template"}, Clusters: []string{"cluster"}, Constraints: constraints}}
				_, te := template.ValidateCreate(context.Background(), template)
				_, be := binding.ValidateCreate(context.Background(), binding)
				_, tue := template.ValidateUpdate(context.Background(), template.DeepCopy(), template)
				_, bue := binding.ValidateUpdate(context.Background(), binding.DeepCopy(), binding)
				invalid := duration != "" && duration != "1h"
				for _, err := range []error{te, be, tue, bue} {
					if invalid {
						if err == nil || !strings.Contains(err.Error(), field) {
							t.Fatalf("expected %s validation, got %v", field, err)
						}
					} else if err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestNonterminalRetentionDirectAdmission(t *testing.T) {
	now := metav1.NewTime(time.Now())
	session := &DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session"}, Spec: DebugSessionSpec{Cluster: "cluster", TemplateRef: "template", RequestedBy: "alice"}, Status: DebugSessionStatus{State: DebugSessionStatePending}}
	_, err := session.ValidateCreate(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	invalid := session.DeepCopy()
	invalid.Status.RetainedUntil = &now
	_, err = invalid.ValidateCreate(context.Background(), invalid)
	if err == nil || !strings.Contains(err.Error(), "retainedUntil") {
		t.Fatalf("create accepted retention: %v", err)
	}
	_, err = invalid.ValidateUpdate(context.Background(), session, invalid)
	if err == nil || !strings.Contains(err.Error(), "retainedUntil") {
		t.Fatalf("update accepted retention: %v", err)
	}
}

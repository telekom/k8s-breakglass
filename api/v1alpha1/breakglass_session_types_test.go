// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
// Copyright 2024.
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateCreate_MissingFields(t *testing.T) {
	bs := &BreakglassSession{}
	if err := bs.ValidateCreate(); err == nil {
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
	if err := bs.ValidateCreate(); err != nil {
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
	if err := modified.ValidateUpdate(old); err == nil {
		t.Fatalf("expected ValidateUpdate to return error when spec changed")
	}

	// identical spec should succeed
	same := old.DeepCopy()
	if err := same.ValidateUpdate(old); err != nil {
		t.Fatalf("expected ValidateUpdate to succeed when spec unchanged, got: %v", err)
	}

	// also ensure DeepCopy produced equal spec
	if !reflect.DeepEqual(old.Spec, same.Spec) {
		t.Fatalf("sanity: deep copy produced different spec")
	}
}

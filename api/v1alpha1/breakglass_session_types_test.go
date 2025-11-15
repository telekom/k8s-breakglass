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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

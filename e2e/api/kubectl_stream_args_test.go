//go:build multicluster
// +build multicluster

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

package api

import (
	"context"
	"testing"
)

func TestKubectlTokenStreamCommandTimeoutBehavior(t *testing.T) {
	suite := &SpokeHubAuthorizationSuite{}

	longLived := suite.newLongLivedKubectlWithToken(context.Background(), "/tmp/oidc.kubeconfig", "token", "exec", "pod", "--", "true")
	if longLived.Args[0] != "kubectl" {
		t.Fatalf("long-lived helper must invoke kubectl, got %q", longLived.Args[0])
	}
	for _, arg := range longLived.Args {
		if arg == "--request-timeout=5s" || arg == "--request-timeout=0" {
			t.Fatalf("long-lived helper must not impose a request timeout, got args %v", longLived.Args)
		}
	}

	bounded := suite.newKubectlWithToken(context.Background(), "/tmp/oidc.kubeconfig", "token", "get", "pods")
	foundBound := false
	for _, arg := range bounded.Args {
		if arg == "--request-timeout=5s" {
			foundBound = true
			break
		}
	}
	if !foundBound {
		t.Fatalf("ordinary helper must retain its bounded request timeout, got args %v", bounded.Args)
	}
}

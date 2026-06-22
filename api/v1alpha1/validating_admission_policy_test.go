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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityProviderVAPRejectsInsecureSkipVerify(t *testing.T) {
	policyPath := filepath.Join("..", "..", "config", "components", "vap", "identityprovider-policy.yaml")
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read IdentityProvider VAP policy: %v", err)
	}
	policy := string(policyBytes)

	for _, want := range []string{
		"object.spec.oidc.insecureSkipVerify == false",
		"object.spec.keycloak.insecureSkipVerify == false",
		"spec.oidc.insecureSkipVerify is not supported",
		"spec.keycloak.insecureSkipVerify is not supported",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("IdentityProvider VAP policy missing %q", want)
		}
	}
}

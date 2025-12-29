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

package breakglass

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzCreateDebugSessionRequest tests the create session request deserialization
func FuzzCreateDebugSessionRequest(f *testing.F) {
	// Add seed corpus with valid and edge case inputs
	seeds := []string{
		`{"templateRef":"standard-debug","cluster":"production"}`,
		`{"templateRef":"","cluster":""}`,
		`{"templateRef":"a","cluster":"b","requestedDuration":"1h","reason":"testing"}`,
		`{}`,
		`{"templateRef":"<script>alert(1)</script>","cluster":"production"}`,
		`{"templateRef":"test","cluster":"prod","nodeSelector":{"zone":"us-east"}}`,
		`{"templateRef":"test","cluster":"prod","requestedDuration":"invalid"}`,
		`{"templateRef":"test","cluster":"prod","requestedDuration":"9999h"}`,
		`{"templateRef":"test","cluster":"prod","reason":"` + string(make([]byte, 10000)) + `"}`,
		`null`,
		`[]`,
		`"string"`,
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req CreateDebugSessionRequest
		// Should never panic on any input
		err := json.Unmarshal(data, &req)
		// Verify unmarshaling doesn't panic, successful parse is fine
		_ = err
	})
}

// FuzzRenewDebugSessionRequest tests renewal request deserialization
func FuzzRenewDebugSessionRequest(f *testing.F) {
	seeds := []string{
		`{"extendBy":"1h"}`,
		`{"extendBy":"30m"}`,
		`{"extendBy":""}`,
		`{"extendBy":"invalid"}`,
		`{"extendBy":"-1h"}`,
		`{"extendBy":"9999999h"}`,
		`{}`,
		`null`,
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req RenewDebugSessionRequest
		err := json.Unmarshal(data, &req)
		if err != nil {
			return // Invalid JSON is expected
		}

		// Validate that if extendBy is set, it can be parsed as a duration
		if req.ExtendBy != "" {
			_, parseErr := time.ParseDuration(req.ExtendBy)
			// It's okay for parsing to fail - we just need to not panic
			_ = parseErr
		}
	})
}

// FuzzApprovalRequest tests approval request deserialization
func FuzzApprovalRequest(f *testing.F) {
	seeds := []string{
		`{"reason":"approved"}`,
		`{"reason":""}`,
		`{}`,
		`{"reason":"<script>alert('xss')</script>"}`,
		`{"reason":"` + string(make([]byte, 5000)) + `"}`,
		`null`,
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req ApprovalRequest
		// Should never panic on any input
		_ = json.Unmarshal(data, &req)
	})
}

// FuzzJoinDebugSessionRequest tests join request deserialization
func FuzzJoinDebugSessionRequest(f *testing.F) {
	seeds := []string{
		`{"role":"viewer"}`,
		`{"role":"participant"}`,
		`{"role":""}`,
		`{"role":"admin"}`,
		`{"role":"<script>"}`,
		`{}`,
		`null`,
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req JoinDebugSessionRequest
		// Should never panic on any input
		_ = json.Unmarshal(data, &req)

		// Validate role if present
		if req.Role != "" {
			// Check that we handle unexpected roles gracefully
			switch req.Role {
			case "viewer", "participant":
				// Valid roles
			default:
				// Invalid role - should be handled by the API handler
			}
		}
	})
}

// FuzzMatchPattern tests the pattern matching utility function
func FuzzMatchPattern(f *testing.F) {
	// Add seed pairs of (pattern, value)
	seeds := []struct {
		pattern string
		value   string
	}{
		{"*", "anything"},
		{"prod-*", "prod-cluster"},
		{"*-prod", "us-east-prod"},
		{"exact", "exact"},
		{"no-match", "different"},
		{"", "empty-pattern"},
		{"pattern", ""},
		{"*", ""},
		{"", ""},
		{"production-*-cluster", "production-east-cluster"},
	}

	for _, seed := range seeds {
		f.Add(seed.pattern, seed.value)
	}

	f.Fuzz(func(t *testing.T, pattern, value string) {
		// matchPattern should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("matchPattern panicked with pattern=%q value=%q: %v", pattern, value, r)
			}
		}()

		result := matchPattern(pattern, value)

		// Basic invariant checks
		if pattern == "*" && !result {
			t.Errorf("expected '*' to match any value, but got false for %q", value)
		}
		if pattern == value && !result {
			t.Errorf("expected exact match for pattern=%q value=%q", pattern, value)
		}
	})
}

// FuzzDebugSessionSummary tests summary serialization
func FuzzDebugSessionSummary(f *testing.F) {
	f.Add("session-1", "template", "cluster", "user@example.com", "Active", 5, 10)
	f.Add("", "", "", "", "", 0, 0)
	f.Add("a", "b", "c", "d", "Pending", -1, -1)

	f.Fuzz(func(t *testing.T, name, templateRef, cluster, requestedBy, state string, participants, allowedPods int) {
		summary := DebugSessionSummary{
			Name:         name,
			TemplateRef:  templateRef,
			Cluster:      cluster,
			RequestedBy:  requestedBy,
			Participants: participants,
			AllowedPods:  allowedPods,
		}

		// Should be able to marshal without panic
		data, err := json.Marshal(summary)
		if err != nil {
			return
		}

		// Should be able to unmarshal back
		var decoded DebugSessionSummary
		_ = json.Unmarshal(data, &decoded)
	})
}

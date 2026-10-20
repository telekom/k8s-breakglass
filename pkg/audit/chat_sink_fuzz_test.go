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

package audit

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzChatMessageText checks the chat message invariants for arbitrary event
// values: no Slack control characters, no "@" mentions, no control
// characters, every "&" starts an entity, and neither the approving actor
// nor the reason in the text.
func FuzzChatMessageText(f *testing.F) {
	f.Add("session.requested", "sess", "alice@example.com", "admins", "prod", "")
	f.Add("debug_session.rejected", "<!channel>", "@here", "<https://x|y>", "a&b", "https://bg.example.com")
	f.Add("custom.event", "x\ny", "\u0000@all", "&lt;", "c1", "https://bg.example.com/")
	// The requester is the actor when no requester detail is set.
	f.Add("session.requested", "0", "", "0", "0", "")

	const approver, groups, reason = "approver-marker-7f3a", "groups-marker-2d6b", "reason-marker-9c1e"
	f.Fuzz(func(t *testing.T, eventType, name, requester, scope, cluster, baseURL string) {
		event := &Event{
			Type:   EventType(eventType),
			Actor:  Actor{User: approver, Groups: []string{groups}},
			Target: Target{Kind: "BreakglassSession", Name: name, Cluster: cluster},
			Details: map[string]interface{}{
				"user":         requester,
				"requestedBy":  requester,
				"grantedGroup": scope,
				"templateRef":  scope,
				"reason":       reason,
				"message":      reason,
			},
		}
		// baseURL is operator configuration, not event data: keep it plain.
		if strings.ContainsAny(baseURL, "<>&@") || strings.IndexFunc(baseURL, unicode.IsControl) >= 0 {
			baseURL = ""
		}
		text := chatMessageText(event, baseURL)

		if strings.ContainsAny(text, "<>@") {
			t.Fatalf("unescaped mention or markup in %q", text)
		}
		if strings.IndexFunc(text, unicode.IsControl) >= 0 {
			t.Fatalf("control character in %q", text)
		}
		if got, want := len(entityPattern.FindAllString(text, -1)), strings.Count(text, "&"); got != want {
			t.Fatalf("bare & in %q", text)
		}
		if inputs := eventType + name + requester + scope + cluster + baseURL; !strings.Contains(inputs, "marker") {
			if strings.Contains(text, reason) || strings.Contains(text, groups) {
				t.Fatalf("reason or actor groups leaked into %q", text)
			}
			// Without a requester detail, the actor of a request, withdrawal
			// or debug session creation is the requester and is shown. For
			// every other event the actor may be the approver.
			actorIsRequester := requester == "" && (eventType == string(EventSessionRequested) ||
				eventType == string(EventSessionWithdrawn) || eventType == string(EventDebugSessionCreated))
			if !actorIsRequester && strings.Contains(text, approver) {
				t.Fatalf("approver leaked into %q", text)
			}
		}
	})
}

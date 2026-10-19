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
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"go.uber.org/zap"
)

// ChatWebhookSink posts one {"text": "..."} message per audit event, the body
// Slack and Mattermost incoming webhooks accept. It is advisory: the required
// synchronous audit path skips it (see isAdvisorySink). It deliberately has no
// WriteBatch, so queued delivery sends one request per event.
type ChatWebhookSink struct {
	webhook *WebhookSink
	baseURL string
}

// NewChatWebhookSink creates a chat sink. baseURL is the frontend base URL used
// for links; when empty, messages carry no link.
func NewChatWebhookSink(cfg WebhookSinkConfig, baseURL string, logger *zap.Logger) *ChatWebhookSink {
	return &ChatWebhookSink{webhook: NewWebhookSink(cfg, logger), baseURL: baseURL}
}

// Write posts the chat message for event.
func (s *ChatWebhookSink) Write(ctx context.Context, event *Event) error {
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: chatMessageText(event, s.baseURL)})
	if err != nil {
		return fmt.Errorf("failed to marshal chat message: %w: %w", ErrSerialization, err)
	}
	return s.webhook.post(ctx, body, event)
}

// Close releases the underlying webhook sink.
func (s *ChatWebhookSink) Close() error { return s.webhook.Close() }

// Name returns the sink identifier.
func (s *ChatWebhookSink) Name() string { return s.webhook.Name() }

// isAdvisorySink reports whether sink, through its wrappers, is a chat sink.
// Advisory sinks never take part in required synchronous delivery: they are not
// checked for filters or receipts and are not written.
func isAdvisorySink(sink Sink) bool {
	for {
		switch s := sink.(type) {
		case *ChatWebhookSink:
			return true
		case *filteredBatchSink:
			sink = s.sink
		case *filteredSink:
			sink = s.sink
		case *CircuitBreakerSink:
			sink = s.sink
		case *QueuedSink:
			sink = s.sink
		default:
			return false
		}
	}
}

var chatVerbs = map[EventType]string{
	EventSessionRequested:            "requested",
	EventSessionApproved:             "approved",
	EventSessionDenied:               "denied",
	EventSessionExpired:              "expired",
	EventSessionWithdrawn:            "withdrawn",
	EventDebugSessionCreated:         "created",
	EventDebugSessionApproved:        "approved",
	EventDebugSessionRejected:        "rejected",
	EventDebugSessionApprovalTimeout: "approval timed out",
	EventDebugSessionExpired:         "expired",
}

// Slack treats &, < and > as control characters (<!channel>, <@U123>,
// <url|label>) and documents these entities. Mattermost mentions plain
// "@channel"; a fullwidth at sign (U+FF20) reads the same and never mentions.
var chatEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "@", "＠")

// chatEscape makes an event string safe for a chat message: mentions, links
// and markup characters are neutralised and control characters such as
// newlines become spaces.
func chatEscape(s string) string {
	return chatEscaper.Replace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

func detail(event *Event, key string) string {
	v, _ := event.Details[key].(string)
	return v
}

// chatMessageText renders the chat message for event. It never includes the
// request reason, approver names or approver groups: a channel message reaches
// everyone in the channel, unlike the per-recipient approval emails.
func chatMessageText(event *Event, baseURL string) string {
	cluster := event.Target.Cluster
	if cluster == "" {
		cluster = detail(event, "cluster")
	}

	verb, known := chatVerbs[event.Type]
	if !known {
		text := "Breakglass audit event " + chatEscape(string(event.Type))
		if event.Target.Kind != "" || event.Target.Name != "" {
			text += " for " + strings.TrimSpace(chatEscape(event.Target.Kind)+" "+chatEscape(event.Target.Name))
		}
		if cluster != "" {
			text += " on cluster " + chatEscape(cluster)
		}
		return text
	}

	name := event.Target.Name
	debug := strings.HasPrefix(string(event.Type), "debug_session.")
	// Session events carry the requester as "user", debug session events and
	// the Manager helpers as "requestedBy".
	requester := detail(event, "user")
	if requester == "" {
		requester = detail(event, "requestedBy")
	}
	noun, scopeLabel, scope, path := "Breakglass session", "group", detail(event, "grantedGroup"), "/session/"+url.PathEscape(name)
	if debug {
		noun, scopeLabel, path = "Debug session", "template", "/debug-sessions/"+url.PathEscape(name)
		if scope = detail(event, "templateRef"); scope == "" {
			scope = detail(event, "templateName")
		}
	}
	if event.Type == EventSessionRequested {
		path += "/approve"
	}
	// The actor is the requester only when the requester performed the action;
	// for approvals and denials it is the approver and must not be shown.
	if requester == "" && event.Actor.User != "system" &&
		(event.Type == EventSessionRequested || event.Type == EventSessionWithdrawn || event.Type == EventDebugSessionCreated) {
		requester = event.Actor.User
	}

	var facts []string
	for _, f := range [][2]string{{"requester", requester}, {scopeLabel, scope}, {"cluster", cluster}} {
		if f[1] != "" {
			facts = append(facts, f[0]+": "+chatEscape(f[1]))
		}
	}

	text := noun + " " + chatEscape(name) + " " + verb
	if len(facts) > 0 {
		text += " (" + strings.Join(facts, ", ") + ")"
	}
	if baseURL = strings.TrimRight(baseURL, "/"); baseURL != "" {
		text += ": " + chatEscaper.Replace(baseURL+path)
	}
	return text
}

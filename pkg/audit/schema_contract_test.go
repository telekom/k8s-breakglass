// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	auditv1 "github.com/telekom/k8s-breakglass/api/audit/v1"
)

type schemaDoc struct {
	Properties map[string]json.RawMessage `json:"properties"`
	AllOf      []struct {
		If struct {
			Properties struct {
				Type struct {
					Enum []string `json:"enum"`
				} `json:"type"`
			} `json:"properties"`
		} `json:"if"`
		Then struct {
			Properties struct {
				Details struct {
					Ref string `json:"$ref"`
				} `json:"details"`
			} `json:"properties"`
		} `json:"then"`
	} `json:"allOf"`
	Defs map[string]struct {
		Properties map[string]json.RawMessage `json:"properties"`
	} `json:"$defs"`
}

func loadSchemaDoc(t *testing.T) schemaDoc {
	t.Helper()
	var doc schemaDoc
	require.NoError(t, json.Unmarshal(auditv1.Schema, &doc))
	return doc
}

// declaredEventTypes parses types.go, so a new EventType constant cannot
// escape the contract by being left out of a hand-maintained list.
func declaredEventTypes(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "types.go", nil, 0)
	require.NoError(t, err)
	var types []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			if ident, ok := value.Type.(*ast.Ident); !ok || ident.Name != "EventType" {
				continue
			}
			for _, v := range value.Values {
				lit := v.(*ast.BasicLit)
				types = append(types, constant.StringVal(constant.MakeFromLiteral(lit.Value, lit.Kind, 0)))
			}
		}
	}
	require.Greater(t, len(types), 100, "EventType constants not found in types.go")
	return types
}

// Every declared event type has exactly one details schema, and the schema
// names no event type that the code does not declare.
func TestAuditSchemaCoversEveryEventType(t *testing.T) {
	doc := loadSchemaDoc(t)
	mapped := map[string]string{}
	for _, clause := range doc.AllOf {
		ref := clause.Then.Properties.Details.Ref
		require.True(t, strings.HasPrefix(ref, "#/$defs/"), "dispatch clause without details $ref")
		_, ok := doc.Defs[strings.TrimPrefix(ref, "#/$defs/")]
		require.True(t, ok, "dangling %s", ref)
		for _, eventType := range clause.If.Properties.Type.Enum {
			require.NotContains(t, mapped, eventType, "%s mapped twice", eventType)
			mapped[eventType] = ref
		}
	}
	declared := declaredEventTypes(t)
	for _, eventType := range declared {
		require.Contains(t, mapped, eventType,
			"event type %q has no details schema: add it to api/audit/v1/audit-event.schema.json and docs/audit-event-schema.md", eventType)
	}
	for eventType := range mapped {
		require.Contains(t, declared, eventType, "schema maps undeclared event type %q", eventType)
	}
}

func jsonFields(typ reflect.Type) []string {
	var fields []string
	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
}

func schemaFields(props map[string]json.RawMessage) []string {
	var fields []string
	for name := range props {
		fields = append(fields, name)
	}
	sort.Strings(fields)
	return fields
}

// The envelope schema and the Go types serialize the same fields.
func TestAuditSchemaEnvelopeMatchesGoTypes(t *testing.T) {
	doc := loadSchemaDoc(t)
	require.Equal(t, jsonFields(reflect.TypeFor[Event]()), schemaFields(doc.Properties))
	require.Equal(t, jsonFields(reflect.TypeFor[Actor]()), schemaFields(doc.Defs["actor"].Properties))
	require.Equal(t, jsonFields(reflect.TypeFor[Target]()), schemaFields(doc.Defs["target"].Properties))
	require.Equal(t, jsonFields(reflect.TypeFor[RequestContext]()), schemaFields(doc.Defs["requestContext"].Properties))
}

// The Manager's helper emitters produce events that validate strictly: every
// details key they write is declared in the schema.
func TestAuditSchemaManagerEmittersProduceValidEvents(t *testing.T) {
	var mu sync.Mutex
	var events []*Event
	sink := &testSink{name: "schema", writeFunc: func(event *Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}}
	m := NewManager(sink, ManagerConfig{QueueSize: 64, WorkerCount: 1}, zap.NewNop())
	ctx := context.Background()
	m.SessionRequested(ctx, "s", "esc", "alice@example.com", "incident")
	m.SessionApproved(ctx, "s", "esc", "bob@example.com", "alice@example.com")
	m.SessionDenied(ctx, "s", "esc", "bob@example.com", "alice@example.com", "no")
	m.AccessDecision(ctx, "alice", []string{"g"}, "pods", "p", "ns", "c", "get", true, "s")
	m.AccessDecision(ctx, "alice", []string{"g"}, "pods", "p", "ns", "c", "get", false, "s")
	m.PolicyViolation(ctx, "alice", nil, "pods", "p", "ns", "c", "deny", "blocked")
	m.DebugSessionCreated(ctx, "d", "alice", "c", "tpl")
	m.DebugSessionStarted(ctx, "d", "ns", "uid", "alice", "c", "tpl")
	m.DebugSessionTerminated(ctx, "d", "alice", "done")
	m.DebugSessionFailed(ctx, "d", "ns", "c", "boom", map[string]interface{}{"template": "tpl", "requested_by": "alice", "previous_state": "Active"})
	m.DebugSessionExpired(ctx, "d", "ns", "c", "alice", "tpl")
	m.DebugSessionApprovalTimeout(ctx, "d", "ns", "c", "alice", "tpl")
	m.DebugSessionValidationFailed(ctx, "d", "ns", "c", "invalid")
	m.DebugSessionCleanupFailed(ctx, "d", "ns", "c", []string{"v1/ConfigMap/ns/x"})
	m.DebugSessionCleanupRecovered(ctx, "d", "ns", "c")
	m.DebugSessionBindingUnresolved(ctx, "d", "ns", "c", "b", "bns", "missing")
	m.DebugSessionPodFailed(ctx, "d", "ns", "pod", "pns", "OOMKilled", "msg")
	m.DebugSessionPodRestarted(ctx, "d", "ns", "pod", "pns", 3, "Error")
	m.DebugSessionResourceDeployed(ctx, "d", "ns", "c", "ConfigMap", "x", "ns")
	m.DebugSessionResourceCleanup(ctx, "d", "ns", "c", "ConfigMap", "x", "ns")
	require.NoError(t, m.Close())

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 20)
	for _, event := range events {
		raw, err := json.Marshal(event)
		require.NoError(t, err)
		require.NoError(t, auditv1.ValidateStrict(raw), "%s: %s", event.Type, raw)
		require.Equal(t, SchemaVersion, event.SchemaVersion)
	}
}

// Malformed events are rejected; unknown properties are accepted by the
// published schema but rejected by the strict CI variant.
func TestAuditSchemaRejectsMalformedEvents(t *testing.T) {
	valid := Event{ID: "e1", SchemaVersion: SchemaVersion, Type: EventDebugSessionTerminalRecordingFinalized,
		Severity: SeverityInfo, Timestamp: time.Now().UTC(), Actor: Actor{User: "alice"},
		Target:  Target{Kind: "DebugSession", Name: "d"},
		Details: map[string]interface{}{"recordingId": "r", "sha256": strings.Repeat("a", 64), "bytes": 10}}
	raw, err := json.Marshal(valid)
	require.NoError(t, err)
	require.NoError(t, auditv1.ValidateStrict(raw))

	mutate := func(f func(map[string]any)) []byte {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(raw, &doc))
		f(doc)
		out, err := json.Marshal(doc)
		require.NoError(t, err)
		return out
	}
	for name, doc := range map[string][]byte{
		"missing id":        mutate(func(d map[string]any) { delete(d, "id") }),
		"bad severity":      mutate(func(d map[string]any) { d["severity"] = "debug" }),
		"bad timestamp":     mutate(func(d map[string]any) { d["timestamp"] = "yesterday" }),
		"bad version":       mutate(func(d map[string]any) { d["schemaVersion"] = "v2" }),
		"bad digest":        mutate(func(d map[string]any) { d["details"].(map[string]any)["sha256"] = "xyz" }),
		"bad details value": mutate(func(d map[string]any) { d["details"].(map[string]any)["bytes"] = "ten" }),
	} {
		require.Error(t, auditv1.Validate(doc), name)
	}
	for _, eventType := range []EventType{EventDebugSessionMaintenanceIntent, EventDebugSessionAdmissionRecipeApplied,
		EventDebugSessionHotfixResult, EventDebugSessionTerminalRecordingAccessed} {
		require.Error(t, auditv1.Validate(mutate(func(d map[string]any) { d["type"] = string(eventType); delete(d, "details") })),
			"%s must not omit its mandatory details", eventType)
	}
	require.NoError(t, auditv1.Validate(mutate(func(d map[string]any) { delete(d, "details") })),
		"details stay optional for payloads without mandatory fields")
	extra := mutate(func(d map[string]any) { d["details"].(map[string]any)["newField"] = 1; d["newEnvelopeField"] = true })
	require.NoError(t, auditv1.Validate(extra), "published schema must stay open for additive changes")
	require.Error(t, auditv1.ValidateStrict(extra), "strict schema must reject undeclared fields")
}

var docJSONBlock = regexp.MustCompile("(?s)```json\n(.*?)```")

// Every JSON example in docs/audit-event-schema.md is a valid event.
func TestAuditSchemaDocExamplesValidate(t *testing.T) {
	raw, err := os.ReadFile("../../docs/audit-event-schema.md")
	require.NoError(t, err)
	blocks := docJSONBlock.FindAllSubmatch(raw, -1)
	require.NotEmpty(t, blocks)
	seen := map[string]bool{}
	for _, block := range blocks {
		require.NoError(t, auditv1.ValidateStrict(block[1]), "%s", block[1])
		var event Event
		require.NoError(t, json.Unmarshal(block[1], &event))
		seen[string(event.Type)] = true
	}
	for _, eventType := range []EventType{EventSessionRequested, EventDebugSessionStarted,
		EventDebugSessionTerminalRecordingFinalized, EventDebugSessionTerminalRecordingAccessed} {
		require.True(t, seen[string(eventType)], "docs lack an example of %s", eventType)
	}
}

// Single and batched Kafka writes carry the same headers.
func TestKafkaHeadersDocumented(t *testing.T) {
	event := &Event{ID: "e1", SchemaVersion: SchemaVersion, Type: EventSessionRequested, Severity: SeverityInfo,
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Actor: Actor{User: "alice"},
		RequestContext: &RequestContext{CorrelationID: "cid"}}
	var keys []string
	values := map[string]string{}
	for _, header := range kafkaHeaders(event) {
		keys = append(keys, header.Key)
		values[header.Key] = string(header.Value)
	}
	require.Equal(t, []string{"event-type", "severity", "timestamp", "schema-version", "actor", "correlation-id"}, keys)
	require.Equal(t, "2026-01-02T03:04:05Z", values["timestamp"])
	require.Equal(t, "v1", values["schema-version"])

	event.RequestContext, event.Actor.User = nil, ""
	keys = keys[:0]
	for _, header := range kafkaHeaders(event) {
		keys = append(keys, header.Key)
	}
	require.False(t, slices.Contains(keys, "actor") || slices.Contains(keys, "correlation-id"), "empty optional headers are omitted")
}

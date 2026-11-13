// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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

var eventTypePattern = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)+$`)

// declaredEventConsts parses every non-test file of this package and returns
// the EventType constants by name, so a new event type cannot escape the
// contract by being left out of a hand-maintained list. A string constant that
// looks like an event type but is not typed EventType fails the test.
func declaredEventConsts(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	consts := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				ident, typed := value.Type.(*ast.Ident)
				typed = typed && ident.Name == "EventType"
				for i, v := range value.Values {
					if call, ok := v.(*ast.CallExpr); ok {
						// EventType("x") is typed too.
						if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "EventType" && len(call.Args) == 1 {
							typed, v = true, call.Args[0]
						}
					}
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						require.False(t, typed, "%s: EventType constant %s must be a string literal", name, value.Names[i])
						continue
					}
					str := constant.StringVal(constant.MakeFromLiteral(lit.Value, lit.Kind, 0))
					if !typed {
						require.False(t, eventTypePattern.MatchString(str),
							"%s: constant %s = %q looks like an event type but is not typed EventType", name, value.Names[i], str)
						continue
					}
					consts[value.Names[i].Name] = str
				}
			}
		}
	}
	require.Greater(t, len(consts), 100, "EventType constants not found")
	return consts
}

func declaredEventTypes(t *testing.T) []string {
	t.Helper()
	var types []string
	for _, v := range declaredEventConsts(t) {
		types = append(types, v)
	}
	sort.Strings(types)
	return types
}

func collectEmittingHelpers(file *ast.File, consts map[string]string, helpers map[string][]string) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name == "Emit" || fn.Name.Name == "EmitSync" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && consts[id.Name] != "" {
				helpers[fn.Name.Name] = append(helpers[fn.Name.Name], consts[id.Name])
			}
			return true
		})
	}
}

const auditImportPath = "github.com/telekom/k8s-breakglass/pkg/audit"

// emittedEventTypes returns the event types that production code can emit:
// every audit.EventX referenced by non-test code outside this package, plus
// the types of the Manager helper methods that such code calls.
func emittedEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	consts := declaredEventConsts(t)
	fset := token.NewFileSet()
	// Emitting helpers: Manager methods and the event builders. Classifier
	// functions (types.go) name every type and are not emitters.
	helpers := map[string][]string{}
	for _, name := range []string{"manager.go", "security_events.go"} {
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		collectEmittingHelpers(file, consts, helpers)
	}
	emitted := map[string]bool{}
	for _, root := range []string{"../../cmd", "../../internal", "../../pkg", "../../api"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				filepath.Dir(path) == "../../pkg/audit" {
				return err
			}
			// Helper calls need no import of this package (for example through
			// a field of type *audit.Manager), so every file is scanned.
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			alias := ""
			for _, imp := range file.Imports {
				if imp.Path.Value == `"`+auditImportPath+`"` {
					alias = "audit"
					if imp.Name != nil {
						alias = imp.Name.Name
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); ok && alias != "" && x.Name == alias && consts[sel.Sel.Name] != "" {
					emitted[consts[sel.Sel.Name]] = true
				}
				for _, eventType := range helpers[sel.Sel.Name] {
					emitted[eventType] = true
				}
				return true
			})
			return nil
		})
		require.NoError(t, err)
	}
	require.NotEmpty(t, emitted)
	return emitted
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
	var envelopeType struct {
		Enum []string `json:"enum"`
	}
	require.NoError(t, json.Unmarshal(doc.Properties["type"], &envelopeType))
	sort.Strings(envelopeType.Enum)
	require.Equal(t, declared, envelopeType.Enum, "the envelope type enum must list exactly the declared event types")
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
	m.DebugSessionCleanupFailed(ctx, "d", "ns", "c", nil)        // residuals: null
	m.DebugSessionCleanupFailed(ctx, "d", "ns", "c", []string{}) // residuals: null as well
	m.DebugSessionCleanupRecovered(ctx, "d", "ns", "c")
	m.DebugSessionBindingUnresolved(ctx, "d", "ns", "c", "b", "bns", "missing")
	m.DebugSessionPodFailed(ctx, "d", "ns", "pod", "pns", "OOMKilled", "msg")
	m.DebugSessionPodRestarted(ctx, "d", "ns", "pod", "pns", 3, "Error")
	m.DebugSessionResourceDeployed(ctx, "d", "ns", "c", "ConfigMap", "x", "ns")
	m.DebugSessionResourceCleanup(ctx, "d", "ns", "c", "ConfigMap", "x", "ns")
	require.NoError(t, m.Close())

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 22)
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
		"unknown type":      mutate(func(d map[string]any) { d["type"] = "debug_session.unknown_thing" }),
		"bad digest":        mutate(func(d map[string]any) { d["details"].(map[string]any)["sha256"] = "xyz" }),
		"bad details value": mutate(func(d map[string]any) { d["details"].(map[string]any)["bytes"] = "ten" }),
	} {
		require.Error(t, auditv1.Validate(doc), name)
		require.Error(t, auditv1.ValidateStrict(doc), name)
	}
	for _, eventType := range []EventType{EventDebugSessionMaintenanceIntent, EventDebugSessionAdmissionRecipeApplied,
		EventDebugSessionHotfixResult, EventDebugSessionTerminalRecordingAccessed} {
		require.Error(t, auditv1.Validate(mutate(func(d map[string]any) { d["type"] = string(eventType); delete(d, "details") })),
			"%s must not omit its mandatory details", eventType)
	}
	require.NoError(t, auditv1.Validate(mutate(func(d map[string]any) { delete(d, "details") })),
		"details stay optional for payloads without mandatory fields")
	strictRejects := func(name string, event map[string]any) {
		t.Helper()
		doc, err := json.Marshal(event)
		require.NoError(t, err)
		require.Error(t, auditv1.ValidateStrict(doc), name)
	}
	receipt := func(eventType EventType, details map[string]any) map[string]any {
		return map[string]any{"id": "r1", "schemaVersion": "v1", "type": string(eventType), "severity": "critical",
			"timestamp": "2026-11-13T09:00:00Z", "actor": map[string]any{"user": "alice"},
			"target": map[string]any{"kind": "Node", "name": "n"}, "details": details}
	}
	hotfix := func(payload map[string]any) map[string]any {
		return receipt(EventDebugSessionHotfixIntent, map[string]any{"sessionUID": "u", "stage": "canary", "payload": payload})
	}
	deb := map[string]any{"url": "https://example.com/a.deb", "sha256": strings.Repeat("b", 64), "package": "a", "version": "1"}
	validHotfix, err := json.Marshal(hotfix(map[string]any{"type": "node-deb", "debs": []any{deb}}))
	require.NoError(t, err)
	require.NoError(t, auditv1.ValidateStrict(validHotfix))
	strictRejects("hotfix payload without type", hotfix(map[string]any{"debs": []any{deb}}))
	strictRejects("hotfix deb without sha256", hotfix(map[string]any{"type": "node-deb", "debs": []any{map[string]any{"url": "u", "package": "a", "version": "1"}}}))
	strictRejects("hotfix deb with bad sha256", hotfix(map[string]any{"type": "node-deb", "debs": []any{map[string]any{"url": "u", "sha256": "x", "package": "a", "version": "1"}}}))
	strictRejects("hotfix file without mode", hotfix(map[string]any{"type": "node-file", "file": map[string]any{"path": "/etc/x"}}))
	strictRejects("undeclared hotfix payload field", hotfix(map[string]any{"type": "node-deb", "script": "rm -rf /"}))
	maintenance := func(restartPods any) map[string]any {
		return receipt(EventDebugSessionMaintenanceIntent, map[string]any{"sessionUID": "u", "operationID": "op", "restartPods": restartPods})
	}
	okSelector, err := json.Marshal(maintenance([]any{map[string]any{"namespace": "kube-system", "matchLabels": map[string]any{"k8s-app": "cilium"}}}))
	require.NoError(t, err)
	require.NoError(t, auditv1.ValidateStrict(okSelector))
	strictRejects("selector without matchLabels", maintenance([]any{map[string]any{"namespace": "kube-system"}}))
	strictRejects("selector with empty matchLabels", maintenance([]any{map[string]any{"namespace": "kube-system", "matchLabels": map[string]any{}}}))
	strictRejects("selector with non-string label", maintenance([]any{map[string]any{"namespace": "kube-system", "matchLabels": map[string]any{"a": 1}}}))
	strictRejects("selector that is not an object", maintenance([]any{"kube-system/cilium"}))
	strictRejects("undeclared selector field", maintenance([]any{map[string]any{"namespace": "n", "matchLabels": map[string]any{"a": "b"}, "fieldSelector": "x"}}))
	strictRejects("undeclared admission recipe target field", receipt(EventDebugSessionAdmissionRecipeApplied,
		map[string]any{"sessionUID": "u", "operationID": "op", "action": "a", "targets": []any{map[string]any{"target": "t", "secret": "s"}}}))
	strictRejects("details on a reserved type", receipt(EventConfigChanged, map[string]any{"anything": 1}))
	require.Error(t, auditv1.ValidateStrict(mutate(func(d map[string]any) { d["actor"].(map[string]any)["token"] = "t" })), "undeclared actor field")

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

const (
	emittedBegin = "<!-- BEGIN GENERATED: emitted event types (UPDATE_AUDIT_SCHEMA_DOCS=1 go test ./pkg/audit -run TestAuditSchemaEmittedTypesDocumented) -->\n"
	emittedEnd   = "<!-- END GENERATED: emitted event types -->"
)

func codeList(types []string) string {
	if len(types) == 0 {
		return "none"
	}
	return "`" + strings.Join(types, "`, `") + "`"
}

// The docs list exactly the event types that production code emits, every
// emitted type has a structured details schema, and the remaining declared
// types are marked reserved. Regenerate with UPDATE_AUDIT_SCHEMA_DOCS=1.
func TestAuditSchemaEmittedTypesDocumented(t *testing.T) {
	doc := loadSchemaDoc(t)
	emitted := emittedEventTypes(t)
	var b strings.Builder
	b.WriteString(emittedBegin)
	b.WriteString("\n| Details definition | Emitted by this release | Declared, not emitted (reserved) |\n|---|---|---|\n")
	for _, clause := range doc.AllOf {
		def := strings.TrimPrefix(clause.Then.Properties.Details.Ref, "#/$defs/")
		var emittedTypes, reserved []string
		for _, eventType := range clause.If.Properties.Type.Enum {
			if emitted[eventType] {
				emittedTypes = append(emittedTypes, eventType)
			} else {
				reserved = append(reserved, eventType)
			}
		}
		if def == "generic" {
			require.Empty(t, emittedTypes, "emitted event types need a structured details schema")
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", def, codeList(emittedTypes), codeList(reserved))
	}
	b.WriteString("\n" + emittedEnd)

	const path = "../../docs/audit-event-schema.md"
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(raw)
	start, end := strings.Index(content, emittedBegin), strings.Index(content, emittedEnd)
	require.True(t, start >= 0 && end > start, "generated markers missing in %s", path)
	updated := content[:start] + b.String() + content[end+len(emittedEnd):]
	if os.Getenv("UPDATE_AUDIT_SCHEMA_DOCS") != "" {
		require.NoError(t, os.WriteFile(path, []byte(updated), 0o600))
		return
	}
	require.Equal(t, updated, content, "emitted event types are stale: run UPDATE_AUDIT_SCHEMA_DOCS=1 go test ./pkg/audit -run TestAuditSchemaEmittedTypesDocumented")
}

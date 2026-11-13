// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package audittest checks audit events captured by test doubles against the
// versioned audit event schema (api/audit/v1).
package audittest

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	auditv1 "github.com/telekom/k8s-breakglass/api/audit/v1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
)

var (
	mu         sync.Mutex
	violations []string
)

// Check validates event as a sink receives it, after the defaults that the
// audit Manager applies, against the strict schema.
func Check(event *audit.Event) error {
	e := *event
	if e.ID == "" {
		e.ID = "audittest"
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = audit.SeverityForEventType(e.Type)
	}
	e.SchemaVersion = audit.SchemaVersion
	raw, err := json.Marshal(&e)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", e.Type, err)
	}
	if err := auditv1.ValidateStrict(raw); err != nil {
		return fmt.Errorf("%s: %w\n%s", e.Type, err, raw)
	}
	return nil
}

// Record keeps a schema violation of event for Main to report. Test doubles
// call it on every captured event.
func Record(event *audit.Event) {
	if err := Check(event); err != nil {
		mu.Lock()
		violations = append(violations, err.Error())
		mu.Unlock()
	}
}

// Main runs the package's tests and fails them when any recorded event
// violated the schema. Use it from TestMain: os.Exit(audittest.Main(m)).
func Main(m *testing.M) int {
	code := m.Run()
	mu.Lock()
	defer mu.Unlock()
	if len(violations) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d emitted audit events violate api/audit/v1/audit-event.schema.json:\n", len(violations))
		for _, v := range violations {
			fmt.Fprintln(os.Stderr, v)
		}
		if code == 0 {
			code = 1
		}
	}
	return code
}

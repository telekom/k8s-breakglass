// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package auditv1 publishes the versioned JSON Schema of one audit event (a
// Kafka record value, a webhook single-event body, or one element of a webhook
// batch's events array) and validates documents against it. The log sink
// flattens events into log fields and is not covered.
// See docs/audit-event-schema.md.
package auditv1

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// SchemaID is the $id of the audit event schema.
// It is a version-stable URN: it names v1, not a branch or file location.
const SchemaID = "urn:telekom:k8s-breakglass:audit-event:v1"

// Schema is the JSON Schema (draft 2020-12) of one audit event.
//
//go:embed audit-event.schema.json
var Schema []byte

var (
	compileOnce       sync.Once
	published, strict *jsonschema.Schema
	errCompile        error
)

func compile() {
	compileOnce.Do(func() {
		published, errCompile = compileSchema(Schema)
		if errCompile != nil {
			return
		}
		var doc any
		if errCompile = json.Unmarshal(Schema, &doc); errCompile != nil {
			return
		}
		closeObjects(doc)
		closed, err := json.Marshal(doc)
		if err != nil {
			errCompile = err
			return
		}
		strict, errCompile = compileSchema(closed)
	})
}

func compileSchema(raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse audit event schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(SchemaID, doc); err != nil {
		return nil, fmt.Errorf("add audit event schema: %w", err)
	}
	schema, err := c.Compile(SchemaID)
	if err != nil {
		return nil, fmt.Errorf("compile audit event schema: %w", err)
	}
	return schema, nil
}

// closeObjects forbids undeclared properties on every object schema ("type"
// "object" or a type list that includes it) that declares properties and
// does not already constrain additional ones. if/then dispatch clauses carry
// no type and stay open.
func closeObjects(node any) {
	switch n := node.(type) {
	case map[string]any:
		if _, ok := n["properties"]; ok && allowsObject(n["type"]) {
			if _, set := n["additionalProperties"]; !set {
				n["additionalProperties"] = false
			}
		}
		for _, child := range n {
			closeObjects(child)
		}
	case []any:
		for _, child := range n {
			closeObjects(child)
		}
	}
}

// Validate checks one JSON-encoded audit event against the published schema.
// The published schema is open: consumers must accept unknown properties.
func Validate(document []byte) error {
	return validate(document, false)
}

// ValidateStrict additionally rejects properties that the schema does not
// declare. CI uses it so that every emitted field is documented.
func ValidateStrict(document []byte) error {
	return validate(document, true)
}

func validate(document []byte, closed bool) error {
	compile()
	if errCompile != nil {
		return errCompile
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("parse audit event: %w", err)
	}
	schema := published
	if closed {
		schema = strict
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("audit event violates schema: %w", err)
	}
	return nil
}

func allowsObject(typ any) bool {
	switch t := typ.(type) {
	case string:
		return t == "object"
	case []any:
		for _, v := range t {
			if v == "object" {
				return true
			}
		}
	}
	return false
}

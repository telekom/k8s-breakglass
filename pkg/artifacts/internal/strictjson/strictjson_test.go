// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package strictjson

import (
	"strings"
	"testing"
)

func TestDecodeRejectsAmbiguityAndBounds(t *testing.T) {
	type nested struct {
		Value string `json:"value"`
	}
	type document struct {
		Name   string `json:"name"`
		Nested nested `json:"nested"`
	}

	for name, input := range map[string]string{
		"duplicate top level": `{"name":"one","name":"two","nested":{"value":"ok"}}`,
		"duplicate nested":    `{"name":"one","nested":{"value":"one","value":"two"}}`,
		"unknown":             `{"name":"one","nested":{"value":"ok"},"extra":true}`,
		"trailing":            `{"name":"one","nested":{"value":"ok"}} {}`,
		"empty":               ``,
	} {
		t.Run(name, func(t *testing.T) {
			var target document
			if err := Decode([]byte(input), 1024, &target); err == nil {
				t.Fatal("Decode() unexpectedly accepted ambiguous input")
			}
		})
	}

	valid := []byte(`{"name":"one","nested":{"value":"ok"}}`)
	var target document
	if err := Decode(valid, len(valid), &target); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if target.Name != "one" || target.Nested.Value != "ok" {
		t.Fatalf("Decode() = %#v", target)
	}
	if err := Decode(valid, len(valid)-1, &target); err == nil || !strings.Contains(err.Error(), "bounded") {
		t.Fatalf("oversized Decode() error = %v", err)
	}
}

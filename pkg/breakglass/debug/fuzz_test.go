package debug

import (
	"testing"
	"unicode/utf8"

	"sigs.k8s.io/yaml"
)

// FuzzYamlQuote tests the yamlQuote function with fuzzed inputs to ensure
// it safely handles any string without panicking and produces valid YAML.
func FuzzYamlQuote(f *testing.F) {
	// Add seed corpus with YAML-sensitive patterns
	seeds := []string{
		"",
		"normal string",
		"string with: colon",
		"string with # comment",
		"string with\nnewline",
		"string with\ttab",
		"string with \"quotes\"",
		"string with 'single quotes'",
		"true", "false", "null", "yes", "no", "~",
		"---", "...",
		"key: value",
		"{ json: object }",
		"[ array, items ]",
		"*alias",
		"&anchor",
		"!!type",
		"@at sign",
		"`backtick`",
		"\\backslash\\",
		"multi\nline\nstring",
		"string\twith\ttabs",
		"unicode: こんにちは",
		"emoji: 🎉🔥💀",
		string(make([]byte, 1000)), // Large input
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			t.Skip()
		}
		var value interface{}
		if err := yaml.Unmarshal([]byte(yamlQuote(input)), &value); err != nil {
			t.Fatal(err)
		}
		if value != input {
			t.Fatalf("scalar changed: %q -> %#v", input, value)
		}
	})
}

// FuzzYamlSafe tests the yamlSafe function with fuzzed inputs
func FuzzYamlSafe(f *testing.F) {
	seeds := []string{
		"",
		"normal string",
		"string:with:colons",
		"###comments###",
		"yaml: injection\nkey: value",
		"{object}",
		"[array]",
		"special!@#$%^&*()chars",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			t.Skip()
		}
		var value interface{}
		if err := yaml.Unmarshal([]byte(yamlSafe(input)), &value); err != nil {
			t.Fatal(err)
		}
		if _, ok := value.(string); !ok {
			t.Fatalf("expected string, got %#v", value)
		}
	})
}

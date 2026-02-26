package debug

import (
	"strings"
	"testing"
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
		// yamlQuote should never panic
		result := yamlQuote(input)

		// Result should not be empty if input was non-empty
		// (empty input returns '""')
		if len(result) == 0 && len(input) > 0 {
			t.Errorf("yamlQuote(%q) returned empty string", input)
		}

		// If the result is quoted, it should start and end with quotes
		if len(result) > 1 && result[0] == '"' {
			if result[len(result)-1] != '"' {
				t.Errorf("yamlQuote(%q) has unbalanced quotes: %q", input, result)
			}
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
		// yamlSafe should never panic
		result := yamlSafe(input)

		// Result should not contain dangerous YAML characters
		dangerousChars := []rune{':', '#', '{', '}', '[', ']', '|', '>', '!', '&', '*', '?', '\'', '"', '\\', '`', '@'}
		for _, char := range dangerousChars {
			if strings.ContainsRune(result, char) {
				t.Errorf("yamlSafe(%q) still contains dangerous char %q: %q", input, char, result)
			}
		}
	})
}

package main

import "testing"

func TestRunVersionCommand(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := run([]string{"unknown-command"}); code != 2 {
		t.Fatalf("expected exit code 2 for unknown command, got %d", code)
	}
}

func TestRunNestedUnknownCommand(t *testing.T) {
	tests := [][]string{
		{"session", "unknown-command"},
		{"debug", "session", "unknown-command"},
		{"config", "unknown-command"},
	}

	for _, args := range tests {
		if code := run(args); code != 2 {
			t.Fatalf("expected exit code 2 for args %v, got %d", args, code)
		}
	}
}

func TestRunHelpOnlyGroup(t *testing.T) {
	if code := run([]string{"session"}); code != 0 {
		t.Fatalf("expected exit code 0 for help-only group, got %d", code)
	}
}

func TestRunUsageError(t *testing.T) {
	if code := run([]string{"session", "get"}); code != 2 {
		t.Fatalf("expected exit code 2 for missing required argument, got %d", code)
	}
}

func TestRunRequiredFlagUsageError(t *testing.T) {
	if code := run([]string{"config", "init", "--oidc-provider", "prod"}); code != 2 {
		t.Fatalf("expected exit code 2 for missing required flag, got %d", code)
	}
}

func TestRunGeneralError(t *testing.T) {
	if code := run([]string{"completion", "unsupported"}); code != 1 {
		t.Fatalf("expected exit code 1 for non-usage command error, got %d", code)
	}
}

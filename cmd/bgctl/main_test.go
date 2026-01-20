package main

import "testing"

func TestRunVersionCommand(t *testing.T) {
	if code := run([]string{"version"}); code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := run([]string{"unknown-command"}); code == 0 {
		t.Fatalf("expected non-zero exit code for unknown command")
	}
}

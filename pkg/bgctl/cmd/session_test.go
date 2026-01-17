package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSessionListCommand(t *testing.T) {
	// Test skipped - requires full runtime context initialization
	// Integration test exists in e2e/cli/cli_e2e_test.go
	t.Skip("Command execution tests moved to e2e")
}

func TestSessionGetCommand(t *testing.T) {
	// Test skipped - requires full runtime context initialization
	// Integration test exists in e2e/cli/cli_e2e_test.go
	t.Skip("Command execution tests moved to e2e")
}

func TestSessionRequestCommand(t *testing.T) {
	// Test skipped - requires full runtime context initialization
	// Integration test exists in e2e/cli/cli_e2e_test.go
	t.Skip("Command execution tests moved to e2e")
}

func TestConfigViewCommand(t *testing.T) {
	// Test skipped - requires full runtime context initialization
	// Integration test exists in e2e/cli/cli_e2e_test.go
	t.Skip("Command execution tests moved to e2e")
}

func TestBuildClientWithoutConfig(t *testing.T) {
	rt := &runtimeState{
		configPath:     filepath.Join(os.TempDir(), "nonexistent-config.yaml"),
		serverOverride: "",
		tokenOverride:  "",
	}

	_, err := buildClient(context.Background(), rt)
	require.Error(t, err)
	require.Contains(t, err.Error(), "config")
}

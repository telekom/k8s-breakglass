// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRootExecuteContextPreservesRuntime(t *testing.T) {
	root := NewRootCommand(Config{OutputWriter: &bytes.Buffer{}})
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "caller")
	root.AddCommand(&cobra.Command{
		Use: "context-proof",
		RunE: func(command *cobra.Command, _ []string) error {
			require.Equal(t, "caller", command.Context().Value(contextKey{}))
			runtime, err := getRuntime(command)
			require.NoError(t, err)
			require.Equal(t, "https://api.example.test", runtime.serverOverride)
			require.NotNil(t, runtime.cfg)
			return nil
		},
	})
	root.SetArgs([]string{"--server", "https://api.example.test", "--token", "test-token", "context-proof"})
	require.NoError(t, root.ExecuteContext(ctx))
}

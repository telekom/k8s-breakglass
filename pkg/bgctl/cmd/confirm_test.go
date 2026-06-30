package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestConfirmAction(t *testing.T) {
	t.Run("proceeds with yes", func(t *testing.T) {
		cmd := &cobra.Command{}
		rt := &runtimeState{}
		err := confirmAction(cmd, rt, "drop", "session", true)
		assert.NoError(t, err)
	})

	t.Run("fails in non-interactive without yes", func(t *testing.T) {
		cmd := &cobra.Command{}
		rt := &runtimeState{nonInteractive: true}
		err := confirmAction(cmd, rt, "drop", "session", false)
		assert.ErrorContains(t, err, "confirmation required")
	})

	t.Run("cancels on n input", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("n\n"))
		var buf bytes.Buffer
		rt := &runtimeState{writer: &buf}
		err := confirmAction(cmd, rt, "drop", "session", false)
		assert.ErrorContains(t, err, "canceled")
	})

	t.Run("proceeds on y input", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("y\n"))
		var buf bytes.Buffer
		rt := &runtimeState{writer: &buf}
		err := confirmAction(cmd, rt, "drop", "session", false)
		assert.NoError(t, err)
	})
}

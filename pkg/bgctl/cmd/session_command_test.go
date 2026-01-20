package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSessionCommand_Subcommands(t *testing.T) {
	cmd := NewSessionCommand()
	assert.Equal(t, "session", cmd.Use)

	var names []string
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "list")
	assert.Contains(t, names, "get")
	assert.Contains(t, names, "request")
	assert.Contains(t, names, "approve")
	assert.Contains(t, names, "reject")
	assert.Contains(t, names, "withdraw")
	assert.Contains(t, names, "drop")
	assert.Contains(t, names, "cancel")
	assert.Contains(t, names, "watch")
}

func TestSessionListCommand_DefaultFlags(t *testing.T) {
	cmd := newSessionListCommand()

	mine, _ := cmd.Flags().GetBool("mine")
	approver, _ := cmd.Flags().GetBool("approver")
	approvedByMe, _ := cmd.Flags().GetBool("approved-by-me")
	activeOnly, _ := cmd.Flags().GetBool("active")

	assert.False(t, mine)
	assert.True(t, approver)
	assert.False(t, approvedByMe)
	assert.False(t, activeOnly)
}

func TestSessionWatchCommand_DefaultFlags(t *testing.T) {
	cmd := newSessionWatchCommand()

	interval, _ := cmd.Flags().GetDuration("interval")
	approver, _ := cmd.Flags().GetBool("approver")
	activeOnly, _ := cmd.Flags().GetBool("active")
	showFull, _ := cmd.Flags().GetBool("show-full")

	assert.Equal(t, 2*time.Second, interval)
	assert.True(t, approver)
	assert.False(t, activeOnly)
	assert.False(t, showFull)
}

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthCommandStructure(t *testing.T) {
	cmd := NewAuthCommand()
	assert.Equal(t, "auth", cmd.Use)
	assert.Contains(t, cmd.Short, "Authenticate")

	subs := map[string]bool{}
	for _, sub := range cmd.Commands() {
		subs[sub.Use] = true
	}
	assert.True(t, subs["login"])
	assert.True(t, subs["status"])
	assert.True(t, subs["logout"])
}

func TestAuthSubcommands(t *testing.T) {
	login := newAuthLoginCommand()
	status := newAuthStatusCommand()
	logout := newAuthLogoutCommand()

	assert.Equal(t, "login", login.Use)
	assert.Equal(t, "status", status.Use)
	assert.Equal(t, "logout", logout.Use)
	assert.Contains(t, login.Short, "Login")
	assert.Contains(t, status.Short, "status")
	assert.Contains(t, logout.Short, "Remove cached token")
}

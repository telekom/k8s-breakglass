package system

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestLogger(t *testing.T) {
	logger := NewTestLogger()
	require.NotNil(t, logger)

	// Verify it's a sugared logger that can log without panicking
	logger.Info("test message")
	logger.Infow("test message with fields", "key", "value")
}

func TestNewTestZapLogger(t *testing.T) {
	logger := NewTestZapLogger()
	require.NotNil(t, logger)

	// Verify it's a zap logger that can log without panicking
	logger.Info("test message")

	// Verify we can get a sugared logger from it
	sugared := logger.Sugar()
	assert.NotNil(t, sugared)
	sugared.Infow("sugared test message", "key", "value")
}

package breakglass

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestGetLoggerOrDefault(t *testing.T) {
	t.Run("returns global logger when no args", func(t *testing.T) {
		got := getLoggerOrDefault()
		assert.NotNil(t, got)
		// Should return the exact same pointer as the global sugared logger
		assert.Same(t, zap.S(), got)
	})

	t.Run("returns global logger when nil arg", func(t *testing.T) {
		got := getLoggerOrDefault(nil)
		assert.NotNil(t, got)
		assert.Same(t, zap.S(), got)
	})

	t.Run("returns provided logger", func(t *testing.T) {
		testLogger := zaptest.NewLogger(t).Sugar()
		got := getLoggerOrDefault(testLogger)
		assert.Same(t, testLogger, got)
	})

	t.Run("returns first non-nil logger from multiple args", func(t *testing.T) {
		testLogger := zaptest.NewLogger(t).Sugar()
		otherLogger := zaptest.NewLogger(t).Sugar()
		got := getLoggerOrDefault(nil, testLogger, otherLogger)
		assert.Same(t, testLogger, got)
	})

	t.Run("returns global logger when all args nil", func(t *testing.T) {
		got := getLoggerOrDefault(nil, nil, nil)
		assert.NotNil(t, got)
		assert.Same(t, zap.S(), got)
	})
}

func TestNopLogger(t *testing.T) {
	// nopLogger should be a valid, non-nil no-op logger
	assert.NotNil(t, nopLogger)
}

package system

import (
	"go.uber.org/zap"
)

// NewTestLogger returns a sugared logger configured for tests. It mirrors the
// development logger but disables automatic stacktraces so normal test logs
// don't include stack frames.
func NewTestLogger() *zap.SugaredLogger {
	cfg := zap.NewDevelopmentConfig()
	cfg.DisableStacktrace = true
	logger, _ := cfg.Build()
	return logger.Sugar()
}

// NewTestZapLogger returns a non-sugared *zap.Logger for tests that expect
// the original zap.Logger type (so they can call .Sugar() themselves).
func NewTestZapLogger() *zap.Logger {
	cfg := zap.NewDevelopmentConfig()
	cfg.DisableStacktrace = true
	logger, _ := cfg.Build()
	return logger
}

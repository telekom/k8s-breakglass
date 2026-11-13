// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package logging builds the zap logger of the breakglass programs and
// registers the shared --log-level and --log-format flags.
package logging

import (
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Accepted --log-format values.
const (
	FormatJSON    = "json"
	FormatConsole = "console"
)

// Options holds the values of --log-level and --log-format.
type Options struct {
	Level  string
	Format string
}

// AddFlags registers --log-level and --log-format on fs. Each defaults to the
// environment variable LOG_LEVEL or LOG_FORMAT when set, and otherwise to
// defaultLevel or defaultFormat.
func (o *Options) AddFlags(fs *flag.FlagSet, defaultLevel, defaultFormat string) {
	fs.StringVar(&o.Level, "log-level", envOr("LOG_LEVEL", defaultLevel),
		"Log level: debug, info, warn or error (env LOG_LEVEL)")
	fs.StringVar(&o.Format, "log-format", envOr("LOG_FORMAT", defaultFormat),
		"Log format: json or console (env LOG_FORMAT)")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// New creates a logger that writes to stderr for a level (debug, info, warn,
// error) and a format. The "json" format is zap's production profile and the
// "console" format its development profile (human-readable; DPanic panics).
// Stacktraces are only added for DPanic level and above to reduce log noise
// during normal error handling (transient network errors, etc.).
func New(level, format string) (*zap.Logger, error) {
	var cfg zap.Config
	switch format {
	case FormatJSON:
		cfg = zap.NewProductionConfig()
	case FormatConsole:
		cfg = zap.NewDevelopmentConfig()
	default:
		return nil, fmt.Errorf("invalid log format %q: must be json or console", format)
	}
	var lvl zapcore.Level
	switch level {
	case "debug", "info", "warn", "error":
		if err := lvl.UnmarshalText([]byte(level)); err != nil {
			return nil, fmt.Errorf("parse log level %q: %w", level, err)
		}
	default:
		return nil, fmt.Errorf("invalid log level %q: must be debug, info, warn or error", level)
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.StacktraceKey = "" // Disable stacktrace field entirely
	logger, err := cfg.Build(zap.AddStacktrace(zap.DPanicLevel))
	if err != nil {
		return nil, fmt.Errorf("unable to create logger (level %s, format %s): %w", level, format, err)
	}
	return logger, nil
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package logging builds the zap logger of the breakglass programs and
// registers the shared --log-level and --log-format flags.
package logging

import (
	"flag"
	"fmt"
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Accepted --log-format values. FormatText is accepted by NewWriter only.
const (
	FormatJSON    = "json"
	FormatConsole = "console"
	// FormatText writes "<logger name>: <message>" per line, the historical
	// error output of the command-line tools.
	FormatText = "text"
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
		"Log format: json, console or text where supported (env LOG_FORMAT)")
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
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.StacktraceKey = "" // Disable stacktrace field entirely
	logger, err := cfg.Build(zap.AddStacktrace(zap.DPanicLevel))
	if err != nil {
		return nil, fmt.Errorf("unable to create logger (level %s, format %s): %w", level, format, err)
	}
	return logger, nil
}

// NewWriter creates a logger for a command-line tool that writes to w. It
// accepts the formats of New and FormatText, and does not sample.
func NewWriter(w io.Writer, level, format string) (*zap.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	sink := zapcore.Lock(zapcore.AddSync(w))
	opts := []zap.Option{zap.ErrorOutput(sink)}
	var enc zapcore.Encoder
	switch format {
	case FormatJSON:
		ec := zap.NewProductionEncoderConfig()
		ec.StacktraceKey = ""
		enc = zapcore.NewJSONEncoder(ec)
		opts = append(opts, zap.AddCaller())
	case FormatConsole:
		ec := zap.NewDevelopmentEncoderConfig()
		ec.StacktraceKey = ""
		enc = zapcore.NewConsoleEncoder(ec)
		opts = append(opts, zap.AddCaller())
	case FormatText:
		enc = zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
			MessageKey:       "msg",
			NameKey:          "logger",
			EncodeName:       zapcore.FullNameEncoder,
			ConsoleSeparator: ": ",
		})
	default:
		return nil, fmt.Errorf("invalid log format %q: must be json, console or text", format)
	}
	return zap.New(zapcore.NewCore(enc, sink, lvl), opts...), nil
}

func parseLevel(level string) (zapcore.Level, error) {
	var lvl zapcore.Level
	switch level {
	case "debug", "info", "warn", "error":
		if err := lvl.UnmarshalText([]byte(level)); err != nil {
			return lvl, fmt.Errorf("parse log level %q: %w", level, err)
		}
		return lvl, nil
	default:
		return lvl, fmt.Errorf("invalid log level %q: must be debug, info, warn or error", level)
	}
}

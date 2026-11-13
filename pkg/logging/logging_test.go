// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// captureStderr runs fn with os.Stderr redirected to a file and returns what
// was written. zap's "stderr" sink binds os.Stderr when the logger is built.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = orig }()
	fn()
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestNew(t *testing.T) {
	tests := []struct {
		name, level, format string
		wantErr             string
		wantEnabled         []zapcore.Level // lowest enabled level first
		wantDisabled        zapcore.Level
		wantJSON            bool
	}{
		{name: "default info json", level: "info", format: "json", wantEnabled: []zapcore.Level{zap.InfoLevel, zap.WarnLevel, zap.ErrorLevel}, wantDisabled: zap.DebugLevel, wantJSON: true},
		{name: "debug json", level: "debug", format: "json", wantEnabled: []zapcore.Level{zap.DebugLevel, zap.InfoLevel}, wantDisabled: zap.DebugLevel - 1, wantJSON: true},
		{name: "legacy --debug: debug console", level: "debug", format: "console", wantEnabled: []zapcore.Level{zap.DebugLevel, zap.InfoLevel}, wantDisabled: zap.DebugLevel - 1},
		{name: "info console", level: "info", format: "console", wantEnabled: []zapcore.Level{zap.InfoLevel}, wantDisabled: zap.DebugLevel},
		{name: "warn json", level: "warn", format: "json", wantEnabled: []zapcore.Level{zap.WarnLevel, zap.ErrorLevel}, wantDisabled: zap.InfoLevel, wantJSON: true},
		{name: "error json", level: "error", format: "json", wantEnabled: []zapcore.Level{zap.ErrorLevel}, wantDisabled: zap.WarnLevel, wantJSON: true},
		{name: "unknown level", level: "verbose", format: "json", wantErr: `invalid log level "verbose"`},
		{name: "fatal level not accepted", level: "fatal", format: "json", wantErr: `invalid log level "fatal"`},
		{name: "empty level", level: "", format: "json", wantErr: `invalid log level ""`},
		{name: "unknown format", level: "info", format: "text", wantErr: `invalid log format "text"`},
		{name: "empty format", level: "info", format: "", wantErr: `invalid log format ""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logger *zap.Logger
			var err error
			out := captureStderr(t, func() {
				logger, err = New(tt.level, tt.format)
				if err != nil {
					return
				}
				logger.Debug("debug line", zap.String("k", "v"))
				logger.Named("component").Error("error line", zap.Error(errors.New("boom")))
				_ = logger.Sync()
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New(%q, %q) error = %v, want %q", tt.level, tt.format, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q, %q): %v", tt.level, tt.format, err)
			}
			for _, l := range tt.wantEnabled {
				if !logger.Core().Enabled(l) {
					t.Errorf("%s not enabled", l)
				}
			}
			if logger.Core().Enabled(tt.wantDisabled) {
				t.Errorf("%s enabled", tt.wantDisabled)
			}
			if got := strings.Contains(out, "debug line"); got != (tt.level == "debug") {
				t.Errorf("debug line written = %t, output:\n%s", got, out)
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			for _, line := range lines {
				var entry map[string]any
				isJSON := json.Unmarshal([]byte(line), &entry) == nil
				if isJSON != tt.wantJSON {
					t.Fatalf("line is JSON = %t, want %t: %s", isJSON, tt.wantJSON, line)
				}
				if !tt.wantJSON {
					continue
				}
				// The documented JSON fields (docs/logging-and-debugging.md).
				for _, key := range []string{"level", "ts", "caller", "msg"} {
					if _, ok := entry[key]; !ok {
						t.Errorf("JSON line has no %q: %s", key, line)
					}
				}
				if _, ok := entry["stacktrace"]; ok {
					t.Errorf("JSON line has a stacktrace: %s", line)
				}
				if _, ok := entry["ts"].(float64); !ok {
					t.Errorf("ts is not epoch seconds: %s", line)
				}
				if entry["msg"] == "error line" && (entry["level"] != "error" || entry["logger"] != "component" || entry["error"] != "boom") {
					t.Errorf("error line fields: %s", line)
				}
				if entry["msg"] == "debug line" && (entry["level"] != "debug" || entry["k"] != "v") {
					t.Errorf("debug line fields: %s", line)
				}
			}
		})
	}
}

func TestAddFlags(t *testing.T) {
	tests := []struct {
		name                  string
		env                   map[string]string
		args                  []string
		wantLevel, wantFormat string
	}{
		{name: "program defaults", wantLevel: "warn", wantFormat: "console"},
		{name: "env", env: map[string]string{"LOG_LEVEL": "debug", "LOG_FORMAT": "json"}, wantLevel: "debug", wantFormat: "json"},
		{name: "flags override env", env: map[string]string{"LOG_LEVEL": "debug", "LOG_FORMAT": "json"}, args: []string{"--log-level=error", "--log-format=console"}, wantLevel: "error", wantFormat: "console"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", "")
			t.Setenv("LOG_FORMAT", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var o Options
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			o.AddFlags(fs, "warn", "console")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if o.Level != tt.wantLevel || o.Format != tt.wantFormat {
				t.Fatalf("got %s/%s, want %s/%s", o.Level, o.Format, tt.wantLevel, tt.wantFormat)
			}
		})
	}
}

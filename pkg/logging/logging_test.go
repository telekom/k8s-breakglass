// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/grpclog"
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

func TestNewWriter(t *testing.T) {
	tests := []struct {
		name, level, format string
		want                func(t *testing.T, out string)
		wantErr             string
	}{
		{name: "text keeps the historical tool output", level: "info", format: FormatText, want: func(t *testing.T, out string) {
			if out != "tool: boom\n" {
				t.Fatalf("output %q", out)
			}
		}},
		{name: "json", level: "debug", format: FormatJSON, want: func(t *testing.T, out string) {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) != 2 {
				t.Fatalf("want debug and error lines, got %q", out)
			}
			for _, line := range lines {
				var e map[string]any
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatalf("not JSON: %s", line)
				}
				if e["logger"] != "tool" || e["caller"] == nil || e["ts"] == nil {
					t.Fatalf("fields: %s", line)
				}
			}
		}},
		{name: "console", level: "warn", format: FormatConsole, want: func(t *testing.T, out string) {
			if !strings.Contains(out, "ERROR\ttool\t") || strings.Contains(out, "debug line") {
				t.Fatalf("output %q", out)
			}
		}},
		{name: "text is not a controller format", level: "info", format: "yaml", wantErr: `invalid log format "yaml"`},
		{name: "bad level", level: "trace", format: FormatText, wantErr: `invalid log level "trace"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf strings.Builder
			logger, err := NewWriter(&buf, tt.level, tt.format)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			logger = logger.Named("tool")
			logger.Debug("debug line")
			logger.Error("boom")
			tt.want(t, buf.String())
		})
	}
	if _, err := New("info", FormatText); err == nil {
		t.Fatal("New must reject the text format")
	}
}

// TestNewDoesNotSample proves that repeated identical lines, such as
// authorization decisions, are all written.
func TestNewDoesNotSample(t *testing.T) {
	out := captureStderr(t, func() {
		logger, err := New("info", FormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		for range 1000 {
			logger.Info("authorization decision", zap.String("decision", "allow"))
		}
		_ = logger.Sync()
	})
	if n := strings.Count(out, `"msg":"authorization decision"`); n != 1000 {
		t.Fatalf("got %d of 1000 lines", n)
	}
}

// TestRouteLibraryLogsTLSHandshakeError proves that an http.Server without an
// ErrorLog logs a TLS handshake error as a JSON line.
func TestRouteLibraryLogsTLSHandshakeError(t *testing.T) {
	out := captureStderr(t, func() {
		logger, err := New("info", FormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		defer RouteLibraryLogs(logger)()

		srv := httptest.NewUnstartedServer(http.NotFoundHandler())
		srv.StartTLS()
		defer srv.Close()
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")) // plain HTTP to a TLS port
		_ = conn.Close()

		deadline := time.Now().Add(10 * time.Second)
		for {
			written, _ := os.ReadFile(os.Stderr.Name())
			if strings.Contains(string(written), "TLS handshake error") {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("no TLS handshake error logged; output: %q", written)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	found := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if msg, _ := e["msg"].(string); strings.Contains(msg, "TLS handshake error") {
			found = true
			if e["level"] != "warn" || e["logger"] != "stdlog" {
				t.Fatalf("fields: %s", line)
			}
		}
	}
	if !found {
		t.Fatalf("no TLS handshake error line in %q", out)
	}
}

// TestRouteLibraryLogsGRPC proves that gRPC errors, such as those of the OTLP
// gRPC exporter, are JSON lines, and that gRPC info messages are dropped.
func TestRouteLibraryLogsGRPC(t *testing.T) {
	out := captureStderr(t, func() {
		logger, err := New("info", FormatJSON)
		if err != nil {
			t.Fatal(err)
		}
		defer RouteLibraryLogs(logger)()
		grpclog.Info("grpc chatter")
		grpclog.Errorf("export failed: %s", "connection refused")
		_ = logger.Sync()
	})
	if strings.Contains(out, "grpc chatter") {
		t.Fatalf("gRPC info logged: %q", out)
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &e); err != nil {
		t.Fatalf("not one JSON line: %q", out)
	}
	if e["level"] != "error" || e["logger"] != "grpc" || e["msg"] != "export failed: connection refused" {
		t.Fatalf("fields: %v", e)
	}
}

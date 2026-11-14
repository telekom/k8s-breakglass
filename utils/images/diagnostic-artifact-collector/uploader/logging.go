// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

// This file is identical in every standard-library-only helper image
// (utils/node-maintenance/cmd/*, utils/images/diagnostic-artifact-collector/*).
// Those images build each helper from its own directory with GO111MODULE=off,
// so they cannot import pkg/logging; the helpers' argument lists are fixed,
// so the settings come from the environment only.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// newLogger builds the stderr logger of a helper from LOG_LEVEL (debug, info,
// warn, error; default info) and LOG_FORMAT (text, the default, or json).
// The text format writes "<prefix>: <message>" lines, or only the message when
// prefix is empty, which is the helpers' historical output. The json format
// writes one object per line with the keys level, ts, logger and msg, like
// the controller.
func newLogger(w io.Writer, name, prefix string) (*slog.Logger, error) {
	var level slog.Level
	switch v := os.Getenv("LOG_LEVEL"); v {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid LOG_LEVEL %q: must be debug, info, warn or error", v)
	}
	switch v := os.Getenv("LOG_FORMAT"); v {
	case "", "text", "console":
		return slog.New(&textHandler{w: w, prefix: prefix, level: level}), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: jsonKeys})).With("logger", name), nil
	default:
		return nil, fmt.Errorf("invalid LOG_FORMAT %q: must be text or json", v)
	}
}

// jsonKeys uses the controller's key names and lower-case levels.
func jsonKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		return slog.Float64("ts", float64(a.Value.Time().UnixNano())/1e9)
	case slog.LevelKey:
		return slog.String("level", strings.ToLower(a.Value.String()))
	}
	return a
}

// textHandler writes "<prefix>: <message>" and ignores attributes.
type textHandler struct {
	w      io.Writer
	prefix string
	level  slog.Level
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	line := r.Message + "\n"
	if h.prefix != "" {
		line = h.prefix + ": " + line
	}
	_, err := io.WriteString(h.w, line)
	return err
}

func (h *textHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *textHandler) WithGroup(string) slog.Handler { return h }

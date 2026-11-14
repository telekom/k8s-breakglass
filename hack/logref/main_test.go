// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggingReferenceUpToDate fails when docs/logging-reference.md does not
// list exactly the log messages, levels and fields of the code.
func TestLoggingReferenceUpToDate(t *testing.T) {
	if err := run(filepath.Join("..", ".."), true); err != nil {
		t.Fatal(err)
	}
}

func TestScanExtractsMessagesLevelsAndFields(t *testing.T) {
	root := t.TempDir()
	src := `package x

func f() {
	log.Infow("session approved", "user", u, "cluster", c)
	s.logger.With("cid", id).Warnf("retry %d", n)
	zapLogger.Error("send failed", zap.String("recipient", r), zap.Error(err))
	r.Log.Error(err, "reconcile failed", "name", n)
	r.Log.V(1).Info("cache hit", "key", k)
	log.Debug("value: " + v)
	log.Error(err)
	zap.S().Warnw("global sugared", "k", v)
	c.Error(err)
	fmt.Errorf("not a log %d", 1)
	err.Error()
}
`
	writeFile(t, filepath.Join(root, "pkg", "x", "x.go"), src)
	writeFile(t, filepath.Join(root, "pkg", "x", "x_test.go"), "package x\nfunc g() { log.Info(\"test only\") }\n")
	writeFile(t, filepath.Join(root, "pkg", "bgctl", "y.go"), "package y\nfunc g() { lg.Infow(\"cli\", \"email\", e) }\n")

	entries, _, err := scan(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.app+" "+e.level+" "+e.message] = strings.Join(sortedKeys(e.fields), ",")
	}
	want := map[string]string{
		"controller info session approved":  "cluster,user",
		"controller warn retry %d":          "cid",
		"controller error send failed":      "error,recipient",
		"controller error reconcile failed": "error,name",
		"controller debug (V(1)) cache hit": "key",
		"controller debug value: …":         "",
		"controller error (dynamic)":        "",
		"controller warn global sugared":    "k",
		"bgctl info cli":                    "email",
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%q: fields %q (present %t), want %q", k, g, ok, v)
		}
	}

	md := render(entries)
	for _, s := range []string{"| controller | 1 | 1 | 2 | 3 | 0 | 0 | 1 |", "`recipient`†", "`email`†", "`cluster`,"} {
		if !strings.Contains(md, s) {
			t.Errorf("rendered catalogue lacks %q:\n%s", s, md)
		}
	}
}

func TestRunCheckDetectsDrift(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pkg", "x", "x.go"), "package x\nfunc f() { log.Info(\"hello\") }\n")
	writeFile(t, filepath.Join(root, docPath), "# Ref\n"+beginMark+"\n"+endMark+"\n")
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "out of date") {
		t.Fatalf("check on a stale doc: %v", err)
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatalf("check after regeneration: %v", err)
	}
	doc, _ := os.ReadFile(filepath.Join(root, docPath))
	if !strings.Contains(string(doc), "`hello`") {
		t.Fatalf("regenerated doc lacks the message:\n%s", doc)
	}
}

func TestRunRequiresEveryProgram(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "cmd", "tool", "main.go"), "package main\nfunc main() {}\n")
	writeFile(t, filepath.Join(root, docPath), "# Ref\n"+beginMark+"\n`cmd/tool`\n"+endMark+"\n")
	if err := run(root, false); err == nil || !strings.Contains(err.Error(), "cmd/tool") {
		t.Fatalf("a program named only in the generated section: %v", err)
	}
	writeFile(t, filepath.Join(root, docPath), "# Ref\n| `cmd/tool` | … |\n"+beginMark+"\n"+endMark+"\n")
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
}

func TestRunRejectsWrongProseLevel(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pkg", "x", "x.go"), "package x\nfunc f() { log.Warnw(\"exporter failed\", \"error\", err) }\n")
	writeFile(t, filepath.Join(root, docPath), "# Ref\nFailed exports are logged as `exporter failed` at error.\n"+beginMark+"\n"+endMark+"\n")
	if err := run(root, false); err == nil || !strings.Contains(err.Error(), `"exporter failed" is logged at warn`) {
		t.Fatalf("wrong level not detected: %v", err)
	}
	writeFile(t, filepath.Join(root, docPath), "# Ref\nFailed exports are logged as `exporter failed` at warn.\n"+beginMark+"\n"+endMark+"\n")
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}

	// A table row: the Level column must hold the code's level, even when
	// other cells mention other levels.
	table := func(level string) string {
		return "# Ref\n\n| Source | Level | Message |\n|---|---|---|\n| SDK | " + level +
			" for export errors; SDK warnings at debug | `exporter failed`; otherwise info |\n\n" + beginMark + "\n" + endMark + "\n"
	}
	writeFile(t, filepath.Join(root, docPath), table("error"))
	if err := run(root, false); err == nil || !strings.Contains(err.Error(), `"exporter failed" is logged at warn, but the reference says error`) {
		t.Fatalf("wrong table level not detected: %v", err)
	}
	writeFile(t, filepath.Join(root, docPath), table("warn"))
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

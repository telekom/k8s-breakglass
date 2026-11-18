// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Command logref generates the message catalogue in docs/logging-reference.md
// from the logger call sites in the Go code of this module.
//
//	go run ./hack/logref          # rewrite the generated section
//	go run ./hack/logref -check   # fail if the section is out of date
//
// It parses the source without type information. A call counts as a log call
// when its method is Debug, Info, Warn, Error, DPanic or Fatal (optionally
// with the suffix w or f), it has arguments, and its receiver expression
// names a logger (contains "log", or is lg/rl). The message is the string
// literal argument; the fields are the literal keys of key-value pairs, zap
// field constructors and With/WithValues calls on the receiver.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	docPath    = "docs/logging-reference.md"
	beginMark  = "<!-- BEGIN GENERATED: go run ./hack/logref -->"
	endMark    = "<!-- END GENERATED -->"
	dynamicMsg = "(dynamic)"
)

var (
	methodRe = regexp.MustCompile(`^(Debug|Info|Warn|Error|DPanic|Fatal)(w|f)?$`)
	vLevelRe = regexp.MustCompile(`\.V\((\d+)\)`)
	levels   = []string{"debug", "info", "warn", "error", "dpanic", "fatal"}
)

// entry is one distinct message of one component at one level.
type entry struct {
	app, component, level, message string
	fields, files                  map[string]bool
}

func main() {
	check := flag.Bool("check", false, "fail if "+docPath+" is out of date instead of rewriting it")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	entries, mains, err := scan(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, docPath)
	doc, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", docPath, err)
	}
	if err := checkPrograms(string(doc), mains); err != nil {
		return err
	}
	if err := checkProseLevels(string(doc), entries); err != nil {
		return err
	}
	updated, err := replaceSection(string(doc), render(entries))
	if err != nil {
		return err
	}
	if updated == string(doc) {
		return nil
	}
	if check {
		return fmt.Errorf("%s is out of date with the log calls in the code; run `go run ./hack/logref` and commit the result", docPath)
	}
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", docPath, err)
	}
	return nil
}

// checkPrograms requires the hand-written part of the reference to name every
// main package, as `dir` or `dir/main.go`.
func checkPrograms(doc string, mains map[string]bool) error {
	prose, _, _ := strings.Cut(doc, beginMark)
	var missing []string
	for _, dir := range sortedKeys(mains) {
		if !strings.Contains(prose, "`"+dir+"`") && !strings.Contains(prose, "`"+dir+"/main.go`") {
			missing = append(missing, dir)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s does not describe the programs %s; add them to \"Programs that log\"", docPath, strings.Join(missing, ", "))
	}
	return nil
}

var (
	backtickRe = regexp.MustCompile("`([^`]+)`")
	// A level word not joined to other words ("debug-session" is not one).
	levelWordRe = regexp.MustCompile(`(?:^|[^\w-])(debug|info|warn|error)(?:[^\w-]|$)`)
	// statedLevelRe matches the level stated right after a backticked name:
	// "`msg` (warn)", "`msg` at info", "`msg` lines are at info".
	statedLevelRe = regexp.MustCompile("`([^`]+)`(?:\\s+lines?)?(?:\\s+are)?\\s+(?:\\(|at\\s+)`?(debug|info|warn|error)\\b")
)

// checkProseLevels fails when the hand-written part states a level for a
// catalogued message that the code does not log it at. A level is stated
// right after the message ("`msg` (warn)", "`msg` at warn"), or, in a table
// with a Level column, by the first level in that column of the row.
func checkProseLevels(doc string, entries map[string]*entry) error {
	levelsOf := map[string]map[string]bool{}
	for _, e := range entries {
		if e.message == dynamicMsg || len(e.message) < 8 {
			continue
		}
		if levelsOf[e.message] == nil {
			levelsOf[e.message] = map[string]bool{}
		}
		levelsOf[e.message][strings.Fields(e.level)[0]] = true
	}
	var bad []string
	check := func(msg, level string) {
		if want, ok := levelsOf[msg]; ok && !want[level] {
			bad = append(bad, fmt.Sprintf("%q is logged at %s, but the reference says %s", msg, strings.Join(sortedKeys(want), "/"), level))
		}
	}
	prose, _, _ := strings.Cut(doc, beginMark)
	levelCol := -1
	for _, line := range strings.Split(prose, "\n") {
		for _, m := range statedLevelRe.FindAllStringSubmatch(line, -1) {
			check(m[1], m[2])
		}
		if !strings.HasPrefix(line, "|") {
			levelCol = -1
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if levelCol < 0 {
			for i, c := range cells {
				if strings.EqualFold(strings.TrimSpace(c), "level") {
					levelCol = i
				}
			}
			continue
		}
		if levelCol >= len(cells) {
			continue
		}
		words := levelWordRe.FindStringSubmatch(strings.ReplaceAll(cells[levelCol], "`", " "))
		if words == nil {
			continue
		}
		for i, c := range cells {
			if i == levelCol {
				continue
			}
			for _, m := range backtickRe.FindAllStringSubmatch(c, -1) {
				check(m[1], words[1])
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s states wrong levels: %s", docPath, strings.Join(bad, "; "))
	}
	return nil
}

// checkPersonalData requires every logged key to be in exactly one of
// personalData and notPersonal, and both lists to name only logged keys.
func checkPersonalData(entries map[string]*entry) error {
	logged := map[string]bool{}
	for _, e := range entries {
		for f := range e.fields {
			logged[f] = true
		}
	}
	not := map[string]bool{}
	for _, k := range notPersonal {
		not[k] = true
	}
	var bad []string
	for _, k := range sortedKeys(logged) {
		if _, classified := personalData[k]; !classified && !not[k] {
			bad = append(bad, fmt.Sprintf("log key %q is in neither personalData nor notPersonal; classify it", k))
		}
	}
	for k, p := range personalData {
		if !logged[k] {
			bad = append(bad, fmt.Sprintf("personalData lists %q, which no log call uses", k))
		}
		if not[k] {
			bad = append(bad, fmt.Sprintf("%q is in both personalData and notPersonal", k))
		}
		if !validClass[p.class] || !validSubject[p.subject] || p.content == "" {
			bad = append(bad, fmt.Sprintf("personalData[%q] needs a class (%s), a data subject (%s) and a content", k, strings.Join(sortedKeys(validClass), ", "), strings.Join(sortedKeys(validSubject), ", ")))
		}
	}
	for k := range not {
		if !logged[k] {
			bad = append(bad, fmt.Sprintf("notPersonal lists %q, which no log call uses", k))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("hack/logref/personal_data.go: %s", strings.Join(bad, "; "))
	}
	return nil
}

func replaceSection(doc, section string) (string, error) {
	begin := strings.Index(doc, beginMark)
	end := strings.Index(doc, endMark)
	if begin < 0 || end < begin {
		return "", fmt.Errorf("%s needs the markers %q and %q", docPath, beginMark, endMark)
	}
	return doc[:begin+len(beginMark)] + "\n" + section + doc[end:], nil
}

// appOf maps a source directory to the process that runs it.
func appOf(dir string) string {
	switch {
	case strings.HasPrefix(dir, "pkg/bgctl"), strings.HasPrefix(dir, "cmd/bgctl"):
		return "bgctl"
	case strings.HasPrefix(dir, "pkg/clustervalidator"), strings.HasPrefix(dir, "cmd/cluster-validator"):
		return "cluster-validator"
	case strings.HasPrefix(dir, "utils/"):
		return "utility images"
	default:
		return "controller"
	}
}

// scan returns the log calls and the directories of the main packages.
func scan(root string) (map[string]*entry, map[string]bool, error) {
	entries := map[string]*entry{}
	mains := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(d.Name(), "zz_generated") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if f.Name.Name == "main" {
			mains[dir] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				addCall(entries, fset, dir, filepath.Base(rel), call)
			}
			return true
		})
		return nil
	})
	return entries, mains, err
}

// skipDir skips non-module code, generated trees and nested Go modules.
func skipDir(path, name string) bool {
	switch name {
	case ".git", "node_modules", "frontend", "e2e", "bin", "testdata", "tests", "vendor", "hack", "docs":
		return true
	}
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil
}

func addCall(entries map[string]*entry, fset *token.FileSet, dir, file string, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	m := methodRe.FindStringSubmatch(sel.Sel.Name)
	if m == nil {
		return
	}
	recv := exprString(fset, sel.X)
	if !isLogger(recv) {
		return
	}
	level := strings.ToLower(m[1])
	if v := vLevelRe.FindStringSubmatch(recv); v != nil && v[1] != "0" {
		level = "debug (V(" + v[1] + "))"
	}
	fields := map[string]bool{}
	withFields(sel.X, fields)
	var msg string
	args := call.Args
	switch m[2] {
	case "f":
		msg = literal(args[0])
	case "w":
		msg = literal(args[0])
		pairs(args[1:], fields)
	default:
		msg = literal(args[0])
		rest := args[1:]
		// logr-style Error(err, "msg", kv...).
		if msg == dynamicMsg && len(args) > 1 && literal(args[1]) != dynamicMsg && len(args)%2 == 0 {
			msg, rest = literal(args[1]), args[2:]
			fields["error"] = true
		}
		if !zapFields(rest, fields) && len(rest)%2 == 0 && keysAreLiterals(rest) {
			pairs(rest, fields)
		}
	}
	app := appOf(dir)
	key := app + "\x00" + dir + "\x00" + level + "\x00" + msg
	e := entries[key]
	if e == nil {
		e = &entry{app: app, component: dir, level: level, message: msg, fields: map[string]bool{}, files: map[string]bool{}}
		entries[key] = e
	}
	for f := range fields {
		e.fields[f] = true
	}
	e.files[file] = true
}

func isLogger(recv string) bool {
	switch recv {
	case "fmt", "zap", "errors", "http", "context":
		return false
	case "lg", "rl":
		return true
	}
	return strings.HasPrefix(recv, "zap.S()") || strings.HasPrefix(recv, "zap.L()") ||
		strings.Contains(strings.ToLower(recv), "log")
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, e)
	return b.String()
}

// literal returns the constant text of a string literal or a concatenation
// containing literals; other parts become "…".
func literal(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			if s, err := strconv.Unquote(x.Value); err == nil {
				return s
			}
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			l, r := literal(x.X), literal(x.Y)
			if l == dynamicMsg && r == dynamicMsg {
				return dynamicMsg
			}
			return strings.ReplaceAll(l, dynamicMsg, "…") + strings.ReplaceAll(r, dynamicMsg, "…")
		}
	case *ast.ParenExpr:
		return literal(x.X)
	}
	return dynamicMsg
}

func keysAreLiterals(args []ast.Expr) bool {
	for i := 0; i < len(args); i += 2 {
		if literal(args[i]) == dynamicMsg {
			return false
		}
	}
	return len(args) > 0
}

// pairs adds the literal keys of key-value arguments.
func pairs(args []ast.Expr, fields map[string]bool) {
	for i := 0; i < len(args); i += 2 {
		if zapFields(args[i:i+1], fields) {
			i-- // a zap.Field in a sugared call takes one argument
			continue
		}
		if k := literal(args[i]); k != dynamicMsg {
			fields[k] = true
		}
	}
}

// zapFields adds the keys of zap.X("key", ...) / zap.Error(err) arguments and
// reports whether all arguments were zap fields.
func zapFields(args []ast.Expr, fields map[string]bool) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		call, ok := a.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "zap" {
			return false
		}
		switch {
		case sel.Sel.Name == "Error":
			fields["error"] = true
		case len(call.Args) > 0 && literal(call.Args[0]) != dynamicMsg:
			fields[literal(call.Args[0])] = true
		}
	}
	return true
}

// withFields adds fields bound on the receiver chain with With/WithValues.
func withFields(e ast.Expr, fields map[string]bool) {
	for {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		if sel.Sel.Name == "With" || sel.Sel.Name == "WithValues" {
			if !zapFields(call.Args, fields) {
				pairs(call.Args, fields)
			}
		}
		e = sel.X
	}
}

func render(entries map[string]*entry) string {
	list := make([]*entry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.app != b.app {
			return a.app < b.app
		}
		if a.component != b.component {
			return a.component < b.component
		}
		if levelRank(a.level) != levelRank(b.level) {
			return levelRank(a.level) < levelRank(b.level)
		}
		return a.message < b.message
	})

	var b strings.Builder
	b.WriteString("\n## Levels in use\n\nNumber of distinct messages per process and level.\n\n")
	counts := map[string]map[string]int{}
	var apps []string
	for _, e := range list {
		if counts[e.app] == nil {
			counts[e.app] = map[string]int{}
			apps = append(apps, e.app)
		}
		counts[e.app][e.level]++
	}
	b.WriteString("| Process |")
	for _, l := range levels {
		b.WriteString(" " + l + " |")
	}
	b.WriteString(" V-levels |\n|---|")
	b.WriteString(strings.Repeat("---|", len(levels)+1) + "\n")
	for _, a := range apps {
		b.WriteString("| " + a + " |")
		v := 0
		for l, n := range counts[a] {
			if strings.HasPrefix(l, "debug (V(") {
				v += n
			}
		}
		for _, l := range levels {
			fmt.Fprintf(&b, " %d |", counts[a][l])
		}
		fmt.Fprintf(&b, " %d |\n", v)
	}

	renderPersonalData(&b, list)

	b.WriteString("\n## Message catalogue\n\n" +
		"Fields marked † can hold personal data; [Personal-data fields](#personal-data-fields)\n" +
		"gives their class and data subject. `(dynamic)` is a message built at run\n" +
		"time, typically from an error value; `…` marks the variable part of a\n" +
		"concatenated message.\n")
	app, comp := "", ""
	for _, e := range list {
		if e.app != app {
			app, comp = e.app, ""
			fmt.Fprintf(&b, "\n### %s\n", app)
		}
		if e.component != comp {
			comp = e.component
			fmt.Fprintf(&b, "\n#### `%s`\n\n| Level | Message | Fields | File |\n|---|---|---|---|\n", comp)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", e.level, cell(e.message), fieldList(e.fields), strings.Join(sortedKeys(e.files), ", "))
	}
	b.WriteString("\n")
	return b.String()
}

// renderPersonalData writes one row per classified field, with the levels of
// the log calls that pass it, least verbose first.
func renderPersonalData(b *strings.Builder, list []*entry) {
	b.WriteString("\n## Personal-data fields\n\n" +
		"Class and data subject of each catalogued field that can hold personal\n" +
		"data, as defined in [Personal data](#personal-data). *Levels* are the\n" +
		"levels of the log calls that pass the field, least verbose first.\n\n" +
		"| Field | Class | Data subject | Levels | Content |\n|---|---|---|---|---|\n")
	levelsOf := map[string]map[string]bool{}
	for _, e := range list {
		for f := range e.fields {
			if levelsOf[f] == nil {
				levelsOf[f] = map[string]bool{}
			}
			levelsOf[f][strings.Fields(e.level)[0]] = true
		}
	}
	keys := make([]string, 0, len(personalData))
	for k := range personalData {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToLower(keys[i]) < strings.ToLower(keys[j]) })
	for _, k := range keys {
		var ls []string
		for i := len(levels) - 1; i >= 0; i-- {
			if levelsOf[k][levels[i]] {
				ls = append(ls, levels[i])
			}
		}
		p := personalData[k]
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", cell(k), p.class, p.subject, strings.Join(ls, ", "), p.content)
	}
}

var (
	validClass   = map[string]bool{tenantPII: true, staffID: true, customerData: true, content: true}
	validSubject = map[string]bool{operator: true, tenantUser: true, endCustomer: true}
)

func levelRank(l string) int {
	for i, x := range levels {
		if l == x {
			return i
		}
	}
	return -1 // V-levels sort before debug
}

func cell(s string) string {
	s = strings.NewReplacer("\n", " ", "\t", " ").Replace(s)
	if s == dynamicMsg {
		return s
	}
	if strings.Contains(s, "`") {
		return strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "*", `\*`, "_", `\_`).Replace(s)
	}
	return "`" + strings.ReplaceAll(s, "|", `\|`) + "`"
}

func fieldList(fields map[string]bool) string {
	keys := sortedKeys(fields)
	for i, k := range keys {
		keys[i] = cell(k)
		if _, ok := personalData[k]; ok {
			keys[i] += "†"
		}
	}
	return strings.Join(keys, ", ")
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

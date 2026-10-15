// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxFileBytes = 64 << 20

type executor struct {
	// root is where the host filesystem is visible: "/host" for the
	// mount-only shape, "/proc/1/root" for the host-namespace shape.
	root string
	// hostExec allows host commands through nsenter (host-namespace shape only).
	hostExec bool
	// work is a writable scratch and evidence directory inside the container.
	work     string
	run      func(ctx context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, error)
	now      func() time.Time
	deadline time.Time
	client   *http.Client
	// poll is the wait between health checks.
	poll time.Duration
}

func sum(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (ex *executor) host(p string) string { return filepath.Join(ex.root, p) }

// step returns a context for one bounded step, or an error when the step's
// budget no longer fits before the deadline. A mutation is never started
// without its full budget.
func (ex *executor) step(budget time.Duration) (context.Context, context.CancelFunc, error) {
	if err := ex.fits(budget); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), ex.now().Add(budget))
	return ctx, cancel, nil
}

// fits fails when a step of the given budget would end after the deadline.
func (ex *executor) fits(budget time.Duration) error {
	if ex.now().Add(budget).After(ex.deadline) {
		return fmt.Errorf("remaining session time is shorter than the %s step budget; stopping before the change", budget)
	}
	return nil
}

// checkRegular refuses symlinks in every path component and non-regular targets.
func (ex *executor) checkRegular(p string) (os.FileInfo, error) {
	current := ex.root
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s contains a symlink; refusing", p)
		}
	}
	info, err := os.Lstat(ex.host(p))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, maxFileBytes)
	}
	return info, nil
}

func (ex *executor) read(p string) ([]byte, os.FileInfo, error) {
	if _, err := ex.checkRegular(p); err != nil {
		return nil, nil, err
	}
	// O_NOFOLLOW closes the window between the lstat walk and the open for
	// the final component; the directories were checked component by component.
	file, err := os.OpenFile(ex.host(p), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return nil, nil, fmt.Errorf("%s is not a regular file of at most %d bytes", p, maxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

// fileMode keeps permission and setuid/setgid/sticky bits.
func fileMode(info os.FileInfo) os.FileMode {
	return info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// writeSynced writes data to a hidden temporary file next to target, syncs
// it, renames it over target and syncs the directory.
func writeSynced(target string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".breakglass-hotfix.tmp")
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Chmod(mode), file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func fileSHA256(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// writeAtomic replaces p with data, keeping owner and mode. The temporary
// file is hidden (leading dot), so kubelet never reads it as a static Pod.
func (ex *executor) writeAtomic(p string, data []byte, info os.FileInfo) error {
	target := ex.host(p)
	tmp := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".breakglass-hotfix.tmp")
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	var chownErr error
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		chownErr = file.Chown(int(stat.Uid), int(stat.Gid))
	}
	_, writeErr := file.Write(data)
	// Chmod after Chown: chown clears setuid/setgid bits.
	if err := errors.Join(chownErr, writeErr, file.Chmod(fileMode(info)), file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

type backupMeta struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"beforeSHA256"`
	AfterSHA256  string `json:"afterSHA256"`
	Mode         uint32 `json:"mode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
	ModTime      string `json:"modTime"`
}

func (ex *executor) backupPath(req *request, p string) string {
	return path.Join(stateDir, req.HotfixID, sum([]byte(p))[:32]+".bak")
}

// backup keeps the first pre-image of p for this hotfix; a later attempt
// never overwrites it.
func (ex *executor) backup(req *request, p string, data []byte, info os.FileInfo) error {
	dir := ex.host(path.Join(stateDir, req.HotfixID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	target := ex.host(ex.backupPath(req, p))
	if existing, err := os.ReadFile(target); err == nil {
		if sum(existing) != req.Expected.BeforeSHA256 {
			return errors.New("an existing backup does not match the planned pre-image")
		}
		return nil
	}
	meta := backupMeta{Path: p, BeforeSHA256: sum(data), AfterSHA256: req.Expected.AfterSHA256, Mode: uint32(fileMode(info)), ModTime: info.ModTime().UTC().Format(time.RFC3339)}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		meta.UID, meta.GID = stat.Uid, stat.Gid
	}
	encoded, _ := json.Marshal(meta)
	if err := writeSynced(target+".json", encoded, 0o600); err != nil {
		return err
	}
	return writeSynced(target, data, 0o600)
}

func (ex *executor) httpClient() (*http.Client, error) {
	if ex.client != nil {
		return ex.client, nil
	}
	bundle := ex.host("/etc/ssl/certs/ca-certificates.crt")
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(bundle)
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("node CA bundle %s is missing or empty; the controller mounts it for URL sources", bundle)
	}
	ex.client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	return ex.client, nil
}

// fetchToFile streams an HTTPS source into dest and keeps it only if its
// SHA-256 matches; the node's CA bundle verifies TLS.
func (ex *executor) fetchToFile(source, want, dest string, limit int64) error {
	ctx, cancel, err := ex.step(5 * time.Minute)
	if err != nil {
		return err
	}
	defer cancel()
	client, err := ex.httpClient()
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", source, response.StatusCode)
	}
	tmp := dest + ".download"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, limit+1))
	if copyErr == nil && written > limit {
		copyErr = fmt.Errorf("download %s is larger than %d bytes", source, limit)
	}
	if err := errors.Join(copyErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != want {
		return fmt.Errorf("download %s: sha256 %s, want %s", source, got, want)
	}
	return os.Rename(tmp, dest)
}

// fetch downloads a replace source of at most maxFileBytes into memory.
func (ex *executor) fetch(source, want string) ([]byte, error) {
	dest := filepath.Join(ex.work, "replace.download")
	if err := ex.fetchToFile(source, want, dest, maxFileBytes); err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(dest) }()
	info, err := os.Stat(dest)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("download %s is larger than %d bytes", source, maxFileBytes)
	}
	return os.ReadFile(dest)
}

// newContent computes the planned file content.
func (ex *executor) newContent(f *filePayload, old []byte) ([]byte, error) {
	switch f.Mode {
	case "replace":
		if f.Content != "" {
			return []byte(f.Content), nil
		}
		return ex.fetch(f.URL, f.AfterSHA256)
	case "sed":
		ctx, cancel, err := ex.step(30 * time.Second)
		if err != nil {
			return nil, err
		}
		defer cancel()
		args := []string{"--sandbox", "-E"}
		for _, expression := range f.SedExpressions {
			args = append(args, "-e", expression)
		}
		// GNU sed in the executor image, never the host's, and only on stdin.
		return runCommand(ctx, nil, old, "sed", args...)
	case "diff":
		return applyUnifiedDiff(old, f.Diff)
	}
	return nil, fmt.Errorf("unsupported file mode %q", f.Mode)
}

var hunkHeader = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)

// applyUnifiedDiff applies a single-file unified diff strictly: no fuzz and
// no offset. Every context and removed line must match at its stated line.
func applyUnifiedDiff(old []byte, diff string) ([]byte, error) {
	if len(old) > 0 && old[len(old)-1] != '\n' {
		return nil, errors.New("diff mode needs a file that ends with a newline")
	}
	original := strings.SplitAfter(string(old), "\n")
	if len(original) > 0 && original[len(original)-1] == "" {
		original = original[:len(original)-1]
	}
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) < 3 || !strings.HasPrefix(lines[0], "--- ") || !strings.HasPrefix(lines[1], "+++ ") {
		return nil, errors.New("diff must start with one ---/+++ header pair")
	}
	var out strings.Builder
	position := 0 // next unread original line (0-based)
	for i := 2; i < len(lines); {
		match := hunkHeader.FindStringSubmatch(lines[i])
		if match == nil {
			return nil, fmt.Errorf("expected a hunk header, got %q", lines[i])
		}
		start, _ := strconv.Atoi(match[1])
		oldCount, newCount := 1, 1
		if match[2] != "" {
			oldCount, _ = strconv.Atoi(match[2])
		}
		if match[4] != "" {
			newCount, _ = strconv.Atoi(match[4])
		}
		begin := start - 1
		if oldCount == 0 {
			begin = start
		}
		if begin < position || begin > len(original) {
			return nil, fmt.Errorf("hunk %q is out of order or beyond the file", lines[i])
		}
		for ; position < begin; position++ {
			out.WriteString(original[position])
		}
		seenOld, seenNew := 0, 0
		for i++; i < len(lines) && !strings.HasPrefix(lines[i], "@@"); i++ {
			line := lines[i]
			if line == "" {
				return nil, errors.New("diff has an empty line; context lines start with a space")
			}
			body := line[1:] + "\n"
			switch line[0] {
			case ' ', '-':
				if position >= len(original) || original[position] != body {
					return nil, fmt.Errorf("diff does not apply at line %d", position+1)
				}
				position++
				seenOld++
				if line[0] == ' ' {
					out.WriteString(body)
					seenNew++
				}
			case '+':
				out.WriteString(body)
				seenNew++
			default:
				return nil, fmt.Errorf("unsupported diff line %q", line)
			}
		}
		if seenOld != oldCount || seenNew != newCount {
			return nil, errors.New("hunk line counts do not match its header")
		}
	}
	for ; position < len(original); position++ {
		out.WriteString(original[position])
	}
	return []byte(out.String()), nil
}

// reviewDiff renders a truncated unified diff for the approver.
func (ex *executor) reviewDiff(p string, old, updated []byte) string {
	dir, err := os.MkdirTemp(ex.work, "diff")
	if err != nil {
		return ""
	}
	defer func() { _ = os.RemoveAll(dir) }()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if os.WriteFile(a, old, 0o600) != nil || os.WriteFile(b, updated, 0o600) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := runCommand(ctx, nil, nil, "diff", "-u", "-L", "a"+p, "-L", "b"+p, a, b)
	// diff exits 1 when the files differ; anything else is trouble.
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() != 1) {
		return "[diff unavailable: " + err.Error() + "]"
	}
	if len(out) > maxDiffBytes {
		out = append(out[:maxDiffBytes], []byte("\n[truncated]\n")...)
	}
	return string(out)
}

// file plans, applies or rolls back a node-file payload.
func (ex *executor) file(req *request) (*result, error) {
	f := req.Payload.File
	old, info, err := ex.read(f.Path)
	if err != nil {
		return nil, err
	}
	before := sum(old)
	switch req.Stage {
	case stagePlan:
		if len(f.BeforeSHA256) != 0 && !slices.Contains(f.BeforeSHA256, before) {
			if f.AfterSHA256 == before {
				return &result{Result: "planned", Action: "skip", BeforeSHA256: before, AfterSHA256: before}, nil
			}
			return nil, fmt.Errorf("%s has sha256 %s, which is not an accepted beforeSHA256", f.Path, before)
		}
		updated, err := ex.newContent(f, old)
		if err != nil {
			return nil, err
		}
		after := sum(updated)
		if f.AfterSHA256 != "" && after != f.AfterSHA256 {
			return nil, errors.New("new content does not match afterSHA256")
		}
		action := "apply"
		if after == before {
			action = "skip"
		}
		return &result{Result: "planned", Action: action, BeforeSHA256: before, AfterSHA256: after, Diff: ex.reviewDiff(f.Path, old, updated)}, nil
	case stageApply:
		if before == req.Expected.AfterSHA256 {
			return &result{Result: "skipped", BeforeSHA256: before, AfterSHA256: before, Message: "already at the planned content"}, nil
		}
		if before != req.Expected.BeforeSHA256 {
			return nil, fmt.Errorf("%s changed since the plan (sha256 %s)", f.Path, before)
		}
		updated, err := ex.newContent(f, old)
		if err != nil {
			return nil, err
		}
		if sum(updated) != req.Expected.AfterSHA256 {
			return nil, errors.New("computed content differs from the planned afterSHA256")
		}
		if err := ex.replaceFile(req, f.Path, old, updated, info); err != nil {
			return nil, err
		}
		if err := ex.restart(req.Payload.Restart); err != nil {
			return nil, err
		}
		return &result{Result: "applied", BeforeSHA256: before, AfterSHA256: req.Expected.AfterSHA256}, nil
	case stageRollback:
		return ex.restoreFile(req, f.Path, before, info, req.Payload.Restart)
	}
	return nil, fmt.Errorf("unsupported stage %q", req.Stage)
}

// replaceFile backs up and atomically replaces a file, then verifies it.
func (ex *executor) replaceFile(req *request, p string, old, updated []byte, info os.FileInfo) error {
	if err := ex.fits(30 * time.Second); err != nil {
		return err
	}
	if err := ex.backup(req, p, old, info); err != nil {
		return fmt.Errorf("backup %s: %w", p, err)
	}
	if err := ex.writeAtomic(p, updated, info); err != nil {
		return fmt.Errorf("replace %s: %w", p, err)
	}
	written, _, err := ex.read(p)
	if err != nil {
		return err
	}
	if sum(written) != sum(updated) {
		return fmt.Errorf("%s does not have the planned content after the write", p)
	}
	return nil
}

// restoreFile reverts a file only from the hotfix backup and only while the
// file still has the hotfix content.
func (ex *executor) restoreFile(req *request, p, current string, info os.FileInfo, restart []string) (*result, error) {
	if current == req.Expected.BeforeSHA256 {
		return &result{Result: "skipped", BeforeSHA256: current, AfterSHA256: current, Message: "already at the pre-hotfix content"}, nil
	}
	if current != req.Expected.AfterSHA256 {
		return nil, fmt.Errorf("%s changed after the hotfix (sha256 %s); not restoring", p, current)
	}
	saved, err := os.ReadFile(ex.host(ex.backupPath(req, p)))
	if err != nil {
		return nil, fmt.Errorf("read backup of %s: %w", p, err)
	}
	if sum(saved) != req.Expected.BeforeSHA256 {
		return nil, fmt.Errorf("backup of %s does not match the pre-image", p)
	}
	if err := ex.fits(30 * time.Second); err != nil {
		return nil, err
	}
	if err := ex.writeAtomic(p, saved, info); err != nil {
		return nil, err
	}
	if err := ex.restart(restart); err != nil {
		return nil, err
	}
	return &result{Result: "rolledBack", BeforeSHA256: current, AfterSHA256: req.Expected.BeforeSHA256}, nil
}

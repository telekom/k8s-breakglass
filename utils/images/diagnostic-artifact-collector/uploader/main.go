// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Command artifact-upload performs the one network operation allowed by the
// collector image: a bounded PUT to the exact controller-issued URL.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	archivePath      = "/output/artifact.tar.gz"
	readyMarker      = "ready\n"
	maxArchiveBytes  = int64(536870912)
	maxTokenBytes    = 4096
	uploadTimeout    = 10 * time.Minute
	maxAttempts      = 3
	maxManifestBytes = int64(65536)
	retryDelay       = 250 * time.Millisecond
	allowHTTPEnvName = "BREAKGLASS_ARTIFACT_ALLOW_INSECURE_HTTP"
	pinnedCABundle   = "/etc/ssl/certs/ca-certificates.crt"
)

var (
	errRedirect         = errors.New("upload redirect refused")
	artifactPath        = archivePath
	readyPath           = "/output/artifact.ready"
	newUploadHTTPClient = defaultUploadHTTPClient
)

// uploadResponseError keeps the status classification structured. The retry
// loop must never infer safety from a human-readable error string: permanent
// authorization, TLS, and contract failures are intentionally not retryable.
type uploadResponseError struct {
	statusCode int
	temporary  bool
}

func (err *uploadResponseError) Error() string {
	return fmt.Sprintf("upload response: %d", err.statusCode)
}

type artifactManifest struct {
	SchemaVersion string  `json:"schema_version"`
	Recipe        string  `json:"recipe"`
	RecipeVersion int     `json:"recipe_version"`
	Node          *string `json:"node"`
	ArchiveFormat string  `json:"archive_format"`
	Inputs        struct {
		MaxArchiveBytes int64   `json:"maxArchiveBytes"`
		MaxAgeMinutes   *int64  `json:"maxAgeMinutes"`
		Node            *string `json:"node"`
		DetailLevel     *string `json:"detailLevel"`
	} `json:"inputs"`
	PayloadSHA256 string `json:"payload_sha256"`
	FileCount     int64  `json:"file_count"`
	Bytes         int64  `json:"bytes"`
	ExitCode      int    `json:"exit_code"`
	ExitSemantics string `json:"exit_semantics"`
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--archive" || os.Args[2] != archivePath {
		fmt.Fprintln(os.Stderr, "artifact upload accepts only --archive /output/artifact.tar.gz")
		os.Exit(2)
	}
	if err := upload(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "artifact upload failed: %s\n", safeError(err))
		os.Exit(1)
	}
}

func upload(ctx context.Context) error {
	ready, err := os.Lstat(readyPath)
	if err != nil {
		return errors.New("artifact.ready is required before upload")
	}
	if !isPrivateRegular(ready) {
		return errors.New("artifact.ready is not a regular private file")
	}
	readyFile, err := openPrivateNoFollow(readyPath, ready)
	if err != nil {
		return fmt.Errorf("open artifact.ready without following links: %w", err)
	}
	marker, readErr := io.ReadAll(io.LimitReader(readyFile, int64(len(readyMarker)+1)))
	closeErr := readyFile.Close()
	if readErr != nil {
		return errors.New("read artifact.ready marker")
	}
	if closeErr != nil {
		return errors.New("close artifact.ready marker")
	}
	if string(marker) != readyMarker {
		return errors.New("artifact.ready marker is invalid")
	}
	configuredMaxBytes, err := configuredMaxArchiveBytes()
	if err != nil {
		return err
	}
	recipeMaxBytes, err := recipeArchiveLimit(filepath.Join(filepath.Dir(artifactPath), "artifact.manifest.json"))
	if err != nil {
		return err
	}
	if configuredMaxBytes > recipeMaxBytes {
		configuredMaxBytes = recipeMaxBytes
	}
	archive, err := os.Lstat(artifactPath)
	if err != nil {
		return fmt.Errorf("inspect archive: %w", err)
	}
	if !isPrivateRegular(archive) {
		return errors.New("archive is not a regular private file")
	}
	if archive.Size() < 1 || archive.Size() > configuredMaxBytes {
		return fmt.Errorf("archive size %d is outside the bounded upload limit", archive.Size())
	}
	file, err := openArchiveNoFollow(archive)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	endpoint, err := uploadURL()
	if err != nil {
		return err
	}
	token, err := uploadToken()
	if err != nil {
		return err
	}
	timeout, err := configuredUploadTimeout()
	if err != nil {
		return err
	}
	client := newUploadHTTPClient()
	if client == nil {
		return errors.New("upload HTTP client is unavailable")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errRedirect
	}
	if client.Timeout == 0 || client.Timeout > timeout {
		client.Timeout = timeout
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = putOnce(ctx, client, endpoint, token, file, archive.Size())
		if err == nil {
			return nil
		}
		if !retryable(err) || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	return err
}

func recipeArchiveLimit(path string) (int64, error) {
	manifest, err := os.Lstat(path)
	if err != nil {
		return 0, errors.New("artifact manifest is required before upload")
	}
	if !isPrivateRegular(manifest) || manifest.Size() < 1 || manifest.Size() > maxManifestBytes {
		return 0, errors.New("artifact manifest is not a bounded private file")
	}
	file, err := openPrivateNoFollow(path, manifest)
	if err != nil {
		return 0, fmt.Errorf("open artifact manifest without following links: %w", err)
	}
	defer func() { _ = file.Close() }()
	var contract artifactManifest
	decoder := json.NewDecoder(io.LimitReader(file, maxManifestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return 0, errors.New("artifact manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, errors.New("artifact manifest has trailing content")
	}
	return validateManifestContract(contract)
}

func validateManifestContract(contract artifactManifest) (int64, error) {
	if contract.SchemaVersion != "diagnostic-artifact/v1" || contract.RecipeVersion != 1 ||
		contract.ArchiveFormat != "tar.gz" || contract.ExitCode != 0 ||
		contract.ExitSemantics != "0=complete; non-zero=not published" ||
		len(contract.PayloadSHA256) != sha256.Size*2 || contract.FileCount < 0 || contract.Bytes < 0 {
		return 0, errors.New("artifact manifest identity is invalid")
	}

	var immutableLimit int64
	switch contract.Recipe {
	case "system-summary.v1":
		immutableLimit = 16777216
		if contract.Node != nil || contract.Inputs.Node != nil || contract.Inputs.MaxAgeMinutes != nil ||
			contract.Inputs.DetailLevel == nil ||
			(*contract.Inputs.DetailLevel != "basic" && *contract.Inputs.DetailLevel != "extended") {
			return 0, errors.New("artifact manifest does not match the system summary recipe")
		}
	case "crashdump-collection.v1":
		immutableLimit = maxArchiveBytes
		if contract.Node == nil || *contract.Node == "" || contract.Inputs.Node == nil ||
			*contract.Inputs.Node != *contract.Node || contract.Inputs.MaxAgeMinutes == nil ||
			*contract.Inputs.MaxAgeMinutes < 1 || *contract.Inputs.MaxAgeMinutes > 10080 ||
			contract.Inputs.DetailLevel != nil {
			return 0, errors.New("artifact manifest does not match the crashdump recipe")
		}
	default:
		return 0, errors.New("artifact manifest recipe is not allowlisted")
	}
	if contract.Inputs.MaxArchiveBytes < 1 || contract.Inputs.MaxArchiveBytes > immutableLimit {
		return 0, errors.New("artifact manifest archive limit exceeds the immutable recipe ceiling")
	}
	return contract.Inputs.MaxArchiveBytes, nil
}

func configuredMaxArchiveBytes() (int64, error) {
	raw, present := os.LookupEnv("BREAKGLASS_ARTIFACT_MAX_BYTES")
	if !present {
		return maxArchiveBytes, nil
	}
	if raw == "" {
		return 0, errors.New("BREAKGLASS_ARTIFACT_MAX_BYTES must be a positive decimal integer")
	}
	if len(raw) > len(strconv.FormatInt(maxArchiveBytes, 10)) {
		return 0, fmt.Errorf("BREAKGLASS_ARTIFACT_MAX_BYTES must be between 1 and %d", maxArchiveBytes)
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, errors.New("BREAKGLASS_ARTIFACT_MAX_BYTES must be a positive decimal integer")
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || value > maxArchiveBytes {
		return 0, fmt.Errorf("BREAKGLASS_ARTIFACT_MAX_BYTES must be between 1 and %d", maxArchiveBytes)
	}
	return value, nil
}

func configuredUploadTimeout() (time.Duration, error) {
	raw, present := os.LookupEnv("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT")
	if !present {
		return uploadTimeout, nil
	}
	if raw == "" {
		return 0, errors.New("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT must be a positive duration")
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 || duration > time.Hour {
		return 0, errors.New("BREAKGLASS_ARTIFACT_UPLOAD_TIMEOUT must be greater than zero and at most 1h")
	}
	return duration, nil
}

func isPrivateRegular(info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	// syscall.Stat_t stores UID/GID as uint32 while os.Geteuid/Getegid return
	// int. Convert both to int64, which represents every value of either type,
	// after rejecting impossible negative effective identities.
	euid, egid := os.Geteuid(), os.Getegid()
	if euid < 0 || egid < 0 {
		return false
	}
	uid, gid := int64(stat.Uid), int64(stat.Gid)
	// The uploader's runtime identity is the trust boundary. In production it
	// is UID/GID 65532; using the effective identity here also keeps the same
	// contract testable by an unprivileged local test process.
	return (info.Mode().Perm() == 0600 && uid == int64(euid)) ||
		(info.Mode().Perm() == 0640 && uid == 0 && gid == int64(egid))
}

// openPrivateNoFollow opens the exact inode observed by the initial Lstat.
// The output directory is shared with the uploader, so opening by path without
// O_NOFOLLOW would permit a symlink swap to exfiltrate a file.
func openPrivateNoFollow(path string, expected os.FileInfo) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		return nil, errors.New("open private file returned an invalid descriptor")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open private file returned no file")
	}
	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened file: %w", statErr)
	}
	if !isPrivateRegular(info) || !os.SameFile(expected, info) || info.Size() != expected.Size() {
		_ = file.Close()
		return nil, errors.New("file changed while it was opened")
	}
	return file, nil
}

func openArchiveNoFollow(expected os.FileInfo) (*os.File, error) {
	file, err := openPrivateNoFollow(artifactPath, expected)
	if err != nil {
		return nil, fmt.Errorf("open archive without following links: %w", err)
	}
	return file, nil
}

func defaultUploadHTTPClient() *http.Client {
	client, err := uploadHTTPClientForCABundle(pinnedCABundle)
	if err != nil {
		return nil
	}
	return client
}

// uploadHTTPClientForCABundle is private so production always uses the
// image-pinned CA bundle. Its path parameter exists only to make unit tests
// independent of the host filesystem; no environment variable can select a
// trust store.
func uploadHTTPClientForCABundle(caBundlePath string) (*http.Client, error) {
	caBundle, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("read pinned CA bundle: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caBundle) {
		return nil, errors.New("pinned CA bundle contains no certificates")
	}
	return &http.Client{
		Timeout: uploadTimeout,
		Transport: &http.Transport{
			// A presigned URL is an exact target. Ambient proxy variables and
			// ambient CA environment variables are deliberately ignored so they
			// cannot redirect or re-trust the bearer token.
			Proxy:           noProxy,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs},
		},
	}, nil
}

func noProxy(*http.Request) (*url.URL, error) {
	return nil, nil
}

func uploadURL() (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_URL"))
	if raw == "" {
		return nil, errors.New("upload URL is missing")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path == "" ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" ||
		parsed.ForceQuery ||
		strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("upload URL is invalid")
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || os.Getenv(allowHTTPEnvName) != "true" {
			return nil, errors.New("upload URL must use HTTPS")
		}
	}
	return parsed, nil
}

func uploadToken() (string, error) {
	token := os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN")
	if token == "" || len(token) > maxTokenBytes || strings.TrimSpace(token) != token ||
		strings.ContainsAny(token, "\r\n\t\x00") {
		return "", errors.New("upload token is invalid")
	}
	return token, nil
}

func putOnce(ctx context.Context, client *http.Client, endpoint *url.URL, token string, file *os.File, size int64) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind archive: %w", err)
	}
	before, err := file.Stat()
	if err != nil || !isPrivateRegular(before) || before.Size() != size {
		return errors.New("archive changed before upload")
	}
	uploadDigest := sha256.New()
	reader := &countingReader{reader: io.TeeReader(io.LimitReader(file, size), uploadDigest)}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), reader)
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	request.ContentLength = size
	request.Header.Set("Content-Type", "application/gzip")
	request.Header.Set("Content-Length", strconv.FormatInt(size, 10))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return errRedirect
		}
		return fmt.Errorf("send upload: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return errRedirect
	}
	if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode >= 500 {
		return &uploadResponseError{statusCode: response.StatusCode, temporary: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &uploadResponseError{statusCode: response.StatusCode}
	}
	after, statErr := file.Stat()
	if statErr != nil || !isPrivateRegular(after) || after.Size() != size || reader.n != size ||
		!os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("archive changed or was truncated during upload")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("archive could not be verified after upload")
	}
	verifiedDigest := sha256.New()
	verifiedBytes, err := io.CopyN(verifiedDigest, file, size)
	if err != nil || verifiedBytes != size || !bytes.Equal(uploadDigest.Sum(nil), verifiedDigest.Sum(nil)) {
		return errors.New("archive content changed during upload")
	}
	var extra [1]byte
	if n, readErr := file.Read(extra[:]); n != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		return errors.New("archive size changed during upload")
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	n      int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.n += int64(n)
	return n, err
}

func retryable(err error) bool {
	var responseError *uploadResponseError
	if errors.As(err, &responseError) {
		return responseError.temporary
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		// context.DeadlineExceeded implements net.Error itself, but is a
		// caller-owned deadline and must not be retried. The http.Client timeout
		// is wrapped in *url.Error and remains eligible for a bounded retry.
		var httpError *url.Error
		if errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &httpError) {
			return false
		}
		return true
	}
	// Caller-owned cancellation/deadline decisions are terminal, including
	// wrapped forms which are not transport timeouts.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return false
}

func safeError(err error) string {
	message := err.Error()
	if value := strings.TrimSpace(os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_URL")); value != "" {
		message = strings.ReplaceAll(message, value, "[URL]")
	}
	if value := os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN"); value != "" {
		message = strings.ReplaceAll(message, value, "[TOKEN]")
	}
	message = strings.ReplaceAll(message, artifactPath, "[ARCHIVE]")
	return message
}

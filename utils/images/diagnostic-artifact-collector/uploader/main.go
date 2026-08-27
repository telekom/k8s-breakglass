// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Command artifact-upload performs the only network requests allowed by the
// collector image: bounded PUT attempts to the exact controller-issued URL.
package main

import (
	"bytes"
	"compress/gzip"
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
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
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
	pinnedCABundle   = "/etc/ssl/certs/ca-certificates.crt"
	tarBlockSize     = int64(512)
	maxTarMembers    = int64(8192)
	maxTarMetadata   = int64(1 << 20)
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
	manifestContract, manifestBytes, recipeMaxBytes, err := readArtifactManifest(filepath.Join(filepath.Dir(artifactPath), "artifact.manifest.json"))
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
	uploadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := verifyArchiveContract(uploadCtx, file, archive.Size(), manifestContract, manifestBytes); err != nil {
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
		err = putOnce(uploadCtx, client, endpoint, token, file, archive.Size(), manifestContract, manifestBytes)
		if err == nil {
			return nil
		}
		if !retryable(err) || attempt == maxAttempts {
			return err
		}
		select {
		case <-uploadCtx.Done():
			return uploadCtx.Err()
		case <-time.After(retryDelay):
		}
	}
	return err
}

func recipeArchiveLimit(path string) (int64, error) {
	contract, _, limit, err := readArtifactManifest(path)
	if err != nil {
		return 0, err
	}
	if _, err := validateManifestContract(contract); err != nil {
		return 0, err
	}
	return limit, nil
}

func readArtifactManifest(path string) (artifactManifest, []byte, int64, error) {
	var contract artifactManifest
	manifest, err := os.Lstat(path)
	if err != nil {
		return contract, nil, 0, errors.New("artifact manifest is required before upload")
	}
	if !isPrivateRegular(manifest) || manifest.Size() < 1 || manifest.Size() > maxManifestBytes {
		return contract, nil, 0, errors.New("artifact manifest is not a bounded private file")
	}
	file, err := openPrivateNoFollow(path, manifest)
	if err != nil {
		return contract, nil, 0, fmt.Errorf("open artifact manifest without following links: %w", err)
	}
	manifestBytes, readErr := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(manifestBytes)) != manifest.Size() {
		return contract, nil, 0, errors.New("read artifact manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return contract, nil, 0, errors.New("artifact manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return contract, nil, 0, errors.New("artifact manifest has trailing content")
	}
	limit, err := validateManifestContract(contract)
	if err != nil {
		return contract, nil, 0, err
	}
	return contract, manifestBytes, limit, nil
}

func validateManifestContract(contract artifactManifest) (int64, error) {
	if contract.SchemaVersion != "diagnostic-artifact/v1" || contract.RecipeVersion != 1 ||
		contract.ArchiveFormat != "tar.gz" || contract.ExitCode != 0 ||
		contract.ExitSemantics != "0=complete; non-zero=not published" ||
		len(contract.PayloadSHA256) != sha256.Size*2 || contract.FileCount < 0 || contract.Bytes < 0 {
		return 0, errors.New("artifact manifest identity is invalid")
	}
	if _, err := hex.DecodeString(contract.PayloadSHA256); err != nil {
		return 0, errors.New("artifact manifest payload checksum is invalid")
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

// verifyArchiveContract consumes the archive as a bounded gzip/tar stream. It
// hashes the exact raw tar records used by the collector (excluding only the
// embedded manifest record), so a semantically equivalent re-encoding cannot
// be substituted for the bytes the collector committed to the sidecar.
func verifyArchiveContract(ctx context.Context, file *os.File, size int64, contract artifactManifest, sidecar []byte) error {
	if size < 1 || size > maxArchiveBytes {
		return errors.New("archive size is outside the bounded contract")
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind archive for contract verification: %w", err)
	}
	compressed := &contextLimitedReader{ctx: ctx, reader: file, remaining: size}
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return errors.New("archive is not a valid gzip stream")
	}
	reader.Multistream(false)
	defer func() { _ = reader.Close() }()

	hash := sha256.New()
	seen := make(map[string]struct{})
	var pending []byte
	var pendingName string
	var members, payloadFiles, payloadBytes int64
	var foundStdout, foundStderr, foundFiles, foundCrashDir, foundManifest bool
	var embedded []byte
	var tarBytes int64
	const maxTarBytes = maxArchiveBytes + maxArchiveBytes/8 + maxManifestBytes

	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		header := make([]byte, tarBlockSize)
		if err := readFullContext(ctx, reader, header); err != nil {
			if contextError := contextErr(ctx); contextError != nil {
				return contextError
			}
			return errors.New("archive tar stream is truncated")
		}
		tarBytes += tarBlockSize
		if tarBytes > maxTarBytes {
			return errors.New("archive decompressed stream exceeds the bounded contract")
		}
		if isZeroBlock(header) {
			trailer := make([]byte, tarBlockSize)
			if err := readFullContext(ctx, reader, trailer); err != nil {
				if contextError := contextErr(ctx); contextError != nil {
					return contextError
				}
				return errors.New("archive tar terminator is invalid")
			}
			if !isZeroBlock(trailer) {
				return errors.New("archive tar terminator is invalid")
			}
			tarBytes += tarBlockSize
			if tarBytes > maxTarBytes {
				return errors.New("archive decompressed stream exceeds the bounded contract")
			}
			hash.Write(header)
			hash.Write(trailer)
			var extra [1]byte
			n, readErr := reader.Read(extra[:])
			if contextError := contextErr(ctx); contextError != nil {
				return contextError
			}
			if n != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
				return errors.New("archive has trailing gzip or tar content")
			}
			if compressed.remaining != 0 {
				return errors.New("archive has trailing compressed content")
			}
			break
		}
		member, err := parseTarHeader(header)
		if err != nil {
			return fmt.Errorf("archive tar header is invalid: %w", err)
		}
		members++
		if members > maxTarMembers {
			return errors.New("archive contains too many members")
		}
		padded, err := paddedTarSize(member.size)
		if err != nil || member.size > maxArchiveBytes {
			return errors.New("archive member exceeds the bounded contract")
		}
		if padded > maxTarBytes-tarBlockSize {
			return errors.New("archive decompressed stream exceeds the bounded contract")
		}

		if member.extension {
			if padded > maxTarMetadata {
				return errors.New("archive extension record is too large")
			}
			metadata := make([]byte, padded)
			copy(metadata, header)
			if err := readFullContext(ctx, reader, metadata[tarBlockSize:]); err != nil {
				if contextError := contextErr(ctx); contextError != nil {
					return contextError
				}
				return errors.New("archive extension record is truncated")
			}
			tarBytes += padded
			if tarBytes > maxTarBytes {
				return errors.New("archive extension record is too large")
			}
			name, err := parseTarExtension(member.typeflag, metadata[tarBlockSize:member.size])
			if err != nil {
				return err
			}
			pending = append(pending, metadata...)
			if name != "" {
				pendingName = name
			}
			continue
		}

		name := member.name
		if pendingName != "" {
			name = pendingName
		}
		name, err = canonicalTarName(name, member.directory)
		if err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return errors.New("archive contains duplicate members")
		}
		seen[name] = struct{}{}
		includeInPayloadHash := name != "manifest.json"
		if includeInPayloadHash {
			hash.Write(pending)
			hash.Write(header)
		}
		pending = nil
		pendingName = ""

		switch {
		case member.directory:
			if member.size != 0 {
				return errors.New("archive directory has content")
			}
			if name == "files" {
				foundFiles = true
			} else if name == "files/coredumps" {
				foundCrashDir = true
			} else {
				return errors.New("archive contains an unexpected directory")
			}
		case name == "manifest.json":
			if foundManifest || member.size > maxManifestBytes {
				return errors.New("archive embedded manifest is invalid")
			}
			foundManifest = true
			embedded = make([]byte, member.size)
			if err := readFullContext(ctx, reader, embedded); err != nil {
				if contextError := contextErr(ctx); contextError != nil {
					return contextError
				}
				return errors.New("archive embedded manifest is truncated")
			}
		case name == "stdout.log":
			if foundStdout {
				return errors.New("archive contains duplicate members")
			}
			foundStdout = true
			if err := copyTarContent(ctx, reader, member.size, hash); err != nil {
				return err
			}
		case name == "stderr.log":
			if foundStderr {
				return errors.New("archive contains duplicate members")
			}
			foundStderr = true
			if err := copyTarContent(ctx, reader, member.size, hash); err != nil {
				return err
			}
		case strings.HasPrefix(name, "files/"):
			if member.size < 0 || payloadBytes > maxArchiveBytes-member.size {
				return errors.New("archive payload exceeds the bounded contract")
			}
			payloadFiles++
			payloadBytes += member.size
			if contract.Recipe == "system-summary.v1" && name != "files/system-summary.json" {
				return errors.New("archive payload does not match the system summary recipe")
			}
			if contract.Recipe == "crashdump-collection.v1" && !strings.HasPrefix(name, "files/coredumps/") {
				return errors.New("archive payload does not match the crashdump recipe")
			}
			if err := copyTarContent(ctx, reader, member.size, hash); err != nil {
				return err
			}
		default:
			return errors.New("archive contains an unexpected member")
		}
		padding := padded - member.size
		if padding > 0 {
			if err := copyTarContent(ctx, reader, padding, hashIf(hash, includeInPayloadHash)); err != nil {
				return err
			}
		}
		tarBytes += padded
		if tarBytes > maxTarBytes {
			return errors.New("archive decompressed stream exceeds the bounded contract")
		}
	}
	if len(pending) != 0 || !foundManifest || !foundStdout || !foundStderr || !foundFiles {
		return errors.New("archive is missing required members")
	}
	if contract.Recipe == "crashdump-collection.v1" && !foundCrashDir {
		return errors.New("archive is missing the crashdump directory")
	}
	if !bytes.Equal(embedded, sidecar) {
		return errors.New("archive embedded manifest differs from sidecar")
	}
	if payloadFiles != contract.FileCount || payloadBytes != contract.Bytes {
		return errors.New("archive payload counts do not match the manifest")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), contract.PayloadSHA256) {
		return errors.New("archive payload checksum does not match the manifest")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("archive could not be rewound after contract verification")
	}
	return nil
}

type contextLimitedReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
}

func (reader *contextLimitedReader) ReadByte() (byte, error) {
	if err := contextErr(reader.ctx); err != nil {
		return 0, err
	}
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	var one [1]byte
	n, err := reader.Read(one[:])
	if n == 1 {
		return one[0], nil
	}
	return 0, err
}

func (reader *contextLimitedReader) Read(buffer []byte) (int, error) {
	if err := contextErr(reader.ctx); err != nil {
		return 0, err
	}
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	n, err := reader.reader.Read(buffer)
	reader.remaining -= int64(n)
	return n, err
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func readFullContext(ctx context.Context, reader io.Reader, buffer []byte) error {
	for len(buffer) > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			buffer = buffer[n:]
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buffer) == 0 {
				return nil
			}
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func copyTarContent(ctx context.Context, reader io.Reader, size int64, writer io.Writer) error {
	buffer := make([]byte, 32*1024)
	for size > 0 {
		if err := contextErr(ctx); err != nil {
			return err
		}
		chunk := int64(len(buffer))
		if chunk > size {
			chunk = size
		}
		n, err := reader.Read(buffer[:chunk])
		if n > 0 {
			if writer != nil {
				if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
					return writeErr
				}
			}
			size -= int64(n)
		}
		if err != nil {
			if contextError := contextErr(ctx); contextError != nil {
				return contextError
			}
			if errors.Is(err, io.EOF) && size == 0 {
				return nil
			}
			return errors.New("archive member is truncated")
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func hashIf(hash io.Writer, include bool) io.Writer {
	if include {
		return hash
	}
	return io.Discard
}

type tarMember struct {
	name      string
	typeflag  byte
	size      int64
	directory bool
	extension bool
}

func parseTarHeader(header []byte) (tarMember, error) {
	var member tarMember
	if len(header) != int(tarBlockSize) {
		return member, errors.New("tar header has an invalid size")
	}
	if err := verifyTarChecksum(header); err != nil {
		return member, err
	}
	name := tarString(header[0:100])
	prefix := tarString(header[345:500])
	if prefix != "" {
		name = prefix + "/" + name
	}
	size, err := parseTarNumber(header[124:136])
	if err != nil {
		return member, fmt.Errorf("tar size: %w", err)
	}
	if size < 0 {
		return member, errors.New("tar size is negative")
	}
	typeflag := header[156]
	member.name, member.typeflag, member.size = name, typeflag, size
	switch typeflag {
	case 0, '0':
	case '5':
		member.directory = true
	case 'L', 'x':
		member.extension = true
	case 'g', 'K':
		return member, errors.New("tar global or link extension is not accepted")
	default:
		return member, errors.New("tar link, device, or special member is not accepted")
	}
	return member, nil
}

func verifyTarChecksum(header []byte) error {
	want, err := parseTarNumber(header[148:156])
	if err != nil {
		return errors.New("tar checksum is invalid")
	}
	var sum int64
	for index, value := range header {
		if index >= 148 && index < 156 {
			sum += int64(' ')
		} else {
			sum += int64(value)
		}
	}
	if sum != want {
		return errors.New("tar checksum does not match")
	}
	return nil
}

func parseTarNumber(field []byte) (int64, error) {
	field = bytes.Trim(field, "\x00 ")
	if len(field) == 0 {
		return 0, nil
	}
	if field[0]&0x80 != 0 {
		return 0, errors.New("base-256 tar numbers are not accepted")
	}
	var value int64
	for _, digit := range field {
		if digit < '0' || digit > '7' {
			return 0, errors.New("tar number is not octal")
		}
		if value > (int64(^uint64(0)>>1)-int64(digit-'0'))/8 {
			return 0, errors.New("tar number overflows")
		}
		value = value*8 + int64(digit-'0')
	}
	return value, nil
}

func tarString(field []byte) string {
	if index := bytes.IndexByte(field, 0); index >= 0 {
		field = field[:index]
	}
	return string(field)
}

func paddedTarSize(size int64) (int64, error) {
	if size < 0 || size > maxArchiveBytes {
		return 0, errors.New("tar member size is invalid")
	}
	if size > int64(^uint64(0)>>1)-tarBlockSize+1 {
		return 0, errors.New("tar member size overflows")
	}
	return ((size + tarBlockSize - 1) / tarBlockSize) * tarBlockSize, nil
}

func isZeroBlock(block []byte) bool {
	return bytes.Equal(block, make([]byte, len(block)))
}

func parseTarExtension(typeflag byte, content []byte) (string, error) {
	switch typeflag {
	case 'L':
		nameEnd := bytes.IndexByte(content, 0)
		if nameEnd <= 0 || !bytes.Equal(content[nameEnd:], make([]byte, len(content)-nameEnd)) {
			return "", errors.New("tar long-name extension is invalid")
		}
		name := string(content[:nameEnd])
		if len(name) > 4096 {
			return "", errors.New("tar long-name extension is invalid")
		}
		return name, nil
	case 'x':
		var name string
		for len(content) > 0 {
			space := bytes.IndexByte(content, ' ')
			if space <= 0 || space >= len(content) {
				return "", errors.New("tar PAX extension is invalid")
			}
			length, err := strconv.Atoi(string(content[:space]))
			if err != nil || length < space+3 || length > len(content) {
				return "", errors.New("tar PAX extension length is invalid")
			}
			record := content[:length]
			if record[length-1] != '\n' {
				return "", errors.New("tar PAX extension record is invalid")
			}
			equal := bytes.IndexByte(record[space+1:], '=')
			if equal < 0 {
				return "", errors.New("tar PAX extension record is invalid")
			}
			equal += space + 1
			if string(record[space+1:equal]) == "path" {
				name = string(record[equal+1 : length-1])
			}
			content = content[length:]
		}
		return name, nil
	default:
		return "", errors.New("tar extension is not accepted")
	}
}

func canonicalTarName(name string, directory bool) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "./") {
		return "", errors.New("archive member path is invalid")
	}
	for index := 0; index < len(name); index++ {
		if name[index] < 0x20 || name[index] > 0x7e {
			return "", errors.New("archive member path is invalid")
		}
	}
	if directory {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || path.Clean(name) != name || strings.Contains(name, "//") {
		return "", errors.New("archive member path is invalid")
	}
	return name, nil
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
	raw := os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_URL")
	if raw == "" {
		return nil, errors.New("upload URL is missing")
	}
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 || strings.ContainsRune(raw, '\x00') {
		return nil, errors.New("upload URL is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path == "" ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" ||
		parsed.ForceQuery ||
		strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("upload URL is invalid")
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("upload URL must use HTTPS")
	}
	return parsed, nil
}

func uploadToken() (string, error) {
	token := os.Getenv("BREAKGLASS_ARTIFACT_UPLOAD_TOKEN")
	if token == "" || len(token) > maxTokenBytes || strings.TrimSpace(token) != token ||
		strings.IndexFunc(token, unicode.IsSpace) >= 0 || strings.ContainsRune(token, '\x00') {
		return "", errors.New("upload token is invalid")
	}
	return token, nil
}

func putOnce(ctx context.Context, client *http.Client, endpoint *url.URL, token string, file *os.File, size int64, contract artifactManifest, sidecar []byte) error {
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
		if transientTransport(err) {
			return &uploadTransportError{cause: fmt.Errorf("send upload: %w", err)}
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
	if err := verifyArchiveContract(ctx, file, size, contract, sidecar); err != nil {
		return fmt.Errorf("archive contract changed after upload: %w", err)
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

type uploadTransportError struct {
	cause error
}

func (err *uploadTransportError) Error() string { return err.cause.Error() }

func (err *uploadTransportError) Unwrap() error { return err.cause }

func transientTransport(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var urlError *url.Error
	if !errors.As(err, &urlError) {
		return false
	}
	if urlError.Timeout() {
		return true
	}
	return errors.Is(urlError.Err, syscall.ECONNRESET) ||
		errors.Is(urlError.Err, syscall.ECONNREFUSED) ||
		errors.Is(urlError.Err, syscall.EPIPE) ||
		errors.Is(urlError.Err, io.EOF)
}

func retryable(err error) bool {
	var responseError *uploadResponseError
	if errors.As(err, &responseError) {
		return responseError.temporary
	}
	var transportError *uploadTransportError
	if errors.As(err, &transportError) {
		return true
	}
	if transientTransport(err) {
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

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package archive validates the exact bounded gzip/tar/manifest contract
// emitted by baked diagnostic artifact collectors. It never extracts files.
package archive

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	MaxCollectorTarRecords  = 16389
	defaultMaxMetadataBytes = 1 << 20
	defaultMaxPathBytes     = 4096
	copyBufferBytes         = 32 << 10
)

// Limits independently bounds each validation dimension. Zero fields select
// immutable collector-v1 defaults; values cannot widen those defaults.
type Limits struct {
	MaxCompressedBytes   int64
	MaxDecompressedBytes int64
	MaxPayloadBytes      int64
	MaxEntryBytes        int64
	MaxMembers           int64
	MaxMetadataBytes     int64
	MaxPathBytes         int
}

// Result is safe persisted metadata from a successful validation.
type Result struct {
	Manifest         Manifest
	CompressedBytes  int64
	CompressedSHA256 string
	PayloadBytes     int64
	PayloadFiles     int64
	PayloadSHA256    string
	TarRecords       int64
}

// Validate consumes one seekable staged archive. It verifies the exact
// compressed size and digest, one gzip member, exact tar framing, allowed raw
// records, recipe descriptor, runtime binding, and collector payload digest.
func Validate(ctx context.Context, staged io.ReadSeeker, compressedSize int64, expected Expected, limits Limits) (result Result, resultErr error) {
	if ctx == nil || staged == nil {
		return result, errors.New("artifact validation context and staged archive are required")
	}
	defer func() { resultErr = errors.Join(resultErr, contextError(ctx)) }()
	if err := contextError(ctx); err != nil {
		return result, err
	}
	descriptor, err := descriptorFor(expected.Recipe, expected.RecipeVersion)
	if err != nil {
		return result, err
	}
	limits, err = normalizeLimits(limits, descriptor, expected.Inputs.MaxArchiveBytes)
	if err != nil {
		return result, err
	}
	if compressedSize < 1 || compressedSize > limits.MaxCompressedBytes {
		return result, errors.New("artifact compressed size is outside the bounded contract")
	}
	actualSize, err := staged.Seek(0, io.SeekEnd)
	if err != nil {
		return result, fmt.Errorf("measure staged artifact: %w", err)
	}
	if actualSize != compressedSize {
		return result, errors.New("artifact compressed size does not match the staged file")
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind staged artifact: %w", err)
	}
	compressedHash := sha256.New()
	read, err := copyExact(ctx, compressedHash, staged, compressedSize)
	if err != nil || read != compressedSize {
		if err == nil {
			err = errors.New("artifact compressed stream is truncated")
		}
		return result, err
	}
	if err := contextError(ctx); err != nil {
		return result, err
	}
	result.CompressedBytes = compressedSize
	result.CompressedSHA256 = hex.EncodeToString(compressedHash.Sum(nil))
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind staged artifact for validation: %w", err)
	}
	streamResult, err := validateStream(ctx, staged, compressedSize, expected, descriptor, limits)
	if err != nil {
		return Result{}, err
	}
	streamResult.CompressedBytes = result.CompressedBytes
	streamResult.CompressedSHA256 = result.CompressedSHA256
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind validated artifact: %w", err)
	}
	return streamResult, nil
}

func validateStream(ctx context.Context, staged io.Reader, compressedSize int64, expected Expected, descriptor descriptor, limits Limits) (result Result, resultErr error) {
	compressed := &contextLimitedReader{ctx: ctx, reader: staged, remaining: compressedSize}
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return result, contextErr
		}
		return result, errors.New("artifact is not a valid gzip stream")
	}
	reader.Multistream(false)
	defer func() {
		resultErr = errors.Join(resultErr, contextError(ctx), errorContext("close artifact gzip reader", reader.Close()))
	}()

	payloadHash := sha256.New()
	seen := pathRegistry{seen: make(map[string]bool)}
	var pending []byte
	var pendingName string
	var embeddedManifest []byte
	var decompressedBytes, members, payloadFiles, payloadBytes int64
	var foundManifest, foundStdout, foundStderr bool

	for {
		if err := contextError(ctx); err != nil {
			return result, err
		}
		header := make([]byte, tarBlockSize)
		if err := readFullContext(ctx, reader, header); err != nil {
			return result, errors.New("artifact tar stream is truncated")
		}
		decompressedBytes += tarBlockSize
		if decompressedBytes > limits.MaxDecompressedBytes {
			return result, errors.New("artifact decompressed stream exceeds its bound")
		}
		if allZero(header) {
			trailer := make([]byte, tarBlockSize)
			if err := readFullContext(ctx, reader, trailer); err != nil || !allZero(trailer) {
				return result, errors.New("artifact tar terminator is invalid")
			}
			decompressedBytes += tarBlockSize
			if decompressedBytes > limits.MaxDecompressedBytes {
				return result, errors.New("artifact decompressed stream exceeds its bound")
			}
			_, _ = payloadHash.Write(header)
			_, _ = payloadHash.Write(trailer)
			var extra [1]byte
			n, readErr := reader.Read(extra[:])
			if n != 0 || !errors.Is(readErr, io.EOF) || compressed.remaining != 0 {
				return result, errors.New("artifact has trailing compressed or tar content")
			}
			break
		}

		member, err := parseTarHeader(header)
		if err != nil {
			return result, fmt.Errorf("artifact tar header is invalid: %w", err)
		}
		members++
		if members > limits.MaxMembers {
			return result, errors.New("artifact contains too many tar records")
		}
		padded, err := paddedTarSize(member.size, limits.MaxEntryBytes)
		if err != nil || padded > limits.MaxDecompressedBytes-tarBlockSize {
			return result, errors.New("artifact member exceeds its bound")
		}

		if member.extension {
			if len(pending) != 0 {
				return result, errors.New("artifact has more than one path extension for a member")
			}
			if padded > limits.MaxMetadataBytes {
				return result, errors.New("artifact path extension exceeds its bound")
			}
			recordSize, err := tarRecordSize(padded)
			if err != nil || recordSize > limits.MaxMetadataBytes || recordSize > int64(maxInt()) {
				return result, errors.New("artifact path extension is invalid")
			}
			metadata := make([]byte, int(recordSize))
			copy(metadata, header)
			memberEnd, err := tarMemberEnd(recordSize, member.size, int64(len(metadata)))
			if err != nil || readFullContext(ctx, reader, metadata[int(tarBlockSize):]) != nil {
				return result, errors.New("artifact path extension is truncated")
			}
			decompressedBytes += padded
			if decompressedBytes > limits.MaxDecompressedBytes {
				return result, errors.New("artifact decompressed stream exceeds its bound")
			}
			pendingName, err = parseTarExtension(member.typeflag, metadata[int(tarBlockSize):int(memberEnd)], limits.MaxPathBytes)
			if err != nil {
				return result, err
			}
			pending = metadata
			continue
		}

		name := member.name
		if pendingName != "" {
			name = pendingName
		}
		name, err = canonicalTarName(name, member.directory, limits.MaxPathBytes)
		if err != nil {
			return result, err
		}
		if err := registerPath(&seen, name, member.directory); err != nil {
			return result, err
		}
		if name == "manifest.json" && len(pending) != 0 {
			return result, errors.New("artifact manifest must use its fixed tar name")
		}
		includeInPayloadHash := name != "manifest.json"
		if includeInPayloadHash && len(pending) != 0 {
			_, _ = payloadHash.Write(pending)
		}
		if includeInPayloadHash {
			_, _ = payloadHash.Write(header)
		}
		pending = nil
		pendingName = ""

		switch {
		case member.directory:
			if member.size != 0 || !descriptorAllowsDirectory(descriptor, name) {
				return result, errors.New("artifact contains an unexpected directory")
			}
		case name == "manifest.json":
			if foundManifest || member.size < 1 || member.size > MaxManifestBytes || member.size > int64(maxInt()) {
				return result, errors.New("artifact embedded manifest is invalid")
			}
			foundManifest = true
			embeddedManifest = make([]byte, int(member.size))
			if err := readFullContext(ctx, reader, embeddedManifest); err != nil {
				return result, errors.New("artifact embedded manifest is truncated")
			}
		case name == "stdout.log":
			foundStdout = true
			if err := copyTarContent(ctx, reader, member.size, payloadHash); err != nil {
				return result, err
			}
		case name == "stderr.log":
			foundStderr = true
			if err := copyTarContent(ctx, reader, member.size, payloadHash); err != nil {
				return result, err
			}
		case descriptorAllowsPayload(descriptor, name):
			if member.size > limits.MaxPayloadBytes-payloadBytes {
				return result, errors.New("artifact payload exceeds its bound")
			}
			payloadFiles++
			payloadBytes += member.size
			if err := copyTarContent(ctx, reader, member.size, payloadHash); err != nil {
				return result, err
			}
		default:
			return result, errors.New("artifact contains an unexpected member")
		}

		padding := padded - member.size
		if padding > 0 {
			var writer io.Writer = io.Discard
			if includeInPayloadHash {
				writer = payloadHash
			}
			if err := copyTarContent(ctx, reader, padding, writer); err != nil {
				return result, err
			}
		}
		decompressedBytes += padded
		if decompressedBytes > limits.MaxDecompressedBytes {
			return result, errors.New("artifact decompressed stream exceeds its bound")
		}
	}

	if len(pending) != 0 || !foundManifest || !foundStdout || !foundStderr {
		return result, errors.New("artifact is missing required members")
	}
	if err := validatePathCollisions(seen.seen); err != nil {
		return result, err
	}
	for required := range descriptor.requiredDirectories {
		if isDirectory, found := seen.seen[required]; !found || !isDirectory {
			return result, errors.New("artifact is missing a required directory")
		}
	}
	if descriptor.requiredPayload != "" {
		if isDirectory, found := seen.seen[descriptor.requiredPayload]; !found || isDirectory {
			return result, errors.New("artifact is missing its required payload")
		}
	}
	manifest, _, err := parseAndValidateManifest(embeddedManifest, expected)
	if err != nil {
		return result, err
	}
	if payloadFiles != manifest.FileCount || payloadBytes != manifest.Bytes {
		return result, errors.New("artifact payload counts do not match the manifest")
	}
	payloadDigest := hex.EncodeToString(payloadHash.Sum(nil))
	if payloadDigest != manifest.PayloadSHA256 {
		return result, errors.New("artifact payload checksum does not match the manifest")
	}
	result.Manifest = manifest
	result.PayloadBytes = payloadBytes
	result.PayloadFiles = payloadFiles
	result.PayloadSHA256 = payloadDigest
	result.TarRecords = members
	return result, nil
}

func normalizeLimits(limits Limits, descriptor descriptor, expectedArchiveBytes int64) (Limits, error) {
	if expectedArchiveBytes < 1 || expectedArchiveBytes > descriptor.maxArchiveBytes {
		return limits, errors.New("expected archive bound does not match the recipe descriptor")
	}
	if limits.MaxCompressedBytes == 0 {
		limits.MaxCompressedBytes = expectedArchiveBytes
	}
	if limits.MaxDecompressedBytes == 0 {
		limits.MaxDecompressedBytes = descriptor.maxArchiveBytes + descriptor.maxArchiveBytes/8 + MaxManifestBytes
	}
	if limits.MaxPayloadBytes == 0 {
		limits.MaxPayloadBytes = descriptor.maxArchiveBytes
	}
	if limits.MaxEntryBytes == 0 {
		limits.MaxEntryBytes = descriptor.maxArchiveBytes
	}
	if limits.MaxMembers == 0 {
		limits.MaxMembers = MaxCollectorTarRecords
	}
	if limits.MaxMetadataBytes == 0 {
		limits.MaxMetadataBytes = defaultMaxMetadataBytes
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = defaultMaxPathBytes
	}
	maximumDecompressed := descriptor.maxArchiveBytes + descriptor.maxArchiveBytes/8 + MaxManifestBytes
	if limits.MaxCompressedBytes < 1 || limits.MaxCompressedBytes > expectedArchiveBytes ||
		limits.MaxDecompressedBytes < 2*tarBlockSize || limits.MaxDecompressedBytes > maximumDecompressed ||
		limits.MaxPayloadBytes < 0 || limits.MaxPayloadBytes > descriptor.maxArchiveBytes ||
		limits.MaxEntryBytes < 1 || limits.MaxEntryBytes > descriptor.maxArchiveBytes ||
		limits.MaxMembers < 1 || limits.MaxMembers > MaxCollectorTarRecords ||
		limits.MaxMetadataBytes < tarBlockSize || limits.MaxMetadataBytes > defaultMaxMetadataBytes ||
		limits.MaxPathBytes < 1 || limits.MaxPathBytes > defaultMaxPathBytes {
		return limits, errors.New("artifact validation limits are outside immutable collector bounds")
	}
	return limits, nil
}

func descriptorAllowsDirectory(descriptor descriptor, name string) bool {
	if _, found := descriptor.requiredDirectories[name]; found {
		return true
	}
	return descriptor.payloadPrefix != "" && strings.HasPrefix(name+"/", descriptor.payloadPrefix)
}

func descriptorAllowsPayload(descriptor descriptor, name string) bool {
	if descriptor.requiredPayload != "" {
		return name == descriptor.requiredPayload
	}
	return descriptor.payloadPrefix != "" && strings.HasPrefix(name, descriptor.payloadPrefix) &&
		name != strings.TrimSuffix(descriptor.payloadPrefix, "/")
}

type pathRegistry struct {
	seen map[string]bool
}

func registerPath(registry *pathRegistry, name string, directory bool) error {
	if _, exists := registry.seen[name]; exists {
		return errors.New("artifact contains a duplicate member")
	}
	registry.seen[name] = directory
	return nil
}

func validatePathCollisions(seen map[string]bool) error {
	paths := make([]string, 0, len(seen))
	for name := range seen {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if seen[name] {
			continue
		}
		descendant := name + "/"
		index := sort.SearchStrings(paths, descendant)
		if index < len(paths) && strings.HasPrefix(paths[index], descendant) {
			return errors.New("artifact contains a file/directory prefix collision")
		}
	}
	return nil
}

type contextLimitedReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
}

func (reader *contextLimitedReader) ReadByte() (byte, error) {
	var one [1]byte
	read, err := reader.Read(one[:])
	if read == 1 {
		return one[0], nil
	}
	return 0, err
}

func (reader *contextLimitedReader) Read(buffer []byte) (int, error) {
	if err := contextError(reader.ctx); err != nil {
		return 0, err
	}
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:int(reader.remaining)]
	}
	read, err := reader.reader.Read(buffer)
	reader.remaining -= int64(read)
	return read, err
}

func readFullContext(ctx context.Context, reader io.Reader, buffer []byte) error {
	for len(buffer) > 0 {
		if err := contextError(ctx); err != nil {
			return err
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			buffer = buffer[read:]
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buffer) == 0 {
				return nil
			}
			return err
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func copyExact(ctx context.Context, writer io.Writer, reader io.Reader, size int64) (int64, error) {
	var copied int64
	buffer := make([]byte, copyBufferBytes)
	for copied < size {
		if err := contextError(ctx); err != nil {
			return copied, err
		}
		want := len(buffer)
		if remaining := size - copied; remaining < int64(want) {
			want = int(remaining)
		}
		read, err := reader.Read(buffer[:want])
		if read > 0 {
			written, writeErr := writer.Write(buffer[:read])
			if writeErr != nil {
				return copied, fmt.Errorf("write bounded artifact bytes: %w", writeErr)
			}
			if written != read {
				return copied, io.ErrShortWrite
			}
			copied += int64(read)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && copied == size {
				return copied, nil
			}
			return copied, fmt.Errorf("read bounded artifact bytes: %w", err)
		}
		if read == 0 {
			return copied, io.ErrNoProgress
		}
	}
	return copied, nil
}

func copyTarContent(ctx context.Context, reader io.Reader, size int64, writer io.Writer) error {
	_, err := copyExact(ctx, writer, reader, size)
	if err != nil {
		return fmt.Errorf("read artifact tar member: %w", err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func errorContext(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

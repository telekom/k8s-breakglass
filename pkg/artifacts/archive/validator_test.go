// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type fixtureEntry struct {
	name     string
	typeflag byte
	content  []byte
}

func TestValidateSystemSummaryExactContract(t *testing.T) {
	expected := summaryExpected()
	compressed, manifest := archiveFixture(t, expected, []fixtureEntry{
		{name: "files", typeflag: tar.TypeDir},
		{name: "files/system-summary.json", content: []byte(`{"hostname":"worker"}`)},
		{name: "stdout.log", content: []byte("complete\n")},
		{name: "stderr.log", content: nil},
	}, nil)
	result, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	compressedDigest := sha256.Sum256(compressed)
	if result.Manifest.ArtifactID != expected.ArtifactID || result.PayloadFiles != 1 ||
		result.PayloadBytes != manifest.Bytes || result.PayloadSHA256 != manifest.PayloadSHA256 ||
		result.CompressedSHA256 != hex.EncodeToString(compressedDigest[:]) {
		t.Fatalf("Validate() result = %#v", result)
	}
}

func TestValidateCrashdumpAllowsOneBoundedLongPathExtension(t *testing.T) {
	expected := crashExpected()
	longName := "files/coredumps/" + strings.Repeat("a", 180)
	compressed, _ := archiveFixture(t, expected, []fixtureEntry{
		{name: "files", typeflag: tar.TypeDir},
		{name: "files/coredumps", typeflag: tar.TypeDir},
		{name: longName, content: []byte("core")},
		{name: "stdout.log"},
		{name: "stderr.log"},
	}, nil)
	if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{}); err != nil {
		t.Fatalf("Validate() long path error = %v", err)
	}
}

func TestValidateRejectsGzipAndTarFramingAmbiguity(t *testing.T) {
	expected := summaryExpected()
	valid, _ := archiveFixture(t, expected, summaryEntries(), nil)
	second, _ := archiveFixture(t, expected, summaryEntries(), nil)

	trailingTar := ungzipFixture(t, valid)
	trailingTar = append(trailingTar, make([]byte, tarBlockSize)...)
	badTar := gzipFixture(t, trailingTar)
	for name, candidate := range map[string][]byte{
		"trailing compressed":  append(append([]byte(nil), valid...), byte('x')),
		"second gzip member":   append(append([]byte(nil), valid...), second...),
		"extra tar zero block": badTar,
		"not gzip":             []byte("not-gzip"),
		"truncated":            valid[:len(valid)-4],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate(context.Background(), bytes.NewReader(candidate), int64(len(candidate)), expected, Limits{}); err == nil {
				t.Fatal("Validate() unexpectedly accepted ambiguous framing")
			}
		})
	}
}

func TestValidateRejectsSpecialTraversalDuplicateAndPrefixCollision(t *testing.T) {
	crash := crashExpected()
	tests := map[string][]fixtureEntry{
		"traversal": append(crashEntries(), fixtureEntry{name: "files/coredumps/../escape", content: []byte("bad")}),
		"absolute":  append(crashEntries(), fixtureEntry{name: "/files/coredumps/escape", content: []byte("bad")}),
		"duplicate": append(crashEntries(),
			fixtureEntry{name: "files/coredumps/core", content: []byte("one")},
			fixtureEntry{name: "files/coredumps/core", content: []byte("two")}),
		"prefix collision": append(crashEntries(),
			fixtureEntry{name: "files/coredumps/parent", content: []byte("one")},
			fixtureEntry{name: "files/coredumps/parent/child", content: []byte("two")}),
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			compressed, _ := archiveFixture(t, crash, entries, nil)
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), crash, Limits{}); err == nil {
				t.Fatal("Validate() unexpectedly accepted unsafe tar content")
			}
		})
	}

	for name, typeflag := range map[string]byte{
		"symlink":    tar.TypeSymlink,
		"device":     tar.TypeChar,
		"fifo":       tar.TypeFifo,
		"global pax": tar.TypeXGlobalHeader,
	} {
		t.Run(name, func(t *testing.T) {
			entries := append(crashEntries(), fixtureEntry{name: "files/coredumps/special", content: []byte("content")})
			compressed, _ := archiveFixture(t, crash, entries, nil)
			candidate := mutateTarTypeflag(t, compressed, "files/coredumps/special", typeflag)
			if _, err := Validate(context.Background(), bytes.NewReader(candidate), int64(len(candidate)), crash, Limits{}); err == nil {
				t.Fatal("Validate() unexpectedly accepted a special tar member")
			}
		})
	}
}

func TestValidateRejectsManifestAmbiguityAndBindingForgery(t *testing.T) {
	expected := summaryExpected()
	for name, transform := range map[string]func([]byte) []byte{
		"duplicate key": func(value []byte) []byte {
			return bytes.Replace(value, []byte(`"schema_version":"diagnostic-artifact/v1"`),
				[]byte(`"schema_version":"diagnostic-artifact/v1","schema_version":"diagnostic-artifact/v1"`), 1)
		},
		"unknown key": func(value []byte) []byte {
			return bytes.Replace(value, []byte(`{"schema_version"`), []byte(`{"unknown":true,"schema_version"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			compressed, _ := archiveFixture(t, expected, summaryEntries(), transform)
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{}); err == nil {
				t.Fatal("Validate() unexpectedly accepted ambiguous manifest")
			}
		})
	}

	compressed, _ := archiveFixture(t, expected, summaryEntries(), nil)
	for name, mutate := range map[string]func(*Expected){
		"session namespace": func(value *Expected) { value.SessionNamespace = "other" },
		"session UID":       func(value *Expected) { value.SessionUID = "other-uid" },
		"artifact ID":       func(value *Expected) { value.ArtifactID = "dsa-aaaaaaaaaaaaaaaaaaaaaaaa" },
		"redaction":         func(value *Expected) { value.RedactionProfile = "other" },
		"input": func(value *Expected) {
			detail := "extended"
			value.Inputs.DetailLevel = &detail
		},
	} {
		t.Run(name, func(t *testing.T) {
			forged := expected
			mutate(&forged)
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), forged, Limits{}); err == nil {
				t.Fatal("Validate() unexpectedly accepted forged runtime binding")
			}
		})
	}
}

func TestValidateRequiresFieldsThatCanBeZeroOrNull(t *testing.T) {
	expected := summaryExpected()
	valid, _ := archiveFixture(t, expected, summaryEntries(), nil)
	if _, err := Validate(context.Background(), bytes.NewReader(valid), int64(len(valid)), expected, Limits{}); err != nil {
		t.Fatalf("Validate() rejected an explicit null node: %v", err)
	}

	for _, field := range []string{"exit_code", "file_count", "bytes", "node"} {
		t.Run(field, func(t *testing.T) {
			withoutField := func(value []byte) []byte {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(value, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, field)
				result, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			compressed, _ := archiveFixture(t, expected, summaryEntries(), withoutField)
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{}); err == nil {
				t.Fatalf("Validate() accepted a manifest without %s", field)
			}
		})
	}

	for _, field := range []string{"exit_code", "file_count", "bytes"} {
		t.Run(field+" null", func(t *testing.T) {
			withNull := func(value []byte) []byte {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(value, &fields); err != nil {
					t.Fatal(err)
				}
				fields[field] = json.RawMessage("null")
				result, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			compressed, _ := archiveFixture(t, expected, summaryEntries(), withNull)
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{}); err == nil {
				t.Fatalf("Validate() accepted null %s", field)
			}
		})
	}
}

func TestValidateRejectsChecksumCountsAndHeaderTampering(t *testing.T) {
	expected := summaryExpected()
	compressed, _ := archiveFixture(t, expected, summaryEntries(), nil)
	raw := ungzipFixture(t, compressed)
	raw[0] ^= 1
	badHeader := gzipFixture(t, raw)
	if _, err := Validate(context.Background(), bytes.NewReader(badHeader), int64(len(badHeader)), expected, Limits{}); err == nil {
		t.Fatal("Validate() accepted a corrupt tar checksum")
	}

	validDigest, manifest := archiveFixture(t, expected, summaryEntries(), nil)
	badDigestRaw := ungzipFixture(t, validDigest)
	badDigestRaw = bytes.Replace(badDigestRaw, []byte(manifest.PayloadSHA256), []byte(strings.Repeat("f", sha256.Size*2)), 1)
	badDigest := gzipFixture(t, badDigestRaw)
	if _, err := Validate(context.Background(), bytes.NewReader(badDigest), int64(len(badDigest)), expected, Limits{}); err == nil {
		t.Fatal("Validate() accepted a forged payload digest")
	}

	badCount, _ := archiveFixture(t, expected, summaryEntries(), func(value []byte) []byte {
		return bytes.Replace(value, []byte(`"file_count":1`), []byte(`"file_count":2`), 1)
	})
	if _, err := Validate(context.Background(), bytes.NewReader(badCount), int64(len(badCount)), expected, Limits{}); err == nil {
		t.Fatal("Validate() accepted a forged payload count")
	}
}

func TestValidateEnforcesIndependentBoundsAndContext(t *testing.T) {
	expected := summaryExpected()
	compressed, _ := archiveFixture(t, expected, summaryEntries(), nil)
	for name, limits := range map[string]Limits{
		"compressed":   {MaxCompressedBytes: int64(len(compressed) - 1)},
		"decompressed": {MaxDecompressedBytes: 2 * tarBlockSize},
		"payload":      {MaxPayloadBytes: 1},
		"entry":        {MaxEntryBytes: 1},
		"members":      {MaxMembers: 2},
		"metadata":     {MaxMetadataBytes: tarBlockSize - 1},
		"path":         {MaxPathBytes: 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Validate(context.Background(), bytes.NewReader(compressed), int64(len(compressed)), expected, limits); err == nil {
				t.Fatal("Validate() unexpectedly accepted an exceeded bound")
			}
		})
	}
	if _, err := normalizeLimits(Limits{MaxMembers: MaxCollectorTarRecords + 1}, mustDescriptor(t, expected), expected.Inputs.MaxArchiveBytes); err == nil {
		t.Fatal("normalizeLimits() widened the collector record limit")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Validate(cancelled, bytes.NewReader(compressed), int64(len(compressed)), expected, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate() cancellation error = %v", err)
	}
}

func TestNormalizeLimitsUsesRecipeSpecificDecompressedBound(t *testing.T) {
	summary := summaryExpected()
	summaryDescriptor := mustDescriptor(t, summary)
	limits, err := normalizeLimits(Limits{}, summaryDescriptor, summary.Inputs.MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	want := summaryDescriptor.maxArchiveBytes + summaryDescriptor.maxArchiveBytes/8 + MaxManifestBytes
	if limits.MaxDecompressedBytes != want {
		t.Fatalf("system-summary MaxDecompressedBytes = %d, want %d", limits.MaxDecompressedBytes, want)
	}
	if _, err := normalizeLimits(Limits{MaxDecompressedBytes: MaxCollectorArchiveBytes + MaxCollectorArchiveBytes/8 + MaxManifestBytes}, summaryDescriptor, summary.Inputs.MaxArchiveBytes); err == nil {
		t.Fatal("system-summary limits accepted the crashdump decompression bound")
	}

	crash := crashExpected()
	crashDescriptor := mustDescriptor(t, crash)
	crashLimits, err := normalizeLimits(Limits{}, crashDescriptor, crash.Inputs.MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	if crashLimits.MaxDecompressedBytes != MaxCollectorArchiveBytes+MaxCollectorArchiveBytes/8+MaxManifestBytes {
		t.Fatalf("crashdump MaxDecompressedBytes = %d, want collector bound", crashLimits.MaxDecompressedBytes)
	}
}

func TestRegisterPathScalesAndPreservesPrefixRejection(t *testing.T) {
	registry := pathRegistry{seen: make(map[string]bool)}
	for index := 0; index < MaxCollectorTarRecords-1; index++ {
		name := "files/coredumps/" + strings.Repeat("a", 4) + "/entry-" + fmt.Sprint(index)
		if err := registerPath(&registry, name, false); err != nil {
			t.Fatalf("registerPath(%q) error = %v", name, err)
		}
	}
	if err := registerPath(&registry, "files/coredumps/"+strings.Repeat("a", 4), false); err != nil {
		t.Fatal("registerPath() accepted a file over existing descendants")
	}
	if err := validatePathCollisions(registry.seen); err == nil {
		t.Fatal("validatePathCollisions() accepted a file over existing descendants")
	}
	registry = pathRegistry{seen: make(map[string]bool)}
	if err := registerPath(&registry, "files/coredumps/"+strings.Repeat("a", 4)+"/entry-0", false); err != nil {
		t.Fatal(err)
	}
	if err := registerPath(&registry, "files/coredumps/"+strings.Repeat("a", 4)+"/entry-0/child", false); err == nil {
		t.Fatal("registerPath() accepted a descendant of an existing file")
	}
}

func TestValidatePathCollisionsBoundsDeepUniquePaths(t *testing.T) {
	seen := make(map[string]bool, MaxCollectorTarRecords)
	for index := 0; index < MaxCollectorTarRecords; index++ {
		name := "files/" + strings.Repeat("a", defaultMaxPathBytes-20) + fmt.Sprintf("/%05d", index)
		seen[name] = false
	}
	if err := validatePathCollisions(seen); err != nil {
		t.Fatalf("validatePathCollisions() rejected deep unique paths: %v", err)
	}
}

func TestValidatePathCollisionsRejectsInterposedPath(t *testing.T) {
	tests := map[string]struct {
		seen map[string]bool
		want bool
	}{
		"file with interposer before descendant": {
			seen: map[string]bool{"a": false, "a.foo": true, "a/child": true}, want: true,
		},
		"directory with interposer before descendant": {
			seen: map[string]bool{"a": true, "a.foo": true, "a/child": true}, want: false,
		},
		"file without descendant": {
			seen: map[string]bool{"a": false, "a.foo": true}, want: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validatePathCollisions(test.seen)
			if (err != nil) != test.want {
				t.Fatalf("validatePathCollisions() error = %v, want error = %t", err, test.want)
			}
		})
	}
}

func TestValidateKeepsCancellationIdentityThroughValidation(t *testing.T) {
	expected := summaryExpected()
	compressed, _ := archiveFixture(t, expected, summaryEntries(), nil)
	tests := []struct {
		name       string
		cancelSeek int
		cancelRead int
	}{
		{name: "measure", cancelSeek: 1},
		{name: "compressed digest", cancelRead: 1},
		{name: "archive stream", cancelRead: 2},
		{name: "final rewind", cancelSeek: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			staged := &cancelDuringValidation{
				ReadSeeker: bytes.NewReader(compressed), cancel: cancel,
				cancelSeek: test.cancelSeek, cancelRead: test.cancelRead,
			}
			if _, err := Validate(ctx, staged, int64(len(compressed)), expected, Limits{}); !errors.Is(err, context.Canceled) {
				t.Fatalf("Validate() cancellation error = %v", err)
			}
		})
	}
}

func summaryExpected() Expected {
	detail := "basic"
	return Expected{
		Recipe: SystemSummaryRecipe, RecipeVersion: 1, ArtifactID: "dsa-0123456789abcdef01234567",
		SessionNamespace: "breakglass-test", SessionName: "diagnostic-smoke", SessionUID: "uid-0123456789abcdef",
		RedactionProfile: "credential-text.v1", RedactionVersion: 1,
		Inputs: Inputs{MaxArchiveBytes: MaxSystemSummaryArchiveBytes, DetailLevel: &detail},
	}
}

func crashExpected() Expected {
	node := "worker-one"
	age := int64(60)
	return Expected{
		Recipe: CrashdumpCollectionRecipe, RecipeVersion: 1, ArtifactID: "dsa-0123456789abcdef01234567",
		SessionNamespace: "breakglass-test", SessionName: "diagnostic-crash", SessionUID: "uid-0123456789abcdef",
		RedactionProfile: "credential-text.v1", RedactionVersion: 1, Node: &node,
		Inputs: Inputs{MaxArchiveBytes: MaxCollectorArchiveBytes, MaxAgeMinutes: &age, Node: &node},
	}
}

func summaryEntries() []fixtureEntry {
	return []fixtureEntry{
		{name: "files", typeflag: tar.TypeDir},
		{name: "files/system-summary.json", content: []byte(`{"hostname":"worker"}`)},
		{name: "stdout.log"},
		{name: "stderr.log"},
	}
}

func crashEntries() []fixtureEntry {
	return []fixtureEntry{
		{name: "files", typeflag: tar.TypeDir},
		{name: "files/coredumps", typeflag: tar.TypeDir},
		{name: "stdout.log"},
		{name: "stderr.log"},
	}
}

func archiveFixture(t *testing.T, expected Expected, entries []fixtureEntry, transform func([]byte) []byte) ([]byte, Manifest) {
	t.Helper()
	manifest := Manifest{
		SchemaVersion: SchemaV1, Recipe: expected.Recipe, RecipeVersion: expected.RecipeVersion,
		ArtifactID: expected.ArtifactID, Node: cloneString(expected.Node), ArchiveFormat: ArchiveFormatTarGzip,
		Inputs: expected.Inputs, PayloadSHA256: strings.Repeat("0", sha256.Size*2),
		ExitCode: 0, ExitSemantics: ExitSemanticsCompleteOnly,
	}
	manifest.Session.Namespace = expected.SessionNamespace
	manifest.Session.Name = expected.SessionName
	manifest.Session.UID = expected.SessionUID
	manifest.Redaction.Profile = expected.RedactionProfile
	manifest.Redaction.Version = expected.RedactionVersion
	if expected.Recipe == SystemSummaryRecipe {
		manifest.DeclaredOutputs = []string{"files/system-summary.json", "manifest.json", "stderr.log", "stdout.log"}
	} else {
		manifest.DeclaredOutputs = []string{"files/coredumps/", "manifest.json", "stderr.log", "stdout.log"}
	}
	for _, entry := range entries {
		if entry.typeflag == 0 && (entry.name == "files/system-summary.json" || strings.HasPrefix(entry.name, "files/coredumps/")) {
			manifest.FileCount++
			manifest.Bytes += int64(len(entry.content))
		}
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if transform != nil {
		manifestBytes = transform(manifestBytes)
	}
	raw := tarFixture(t, entries, manifestBytes)
	digest := payloadDigest(t, raw)
	replaced := bytes.Replace(raw, []byte(strings.Repeat("0", sha256.Size*2)), []byte(digest), 1)
	if bytes.Equal(raw, replaced) {
		t.Fatal("manifest payload digest placeholder was not found")
	}
	manifest.PayloadSHA256 = digest
	return gzipFixture(t, replaced), manifest
}

func tarFixture(t *testing.T, entries []fixtureEntry, manifest []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.content)), Typeflag: entry.typeflag}
		if entry.typeflag == tar.TypeDir {
			header.Mode = 0700
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.content) > 0 {
			if _, err := writer.Write(entry.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func payloadDigest(t *testing.T, raw []byte) string {
	t.Helper()
	offset := 0
	manifestStart, manifestEnd := -1, -1
	for offset+int(tarBlockSize) <= len(raw) {
		header := raw[offset : offset+int(tarBlockSize)]
		if bytes.Equal(header, make([]byte, tarBlockSize)) {
			break
		}
		member, err := parseTarHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		padded, err := paddedTarSize(member.size, MaxCollectorArchiveBytes)
		if err != nil {
			t.Fatal(err)
		}
		end := offset + int(tarBlockSize+padded)
		if member.name == "manifest.json" {
			manifestStart, manifestEnd = offset, end
		}
		offset = end
	}
	if manifestStart < 0 || offset+int(2*tarBlockSize) != len(raw) {
		t.Fatalf("unexpected fixture tar framing: manifest=%d offset=%d len=%d", manifestStart, offset, len(raw))
	}
	hash := sha256.New()
	_, _ = hash.Write(raw[:manifestStart])
	_, _ = hash.Write(raw[manifestEnd:])
	return hex.EncodeToString(hash.Sum(nil))
}

func gzipFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Header.ModTime = time.Unix(0, 0)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func ungzipFixture(t *testing.T, compressed []byte) []byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateTarTypeflag(t *testing.T, compressed []byte, name string, typeflag byte) []byte {
	t.Helper()
	raw := ungzipFixture(t, compressed)
	for offset := 0; offset+int(tarBlockSize) <= len(raw); {
		header := raw[offset : offset+int(tarBlockSize)]
		if allZero(header) {
			break
		}
		member, err := parseTarHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		padded, err := paddedTarSize(member.size, MaxCollectorArchiveBytes)
		if err != nil {
			t.Fatal(err)
		}
		if member.name == name {
			header[156] = typeflag
			writeTarChecksum(t, header)
			return gzipFixture(t, raw)
		}
		offset += int(tarBlockSize + padded)
	}
	t.Fatalf("tar member %q not found", name)
	return nil
}

func writeTarChecksum(t *testing.T, header []byte) {
	t.Helper()
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, value := range header {
		sum += int64(value)
	}
	digits := []byte("000000")
	for index := len(digits) - 1; index >= 0 && sum > 0; index-- {
		digits[index] = byte('0' + sum%8)
		sum /= 8
	}
	if sum != 0 {
		t.Fatal("tar checksum exceeds the fixture field")
	}
	copy(header[148:154], digits)
	header[154] = 0
	header[155] = ' '
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func mustDescriptor(t *testing.T, expected Expected) descriptor {
	t.Helper()
	descriptor, err := descriptorFor(expected.Recipe, expected.RecipeVersion)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

type cancelDuringValidation struct {
	io.ReadSeeker
	cancel     context.CancelFunc
	cancelSeek int
	cancelRead int
	seeks      int
	reads      int
}

func (staged *cancelDuringValidation) Seek(offset int64, whence int) (int64, error) {
	staged.seeks++
	if staged.seeks == staged.cancelSeek {
		staged.cancel()
	}
	return staged.ReadSeeker.Seek(offset, whence)
}

func (staged *cancelDuringValidation) Read(value []byte) (int, error) {
	staged.reads++
	if staged.reads == staged.cancelRead {
		staged.cancel()
	}
	return staged.ReadSeeker.Read(value)
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/internal/strictjson"
)

const (
	SchemaV1                     = "diagnostic-artifact/v1"
	SystemSummaryRecipe          = "system-summary.v1"
	CrashdumpCollectionRecipe    = "crashdump-collection.v1"
	ExitSemanticsCompleteOnly    = "0=complete; non-zero=not published"
	ArchiveFormatTarGzip         = "tar.gz"
	MaxManifestBytes             = 32 << 10
	MaxCollectorArchiveBytes     = 512 << 20
	MaxSystemSummaryArchiveBytes = 16 << 20
)

// Manifest is diagnostic-artifact/v1 exactly as emitted by the baked
// collector. Pointer fields preserve explicit null/absence semantics.
type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Recipe        string `json:"recipe"`
	RecipeVersion int    `json:"recipe_version"`
	ArtifactID    string `json:"artifact_id"`
	Session       struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		UID       string `json:"uid"`
	} `json:"session"`
	Redaction struct {
		Profile string `json:"profile"`
		Version int    `json:"version"`
	} `json:"redaction"`
	Node            *string  `json:"node"`
	ArchiveFormat   string   `json:"archive_format"`
	Inputs          Inputs   `json:"inputs"`
	DeclaredOutputs []string `json:"declared_outputs"`
	PayloadSHA256   string   `json:"payload_sha256"`
	FileCount       int64    `json:"file_count"`
	Bytes           int64    `json:"bytes"`
	ExitCode        int      `json:"exit_code"`
	ExitSemantics   string   `json:"exit_semantics"`
}

// Inputs is the closed union of fields used by collector-v1 descriptors.
type Inputs struct {
	MaxArchiveBytes int64   `json:"maxArchiveBytes"`
	MaxAgeMinutes   *int64  `json:"maxAgeMinutes"`
	Node            *string `json:"node"`
	DetailLevel     *string `json:"detailLevel"`
}

// Expected is the immutable server-side binding used to validate a manifest.
type Expected struct {
	Recipe           string
	RecipeVersion    int
	ArtifactID       string
	SessionNamespace string
	SessionName      string
	SessionUID       string
	RedactionProfile string
	RedactionVersion int
	Node             *string
	Inputs           Inputs
}

type descriptor struct {
	recipe              string
	version             int
	maxArchiveBytes     int64
	declaredOutputs     []string
	requiredPayload     string
	requiredDirectories map[string]struct{}
	payloadPrefix       string
}

func descriptorFor(recipe string, version int) (descriptor, error) {
	switch {
	case recipe == SystemSummaryRecipe && version == 1:
		return descriptor{
			recipe: recipe, version: version, maxArchiveBytes: MaxSystemSummaryArchiveBytes,
			declaredOutputs:     []string{"files/system-summary.json", "manifest.json", "stderr.log", "stdout.log"},
			requiredPayload:     "files/system-summary.json",
			requiredDirectories: map[string]struct{}{"files": {}},
		}, nil
	case recipe == CrashdumpCollectionRecipe && version == 1:
		return descriptor{
			recipe: recipe, version: version, maxArchiveBytes: MaxCollectorArchiveBytes,
			declaredOutputs:     []string{"files/coredumps/", "manifest.json", "stderr.log", "stdout.log"},
			requiredDirectories: map[string]struct{}{"files": {}, "files/coredumps": {}},
			payloadPrefix:       "files/coredumps/",
		}, nil
	default:
		return descriptor{}, errors.New("artifact recipe descriptor is not allowlisted")
	}
}

func parseAndValidateManifest(data []byte, expected Expected) (Manifest, descriptor, error) {
	var manifest Manifest
	if err := strictjson.Decode(data, MaxManifestBytes, &manifest); err != nil {
		return manifest, descriptor{}, fmt.Errorf("artifact manifest is invalid: %w", err)
	}
	descriptor, err := descriptorFor(expected.Recipe, expected.RecipeVersion)
	if err != nil {
		return manifest, descriptor, err
	}
	if err := validateManifestContract(manifest, descriptor); err != nil {
		return manifest, descriptor, err
	}
	if !manifestMatchesExpected(manifest, expected) {
		return manifest, descriptor, errors.New("artifact manifest does not match the runtime binding")
	}
	return manifest, descriptor, nil
}

func validateManifestContract(manifest Manifest, descriptor descriptor) error {
	if manifest.SchemaVersion != SchemaV1 || manifest.Recipe != descriptor.recipe ||
		manifest.RecipeVersion != descriptor.version || manifest.ArchiveFormat != ArchiveFormatTarGzip ||
		manifest.ExitCode != 0 || manifest.ExitSemantics != ExitSemanticsCompleteOnly ||
		len(manifest.PayloadSHA256) != sha256.Size*2 || manifest.FileCount < 0 || manifest.Bytes < 0 {
		return errors.New("artifact manifest identity is invalid")
	}
	if !validArtifactID(manifest.ArtifactID) || !validDNSName(manifest.Session.Namespace, 63) ||
		!validDNSName(manifest.Session.Name, 253) || !validOpaqueIdentity(manifest.Session.UID, 128) ||
		!validRedactionProfile(manifest.Redaction.Profile) || manifest.Redaction.Version < 1 ||
		manifest.Redaction.Version > 9999 || !validDeclaredOutputs(manifest.DeclaredOutputs) {
		return errors.New("artifact manifest authorization identity is invalid")
	}
	decoded, err := hex.DecodeString(manifest.PayloadSHA256)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(manifest.PayloadSHA256) != manifest.PayloadSHA256 {
		return errors.New("artifact manifest payload checksum is invalid")
	}
	if !sameStrings(manifest.DeclaredOutputs, descriptor.declaredOutputs) ||
		manifest.Inputs.MaxArchiveBytes < 1 || manifest.Inputs.MaxArchiveBytes > descriptor.maxArchiveBytes {
		return errors.New("artifact manifest recipe contract is invalid")
	}
	switch descriptor.recipe {
	case SystemSummaryRecipe:
		if manifest.Node != nil || manifest.Inputs.Node != nil || manifest.Inputs.MaxAgeMinutes != nil ||
			manifest.Inputs.DetailLevel == nil ||
			(*manifest.Inputs.DetailLevel != "basic" && *manifest.Inputs.DetailLevel != "extended") {
			return errors.New("artifact manifest does not match the system summary descriptor")
		}
	case CrashdumpCollectionRecipe:
		if manifest.Node == nil || *manifest.Node == "" || manifest.Inputs.Node == nil ||
			*manifest.Inputs.Node != *manifest.Node || manifest.Inputs.MaxAgeMinutes == nil ||
			*manifest.Inputs.MaxAgeMinutes < 1 || *manifest.Inputs.MaxAgeMinutes > 10080 ||
			manifest.Inputs.DetailLevel != nil {
			return errors.New("artifact manifest does not match the crashdump descriptor")
		}
	default:
		return errors.New("artifact manifest recipe is not allowlisted")
	}
	return nil
}

func manifestMatchesExpected(manifest Manifest, expected Expected) bool {
	return manifest.Recipe == expected.Recipe && manifest.RecipeVersion == expected.RecipeVersion &&
		manifest.ArtifactID == expected.ArtifactID && manifest.Session.Namespace == expected.SessionNamespace &&
		manifest.Session.Name == expected.SessionName && manifest.Session.UID == expected.SessionUID &&
		manifest.Redaction.Profile == expected.RedactionProfile && manifest.Redaction.Version == expected.RedactionVersion &&
		sameOptionalString(manifest.Node, expected.Node) && sameInputs(manifest.Inputs, expected.Inputs)
}

func sameInputs(left, right Inputs) bool {
	return left.MaxArchiveBytes == right.MaxArchiveBytes && sameOptionalInt64(left.MaxAgeMinutes, right.MaxAgeMinutes) &&
		sameOptionalString(left.Node, right.Node) && sameOptionalString(left.DetailLevel, right.DetailLevel)
}

func sameOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range right {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validArtifactID(value string) bool {
	if len(value) != len("dsa-")+24 || !strings.HasPrefix(value, "dsa-") {
		return false
	}
	for _, character := range value[len("dsa-"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validDNSName(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !isDNSAlphaNumeric(rune(label[0])) ||
			!isDNSAlphaNumeric(rune(label[len(label)-1])) {
			return false
		}
		for _, character := range label {
			if !isDNSAlphaNumeric(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func isDNSAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func validOpaqueIdentity(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

func validRedactionProfile(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._-", character) {
			return false
		}
	}
	return true
}

func validDeclaredOutputs(outputs []string) bool {
	if len(outputs) == 0 || len(outputs) > 32 {
		return false
	}
	for index, output := range outputs {
		if len(output) == 0 || len(output) > 512 || strings.HasPrefix(output, "/") || strings.Contains(output, "//") {
			return false
		}
		clean := strings.TrimSuffix(output, "/")
		if clean == "" || strings.Contains(clean, "\\") || path.Clean(clean) != clean ||
			strings.HasPrefix(clean, "../") || clean == ".." || index > 0 && outputs[index-1] >= output {
			return false
		}
	}
	return true
}

package v1alpha1

import (
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Default data keys used when a SecretKeyReference omits its Key field.
//
// Historically each call site inlined its own default string, which drifted
// apart: the TOFU CA was written under "ca.crt" but read back under "value",
// and refresh-token rotation was validated against "value" while the runtime
// read and wrote "token". A CA that was written under one key and looked up
// under another is never re-read, so TOFU pinning silently re-bootstrapped
// trust on every controller restart. These constants are the single source of
// truth for every write, read and validation path.
const (
	// DefaultSecretKey is the generic default documented on
	// SecretKeyReference.Key ("defaults to \"value\" if not specified").
	// It applies to references that carry no more specific default, such as
	// clientSecretRef.
	DefaultSecretKey = "value"

	// DefaultCASecretKey is the canonical default key for caSecretRef. It
	// matches the key that TOFU has always *written* and that the pre-flight
	// checker has always looked for, and is the value documented in
	// docs/cluster-config.md.
	DefaultCASecretKey = "ca.crt"

	// LegacyCASecretKey is the key that OIDCTokenProvider.configureTLS used to
	// *read* the CA from when caSecretRef.key was omitted. Clusters provisioned
	// against that behaviour may still hold a correctly pinned CA under this
	// key, so reads fall back to it. Reads from the legacy key are reported
	// loudly and migrated on the next write; writes always use
	// DefaultCASecretKey.
	LegacyCASecretKey = DefaultSecretKey

	// DefaultRefreshTokenSecretKey is the runtime default key for
	// refreshTokenSecretRef and subjectTokenSecretRef. The runtime has always
	// used "token" here; admission previously validated
	// rotatedRefreshTokenKey against DefaultSecretKey instead, so
	// `rotatedRefreshTokenKey: token` with an omitted key was accepted as a
	// distinct key while the runtime aliased both onto "token" and overwrote
	// the seed token.
	DefaultRefreshTokenSecretKey = "token"
)

// ResolveSecretKey returns the effective data key for a reference, using
// fallback when the reference omits an explicit key.
func ResolveSecretKey(ref *SecretKeyReference, fallback string) string {
	if ref == nil || ref.Key == "" {
		return fallback
	}
	return ref.Key
}

// ReservedRefreshTokenKeys returns every data key that the refresh-token read
// and write paths may resolve ref to. rotatedRefreshTokenKey must not collide
// with any of them, otherwise a rotated token overwrites the seed token and
// spoke access can be lost permanently once the rotated token expires.
//
// When an explicit key is set, only that key is reserved. When it is omitted,
// both the runtime default ("token") and the generic default ("value") are
// reserved: keeping "value" reserved means this check is never looser than the
// previous behaviour, which only rejected "value".
func ReservedRefreshTokenKeys(ref *SecretKeyReference) []string {
	if ref != nil && ref.Key != "" {
		return []string{ref.Key}
	}
	return []string{DefaultRefreshTokenSecretKey, DefaultSecretKey}
}

// validateRotatedRefreshTokenKey rejects a rotatedRefreshTokenKey that aliases
// any key the seed token may be read from. Returns nil when the key is safe.
func validateRotatedRefreshTokenKey(rotatedKey string, ref *SecretKeyReference, fieldPath *field.Path) *field.Error {
	reserved := ReservedRefreshTokenKeys(ref)
	if !slices.Contains(reserved, rotatedKey) {
		return nil
	}
	return field.Invalid(fieldPath.Child("rotatedRefreshTokenKey"), rotatedKey,
		fmt.Sprintf("must differ from the key in refreshTokenSecretRef to avoid overwriting the original token "+
			"(reserved seed-token keys: %s)", strings.Join(reserved, ", ")))
}

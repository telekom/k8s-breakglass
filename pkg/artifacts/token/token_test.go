// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyExactClaims(t *testing.T) {
	keyring := testKeyring(t, "new", []Key{
		{ID: "old", Secret: bytesOf('o', minimumKeyBytes)},
		{ID: "new", Secret: bytesOf('n', minimumKeyBytes)},
	})
	claims := testClaims(t)
	encoded, err := keyring.Sign(claims)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(encoded) > defaultMaxToken {
		t.Fatalf("Sign() token length = %d", len(encoded))
	}
	verified, err := keyring.Verify(encoded, claims.NotBefore)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.KeyID != "new" || verified.JTI != claims.JTI ||
		verified.RuntimeBindingDigest != claims.RuntimeBindingDigest || verified.Route != claims.Route {
		t.Fatalf("Verify() claims = %#v", verified)
	}
}

func TestVerifyRejectsTamperingAndWireAmbiguity(t *testing.T) {
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	claims := testClaims(t)
	encoded, err := keyring.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, ".")

	tests := map[string]string{
		"payload tamper":   parts[0] + "." + mutateSegment(t, parts[1], `"recipe":"system-summary.v1"`, `"recipe":"other.v1"`) + "." + parts[2],
		"signature tamper": parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(bytesOf('x', sha256.Size)),
		"extra segment":    encoded + ".extra",
		"padding":          parts[0] + "=." + parts[1] + "." + parts[2],
		"whitespace":       " " + encoded,
		"oversized":        strings.Repeat("a", defaultMaxToken+1),
		"unknown header":   signedMutation(t, keyring, parts, 0, `,"extra":true`),
		"duplicate header": signedMutation(t, keyring, parts, 0, `,"alg":"HS256"`),
		"unknown claim":    signedMutation(t, keyring, parts, 1, `,"extra":true`),
		"duplicate claim":  signedMutation(t, keyring, parts, 1, `,"aud":"artifact-upload"`),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := keyring.Verify(candidate, claims.NotBefore); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifyRejectsAlgorithmNegotiation(t *testing.T) {
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	claims := testClaims(t)
	encoded, err := keyring.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, ".")
	for _, algorithm := range []string{"none", "HS512", "hs256"} {
		mutated := append([]string(nil), parts...)
		mutated[0] = mutateSegment(t, parts[0], `"alg":"HS256"`, `"alg":"`+algorithm+`"`)
		unsigned := mutated[0] + "." + mutated[1]
		mutated[2] = base64.RawURLEncoding.EncodeToString(sign(keyring.keys["active"], unsigned))
		candidate := strings.Join(mutated, ".")
		if _, err := keyring.Verify(candidate, claims.NotBefore); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Verify(%q) error = %v", algorithm, err)
		}
	}
}

func TestVerifyUsesInclusiveTimeBoundaries(t *testing.T) {
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	claims := testClaims(t)
	encoded, err := keyring.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Verify(encoded, claims.NotBefore.Add(-time.Second)); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("before nbf error = %v", err)
	}
	if _, err := keyring.Verify(encoded, claims.ExpiresAt.Add(-time.Second)); err != nil {
		t.Fatalf("before expiry error = %v", err)
	}
	if _, err := keyring.Verify(encoded, claims.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry error = %v", err)
	}
}

func TestKeyAndJTICryptographicFloors(t *testing.T) {
	if _, err := NewKeyring("issuer", "audience", "weak", []Key{{ID: "weak", Secret: bytesOf('x', minimumKeyBytes-1)}}, Limits{MaxTTL: time.Hour}); err == nil {
		t.Fatal("NewKeyring() accepted a weak key")
	}
	generated, err := GenerateJTI()
	if err != nil {
		t.Fatalf("GenerateJTI() error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(generated)
	if err != nil || len(decoded)*8 < minimumJTIBits {
		t.Fatalf("GenerateJTI() = %q, decoded=%d, error=%v", generated, len(decoded), err)
	}
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	claims := testClaims(t)
	claims.JTI = base64.RawURLEncoding.EncodeToString(bytesOf('j', minimumJTIBits/8-1))
	if _, err := keyring.Sign(claims); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Sign() weak JTI error = %v", err)
	}
}

func TestKeyringRejectsWireLimitWideningAndEmptyVerifierSet(t *testing.T) {
	key := Key{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}
	for name, limits := range map[string]Limits{
		"token":   {MaxTokenBytes: defaultMaxToken + 1, MaxTTL: time.Minute},
		"segment": {MaxSegmentBytes: defaultMaxSegment + 1, MaxTTL: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewKeyring("issuer", "audience", "active", []Key{key}, limits); err == nil {
				t.Fatal("NewKeyring() widened the fixed token bounds")
			}
		})
	}
	if _, err := NewKeyring("issuer", "audience", "", nil, Limits{MaxTTL: time.Minute}); err == nil {
		t.Fatal("NewKeyring() accepted an empty verifier set")
	}
}

func TestClaimsBindCanonicalRouteAndIdentity(t *testing.T) {
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	for name, mutate := range map[string]func(*Claims){
		"route":        func(claims *Claims) { claims.Route += "/other" },
		"namespace":    func(claims *Claims) { claims.SessionNamespace = "Other" },
		"digest case":  func(claims *Claims) { claims.ArtifactPlanDigest = strings.ToUpper(claims.ArtifactPlanDigest) },
		"node absence": func(claims *Claims) { claims.NodePresent = false },
		"zero epoch":   func(claims *Claims) { claims.OperationEpoch = 0 },
		"artifact ID":  func(claims *Claims) { claims.ArtifactID = "forged" },
	} {
		t.Run(name, func(t *testing.T) {
			claims := testClaims(t)
			mutate(&claims)
			if _, err := keyring.Sign(claims); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Sign() error = %v", err)
			}
		})
	}
}

func TestRotationCoverageAndRetirementDeadline(t *testing.T) {
	keyring := testKeyring(t, "new", []Key{
		{ID: "old", Secret: bytesOf('o', minimumKeyBytes)},
		{ID: "new", Secret: bytesOf('n', minimumKeyBytes)},
	})
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	references := []KeyReference{
		{KeyID: "old", TokenExpiry: now.Add(time.Minute), LeaseDeadline: now.Add(2 * time.Minute), Active: true},
		{KeyID: "old", TokenExpiry: now.Add(3 * time.Minute), LeaseDeadline: now.Add(time.Minute), Active: true},
		{KeyID: "missing", Active: false},
	}
	if err := keyring.ValidateKeyCoverage(references); err != nil {
		t.Fatalf("ValidateKeyCoverage() error = %v", err)
	}
	deadline := RetirementDeadline("old", references, 30*time.Second)
	if want := now.Add(3*time.Minute + 30*time.Second); !deadline.Equal(want) {
		t.Fatalf("RetirementDeadline() = %v, want %v", deadline, want)
	}
	missing := append(references, KeyReference{KeyID: "removed", Active: true})
	if err := keyring.ValidateKeyCoverage(missing); err == nil {
		t.Fatal("ValidateKeyCoverage() accepted a removed active key")
	}
}

func testKeyring(t *testing.T, signer string, keys []Key) *Keyring {
	t.Helper()
	keyring, err := NewKeyring("https://breakglass.example", "artifact-upload", signer, keys, Limits{MaxTTL: 10 * time.Minute})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func testClaims(t *testing.T) Claims {
	t.Helper()
	jti, err := GenerateJTI()
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	claims := Claims{
		JTI: jti, IssuedAt: issued, NotBefore: issued.Add(time.Second), ExpiresAt: issued.Add(5 * time.Minute),
		Method: "PUT", SessionNamespace: "support", SessionName: "session-one",
		SessionUID: "11111111-2222-3333-4444-555555555555", ArtifactID: "dsa-0123456789abcdef01234567",
		ArtifactPlanDigest: strings.Repeat("a", sha256.Size*2), RuntimeBindingDigest: strings.Repeat("b", sha256.Size*2),
		OperationEpoch: 1, TargetIdentityDigest: strings.Repeat("c", sha256.Size*2),
		Recipe: "system-summary.v1", RecipeVersion: 1, Node: "worker-one", NodePresent: true,
	}
	claims.Route = CanonicalUploadRoute(claims)
	return claims
}

func bytesOf(value byte, count int) []byte {
	return []byte(strings.Repeat(string(value), count))
}

func mutateSegment(t *testing.T, segment, old, replacement string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(decoded), old, replacement, 1)
	if mutated == string(decoded) {
		t.Fatalf("mutation source %q not found in %s", old, decoded)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(mutated))
}

func signedMutation(t *testing.T, keyring *Keyring, parts []string, index int, suffix string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) == 0 || decoded[len(decoded)-1] != '}' {
		t.Fatalf("unexpected JSON segment %q", decoded)
	}
	decoded = append(decoded[:len(decoded)-1], []byte(suffix+"}")...)
	mutated := append([]string(nil), parts...)
	mutated[index] = base64.RawURLEncoding.EncodeToString(decoded)
	unsigned := mutated[0] + "." + mutated[1]
	mutated[2] = base64.RawURLEncoding.EncodeToString(sign(keyring.keys["active"], unsigned))
	return strings.Join(mutated, ".")
}

func TestWireJSONIsCanonicalAndStrict(t *testing.T) {
	keyring := testKeyring(t, "active", []Key{{ID: "active", Secret: bytesOf('k', minimumKeyBytes)}})
	claims := testClaims(t)
	encoded, err := keyring.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, ".")
	for _, segment := range parts[:2] {
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(decoded, &value); err != nil {
			t.Fatalf("wire JSON error = %v", err)
		}
		if strings.ContainsAny(string(decoded), "\n\r\t ") {
			t.Fatalf("wire JSON is not compact: %q", decoded)
		}
	}
}

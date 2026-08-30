// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package token implements the fixed diagnostic-artifact upload token wire
// format. It intentionally does not support algorithm negotiation.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/internal/strictjson"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	wireAlgorithm      = "HS256"
	wireType           = "BGART+JWT"
	wireVersion        = 1
	claimsVersion      = "diagnostic-artifact-upload/v1"
	defaultMaxToken    = 4096
	defaultMaxSegment  = 3072
	minimumKeyBytes    = 32
	minimumJTIBits     = 128
	maximumJTIBytes    = 32
	maximumKeyIDBytes  = 64
	maximumStringBytes = 256
)

var (
	// ErrInvalid is returned for malformed, unauthenticated, or contract-drifted
	// tokens. Callers must not use its wrapped details in public responses.
	ErrInvalid = errors.New("artifact upload token is invalid")
	// ErrExpired is returned at the inclusive expiry boundary.
	ErrExpired = errors.New("artifact upload token is expired")
	// ErrNotYetValid is returned before the exact not-before instant.
	ErrNotYetValid = errors.New("artifact upload token is not yet valid")
)

// Key is one HMAC verifier key. Secret must contain at least 32 CSPRNG bytes.
type Key struct {
	ID     string
	Secret []byte
}

// Limits bounds the authenticated token before any external lookup occurs.
type Limits struct {
	MaxTokenBytes   int
	MaxSegmentBytes int
	MaxTTL          time.Duration
}

// Claims are the complete authenticated upload authority.
type Claims struct {
	KeyID                string
	JTI                  string
	IssuedAt             time.Time
	NotBefore            time.Time
	ExpiresAt            time.Time
	Method               string
	Route                string
	SessionNamespace     string
	SessionName          string
	SessionUID           string
	ArtifactID           string
	ArtifactPlanDigest   string
	RuntimeBindingDigest string
	OperationEpoch       uint64
	TargetIdentityDigest string
	Recipe               string
	RecipeVersion        int
	Node                 string
	NodePresent          bool
}

type header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
	Version   int    `json:"v"`
}

type payload struct {
	Version              string `json:"version"`
	Issuer               string `json:"iss"`
	Audience             string `json:"aud"`
	JTI                  string `json:"jti"`
	IssuedAt             int64  `json:"iat"`
	NotBefore            int64  `json:"nbf"`
	ExpiresAt            int64  `json:"exp"`
	Method               string `json:"method"`
	Route                string `json:"route"`
	SessionNamespace     string `json:"session_namespace"`
	SessionName          string `json:"session_name"`
	SessionUID           string `json:"session_uid"`
	ArtifactID           string `json:"artifact_id"`
	ArtifactPlanDigest   string `json:"artifact_plan_sha256"`
	RuntimeBindingDigest string `json:"runtime_binding_sha256"`
	OperationEpoch       uint64 `json:"operation_epoch"`
	TargetIdentityDigest string `json:"target_identity_sha256"`
	Recipe               string `json:"recipe"`
	RecipeVersion        int    `json:"recipe_version"`
	Node                 string `json:"node"`
	NodePresent          bool   `json:"node_present"`
}

// Keyring signs with one key and verifies every configured rollout key.
type Keyring struct {
	issuer   string
	audience string
	signer   string
	keys     map[string][]byte
	limits   Limits
}

// NewKeyring constructs a keyring. signer may be empty for a verifier-only
// rollout stage.
func NewKeyring(issuer, audience, signer string, keys []Key, limits Limits) (*Keyring, error) {
	if !boundedASCII(issuer, maximumStringBytes) || !boundedASCII(audience, maximumStringBytes) {
		return nil, errors.New("artifact token issuer and audience are required bounded ASCII")
	}
	limits = normalizeLimits(limits)
	if limits.MaxTTL <= 0 || limits.MaxTokenBytes < 1 || limits.MaxTokenBytes > defaultMaxToken ||
		limits.MaxSegmentBytes < 1 || limits.MaxSegmentBytes > defaultMaxSegment ||
		limits.MaxSegmentBytes > limits.MaxTokenBytes {
		return nil, errors.New("artifact token limits are outside the fixed wire bounds")
	}
	if len(keys) == 0 {
		return nil, errors.New("artifact token verifier keyring is empty")
	}
	keyring := &Keyring{
		issuer: issuer, audience: audience, signer: signer,
		keys: make(map[string][]byte, len(keys)), limits: limits,
	}
	for _, key := range keys {
		if !validKeyID(key.ID) || len(key.Secret) < minimumKeyBytes {
			return nil, errors.New("artifact token key is outside the cryptographic floor")
		}
		if _, duplicate := keyring.keys[key.ID]; duplicate {
			return nil, errors.New("artifact token key ID is duplicated")
		}
		keyring.keys[key.ID] = append([]byte(nil), key.Secret...)
	}
	if signer != "" {
		if _, found := keyring.keys[signer]; !found {
			return nil, errors.New("artifact token signer is not in the verifier keyring")
		}
	}
	return keyring, nil
}

// GenerateJTI returns a canonical 128-bit CSPRNG identifier.
func GenerateJTI() (string, error) {
	random := make([]byte, minimumJTIBits/8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate artifact token JTI: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// Sign authenticates claims with the configured signer. Issuer, audience,
// version, algorithm, and key ID are controller-owned.
func (keyring *Keyring) Sign(claims Claims) (string, error) {
	if keyring == nil || keyring.signer == "" {
		return "", errors.New("artifact token signer is unavailable")
	}
	claims.KeyID = keyring.signer
	if err := keyring.validateClaims(claims); err != nil {
		return "", err
	}
	headerBytes, err := json.Marshal(header{wireAlgorithm, keyring.signer, wireType, wireVersion})
	if err != nil {
		return "", fmt.Errorf("marshal artifact token header: %w", err)
	}
	payloadBytes, err := json.Marshal(toPayload(keyring.issuer, keyring.audience, claims))
	if err != nil {
		return "", fmt.Errorf("marshal artifact token claims: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := encodedHeader + "." + encodedPayload
	signature := sign(keyring.keys[keyring.signer], unsigned)
	encoded := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) > keyring.limits.MaxTokenBytes {
		return "", errors.New("artifact token exceeds its bounded wire size")
	}
	return encoded, nil
}

// Verify authenticates and validates a token at the injected UTC instant.
func (keyring *Keyring) Verify(encoded string, now time.Time) (Claims, error) {
	var empty Claims
	if keyring == nil || len(encoded) == 0 || len(encoded) > keyring.limits.MaxTokenBytes {
		return empty, ErrInvalid
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		return empty, ErrInvalid
	}
	decoded := make([][]byte, 3)
	for index, part := range parts {
		if len(part) == 0 || len(part) > keyring.limits.MaxSegmentBytes {
			return empty, ErrInvalid
		}
		value, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(value) != part {
			return empty, ErrInvalid
		}
		decoded[index] = value
	}
	var tokenHeader header
	if err := strictjson.Decode(decoded[0], keyring.limits.MaxSegmentBytes, &tokenHeader); err != nil {
		return empty, ErrInvalid
	}
	if tokenHeader.Algorithm != wireAlgorithm || tokenHeader.Type != wireType ||
		tokenHeader.Version != wireVersion || !validKeyID(tokenHeader.KeyID) {
		return empty, ErrInvalid
	}
	secret, found := keyring.keys[tokenHeader.KeyID]
	if !found || len(decoded[2]) != sha256.Size {
		return empty, ErrInvalid
	}
	unsigned := parts[0] + "." + parts[1]
	if !hmac.Equal(sign(secret, unsigned), decoded[2]) {
		return empty, ErrInvalid
	}
	var wireClaims payload
	if err := strictjson.Decode(decoded[1], keyring.limits.MaxSegmentBytes, &wireClaims); err != nil {
		return empty, ErrInvalid
	}
	if wireClaims.Version != claimsVersion || wireClaims.Issuer != keyring.issuer ||
		wireClaims.Audience != keyring.audience {
		return empty, ErrInvalid
	}
	claims := fromPayload(tokenHeader.KeyID, wireClaims)
	if err := keyring.validateClaims(claims); err != nil {
		return empty, ErrInvalid
	}
	now = now.UTC()
	if now.Before(claims.NotBefore) {
		return empty, ErrNotYetValid
	}
	if !now.Before(claims.ExpiresAt) {
		return empty, ErrExpired
	}
	return claims, nil
}

func (keyring *Keyring) validateClaims(claims Claims) error {
	if claims.KeyID == "" || claims.KeyID != keyring.signer && keyring.signer != "" {
		if _, found := keyring.keys[claims.KeyID]; !found {
			return ErrInvalid
		}
	}
	if !validJTI(claims.JTI) || claims.Method != http.MethodPut ||
		claims.Route != CanonicalUploadRoute(claims) ||
		len(validation.IsDNS1123Label(claims.SessionNamespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(claims.SessionName)) != 0 ||
		!validIdentity(claims.SessionUID, 128) || !validArtifactID(claims.ArtifactID) ||
		!validDigest(claims.ArtifactPlanDigest) || !validDigest(claims.RuntimeBindingDigest) ||
		!validDigest(claims.TargetIdentityDigest) || claims.OperationEpoch == 0 ||
		!validIdentity(claims.Recipe, 128) || claims.RecipeVersion < 1 || claims.RecipeVersion > 9999 {
		return ErrInvalid
	}
	if claims.NodePresent {
		if len(validation.IsDNS1123Subdomain(claims.Node)) != 0 {
			return ErrInvalid
		}
	} else if claims.Node != "" {
		return ErrInvalid
	}
	issuedAt := claims.IssuedAt.UTC()
	notBefore := claims.NotBefore.UTC()
	expiresAt := claims.ExpiresAt.UTC()
	if issuedAt.IsZero() || notBefore.IsZero() || expiresAt.IsZero() ||
		issuedAt.Nanosecond() != 0 || notBefore.Nanosecond() != 0 || expiresAt.Nanosecond() != 0 ||
		issuedAt.After(notBefore) || !notBefore.Before(expiresAt) ||
		expiresAt.Sub(issuedAt) > keyring.limits.MaxTTL {
		return ErrInvalid
	}
	return nil
}

// CanonicalUploadRoute returns the only route a token may authorize.
func CanonicalUploadRoute(claims Claims) string {
	return "/api/debugSessionArtifactUploads/" + claims.SessionNamespace + "/" +
		claims.SessionName + "/" + claims.ArtifactID
}

func sign(secret []byte, unsigned string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	return mac.Sum(nil)
}

func toPayload(issuer, audience string, claims Claims) payload {
	return payload{
		Version: claimsVersion, Issuer: issuer, Audience: audience, JTI: claims.JTI,
		IssuedAt: claims.IssuedAt.UTC().Unix(), NotBefore: claims.NotBefore.UTC().Unix(),
		ExpiresAt: claims.ExpiresAt.UTC().Unix(), Method: claims.Method, Route: claims.Route,
		SessionNamespace: claims.SessionNamespace, SessionName: claims.SessionName,
		SessionUID: claims.SessionUID, ArtifactID: claims.ArtifactID,
		ArtifactPlanDigest: claims.ArtifactPlanDigest, RuntimeBindingDigest: claims.RuntimeBindingDigest,
		OperationEpoch: claims.OperationEpoch, TargetIdentityDigest: claims.TargetIdentityDigest,
		Recipe: claims.Recipe, RecipeVersion: claims.RecipeVersion,
		Node: claims.Node, NodePresent: claims.NodePresent,
	}
}

func fromPayload(keyID string, claims payload) Claims {
	return Claims{
		KeyID: keyID, JTI: claims.JTI, IssuedAt: time.Unix(claims.IssuedAt, 0).UTC(),
		NotBefore: time.Unix(claims.NotBefore, 0).UTC(), ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
		Method: claims.Method, Route: claims.Route, SessionNamespace: claims.SessionNamespace,
		SessionName: claims.SessionName, SessionUID: claims.SessionUID, ArtifactID: claims.ArtifactID,
		ArtifactPlanDigest: claims.ArtifactPlanDigest, RuntimeBindingDigest: claims.RuntimeBindingDigest,
		OperationEpoch: claims.OperationEpoch, TargetIdentityDigest: claims.TargetIdentityDigest,
		Recipe: claims.Recipe, RecipeVersion: claims.RecipeVersion,
		Node: claims.Node, NodePresent: claims.NodePresent,
	}
}

func normalizeLimits(limits Limits) Limits {
	if limits.MaxTokenBytes == 0 {
		limits.MaxTokenBytes = defaultMaxToken
	}
	if limits.MaxSegmentBytes == 0 {
		limits.MaxSegmentBytes = defaultMaxSegment
	}
	return limits
}

func validKeyID(value string) bool {
	if len(value) == 0 || len(value) > maximumKeyIDBytes {
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

func validJTI(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && base64.RawURLEncoding.EncodeToString(decoded) == value &&
		len(decoded) >= minimumJTIBits/8 && len(decoded) <= maximumJTIBytes
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
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

func validIdentity(value string, maximum int) bool {
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

func boundedASCII(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

// KeyReference is durable Pending/Uploading work that keeps a verifier key in
// the rollout keyring until every token and transfer drain has passed.
type KeyReference struct {
	KeyID         string
	TokenExpiry   time.Time
	LeaseDeadline time.Time
	Active        bool
}

// ValidateKeyCoverage rejects startup when active work references a missing
// verifier key.
func (keyring *Keyring) ValidateKeyCoverage(references []KeyReference) error {
	for _, reference := range references {
		if !reference.Active {
			continue
		}
		if _, found := keyring.keys[reference.KeyID]; !found {
			return fmt.Errorf("active artifact token references unavailable key %q", reference.KeyID)
		}
	}
	return nil
}

// RetirementDeadline returns the earliest safe verifier-key retirement time.
// The caller must also ensure every replica has observed the new keyring.
func RetirementDeadline(keyID string, references []KeyReference, lateDrain time.Duration) time.Time {
	var deadline time.Time
	for _, reference := range references {
		if !reference.Active || reference.KeyID != keyID {
			continue
		}
		candidate := reference.TokenExpiry
		if reference.LeaseDeadline.After(candidate) {
			candidate = reference.LeaseDeadline
		}
		candidate = candidate.Add(lateDrain)
		if candidate.After(deadline) {
			deadline = candidate
		}
	}
	return deadline.UTC()
}

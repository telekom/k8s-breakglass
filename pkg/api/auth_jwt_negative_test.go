package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// setupTestJWKSServer creates a test JWKS server and returns the server, key, and kid
func setupTestJWKSServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid-" + t.Name()
	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksObj := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   nB64,
				"e":   eB64,
			},
		},
	}
	jwksBytes, err := json.Marshal(jwksObj)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))

	return srv, priv, kid
}

func TestAuthMiddleware_ExtendedNegativeJWTCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	tests := []struct {
		name           string
		makeAuthHeader func() string
		expectedStatus int
		description    string
	}{
		{
			name: "empty bearer token",
			makeAuthHeader: func() string {
				return "Bearer "
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Bearer prefix with no token should fail",
		},
		{
			name: "bearer with only whitespace",
			makeAuthHeader: func() string {
				return "Bearer    "
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Bearer with only spaces should fail",
		},
		{
			name: "lowercase bearer",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "bearer " + tokStr // lowercase
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Lowercase 'bearer' should fail (RFC requires Bearer)",
		},
		{
			name: "token with wrong algorithm header",
			makeAuthHeader: func() string {
				// Create a token claiming to use HS256 but actually using RS256 key
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tok.Header["alg"] = "HS256" // Mismatch
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Algorithm mismatch should fail",
		},
		{
			name: "future not-before (nbf)",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{
					"sub": "test",
					"exp": time.Now().Add(time.Hour).Unix(),
					"nbf": time.Now().Add(10 * time.Minute).Unix(), // Not valid yet
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Token with future nbf should fail",
		},
		{
			name: "future issued-at (iat)",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{
					"sub": "test",
					"exp": time.Now().Add(time.Hour).Unix(),
					"iat": time.Now().Add(10 * time.Minute).Unix(), // Issued in the future
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			// jwt-go library rejects tokens with future iat by default
			expectedStatus: http.StatusUnauthorized,
			description:    "Token with future iat is rejected by jwt-go library",
		},
		{
			name: "missing kid header",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				// Deliberately NOT setting kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Token without kid cannot be validated against JWKS",
		},
		{
			name: "unknown kid",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = "unknown-kid-12345"
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Token with unknown kid should fail",
		},
		{
			name: "truncated token",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				// Truncate the signature
				parts := strings.Split(tokStr, ".")
				return "Bearer " + parts[0] + "." + parts[1] + ".truncated"
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Truncated signature should fail",
		},
		{
			name: "token with extra dot segments",
			makeAuthHeader: func() string {
				return "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig.extra.parts"
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "JWT with extra segments should fail",
		},
		{
			name: "completely empty authorization header",
			makeAuthHeader: func() string {
				return ""
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Empty authorization header should fail",
		},
		{
			name: "token signed with different key",
			makeAuthHeader: func() string {
				// Generate a different key
				otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid // Use same kid but different key
				tokStr, _ := tok.SignedString(otherPriv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Token signed with wrong key should fail",
		},
		{
			name: "token with very long expiry",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{
					"sub": "test",
					"exp": time.Now().Add(100 * 365 * 24 * time.Hour).Unix(), // 100 years
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusOK,
			description:    "Token with long expiry is technically valid",
		},
		{
			name: "token with null bytes in claims",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{
					"sub": "test\x00user",
					"exp": time.Now().Add(time.Minute).Unix(),
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr
			},
			expectedStatus: http.StatusOK,
			description:    "Null bytes in claims are preserved (downstream validation needed)",
		},
		{
			name: "multiple bearer tokens (only first used)",
			makeAuthHeader: func() string {
				claims := jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Minute).Unix()}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, _ := tok.SignedString(priv)
				return "Bearer " + tokStr + " Bearer anothertoken"
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Multiple tokens in header should fail parsing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			authHeader := tt.makeAuthHeader()
			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}

func TestAuthMiddleware_TokenClaimsEdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		email, _ := c.Get("email")
		groups, _ := c.Get("groups")
		c.JSON(http.StatusOK, gin.H{
			"user_id": userID,
			"email":   email,
			"groups":  groups,
		})
	})

	tests := []struct {
		name     string
		claims   jwt.MapClaims
		validate func(t *testing.T, resp map[string]interface{})
	}{
		{
			name: "empty groups array",
			claims: jwt.MapClaims{
				"sub":    "user1",
				"email":  "user1@example.com",
				"groups": []interface{}{},
				"exp":    time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				// Empty groups array may be returned as nil or empty array
				groups := resp["groups"]
				if groups != nil {
					groupsArr, ok := groups.([]interface{})
					require.True(t, ok || groups == nil)
					if ok {
						require.Empty(t, groupsArr)
					}
				}
				// Also verify user_id is set
				require.Equal(t, "user1", resp["user_id"])
			},
		},
		{
			name: "groups as string instead of array",
			claims: jwt.MapClaims{
				"sub":    "user2",
				"email":  "user2@example.com",
				"groups": "single-group", // Not an array
				"exp":    time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				// The middleware should handle this gracefully
				require.Equal(t, "user2", resp["user_id"])
			},
		},
		{
			name: "groups with special characters",
			claims: jwt.MapClaims{
				"sub":    "user3",
				"email":  "user3@example.com",
				"groups": []interface{}{"/path/to/group", "group@domain.com", "group:with:colons"},
				"exp":    time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				groups, ok := resp["groups"].([]interface{})
				require.True(t, ok)
				require.Len(t, groups, 3)
			},
		},
		{
			name: "unicode in email and groups",
			claims: jwt.MapClaims{
				"sub":    "user4",
				"email":  "用户@example.com",
				"groups": []interface{}{"グループ", "группа"},
				"exp":    time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				require.Equal(t, "用户@example.com", resp["email"])
			},
		},
		{
			name: "very long group names",
			claims: jwt.MapClaims{
				"sub":    "user5",
				"groups": []interface{}{strings.Repeat("a", 1000)},
				"exp":    time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				groups, ok := resp["groups"].([]interface{})
				require.True(t, ok)
				require.Len(t, groups, 1)
			},
		},
		{
			name: "numeric sub claim",
			claims: jwt.MapClaims{
				"sub": 12345, // Numeric instead of string
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				// Should handle numeric sub gracefully
				require.NotNil(t, resp["user_id"])
			},
		},
		{
			name: "nested claims structure",
			claims: jwt.MapClaims{
				"sub": "user6",
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"admin", "user"},
				},
				"exp": time.Now().Add(time.Minute).Unix(),
			},
			validate: func(t *testing.T, resp map[string]interface{}) {
				require.Equal(t, "user6", resp["user_id"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.claims)
			tok.Header["kid"] = kid
			tokStr, err := tok.SignedString(priv)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokStr)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)

			tt.validate(t, resp)
		})
	}
}

func TestAuthMiddleware_JWTTimingEdgeCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	tests := []struct {
		name           string
		claims         jwt.MapClaims
		expectedStatus int
	}{
		{
			name: "token expires in 1 second",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(1 * time.Second).Unix(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "token expired 1 second ago",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(-1 * time.Second).Unix(),
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "token with zero expiry (epoch)",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": 0,
				"nbf": 0,
			},
			// jwt-go v4 treats exp=0 as valid (zero value doesn't trigger expiry check)
			// This is library behavior - applications should validate exp > 0 if needed
			expectedStatus: http.StatusOK,
		},
		{
			name: "token with negative expiry",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": -1000,
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "nbf exactly now",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(time.Hour).Unix(),
				"nbf": time.Now().Unix(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "nbf 1 second ago",
			claims: jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(time.Hour).Unix(),
				"nbf": time.Now().Add(-1 * time.Second).Unix(),
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, tt.claims)
			tok.Header["kid"] = kid
			tokStr, err := tok.SignedString(priv)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokStr)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// Test that the middleware sets the jwt.Token and raw_claims in the context so downstream
// handlers can access them.
func TestAuthMiddleware_ExposesTokenAndRawClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "expose-kid"
	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
	jwksObj := map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64}}}
	jwksBytes, err := json.Marshal(jwksObj)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) {
		_, hasToken := c.Get("token")
		raw, _ := c.Get("raw_claims")
		// Indicate presence rather than serializing token directly
		c.JSON(http.StatusOK, gin.H{"token_present": hasToken, "raw_claims_keys": len(raw.(jwt.MapClaims))})
	})

	claims := jwt.MapClaims{"sub": "uid-expose", "exp": time.Now().Add(time.Minute).Unix(), "foo": "bar"}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokStr, err := tok.SignedString(priv)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, true, got["token_present"])
	// raw_claims_keys comes back as a JSON number (float64); ensure we have at least 2 keys
	if n, ok := got["raw_claims_keys"].(float64); ok {
		require.GreaterOrEqual(t, int(n), 2)
	} else {
		t.Fatalf("raw_claims_keys not a number: %T", got["raw_claims_keys"])
	}
}

// Table-driven tests for different group claim shapes and normalization.
func TestAuthMiddleware_GroupNormalizationCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "groups-kid"
	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
	jwksObj := map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64}}}
	jwksBytes, err := json.Marshal(jwksObj)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{name: "groups_array_interface", claims: jwt.MapClaims{"groups": []interface{}{"/team/admin", " /space/ops ", ""}}, want: []string{"admin", "ops"}},
		{name: "groups_array_string", claims: jwt.MapClaims{"groups": []string{"team/user", "/team/user"}}, want: []string{"user"}},
		{name: "realm_access_roles", claims: jwt.MapClaims{"realm_access": map[string]interface{}{"roles": []interface{}{"roleA", "roleB"}}}, want: []string{"roleA", "roleB"}},
		{name: "nested_paths", claims: jwt.MapClaims{"groups": []interface{}{"/a/b/c", "/a/b/c"}}, want: []string{"c"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(auth.Middleware())
			router.GET("/test", func(c *gin.Context) {
				if v, ok := c.Get("groups"); ok {
					c.JSON(http.StatusOK, gin.H{"groups": v})
					return
				}
				c.JSON(http.StatusOK, gin.H{"groups": []string{}})
			})

			claims := tc.claims
			// always include exp
			claims["exp"] = time.Now().Add(time.Minute).Unix()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = kid
			tokStr, err := tok.SignedString(priv)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokStr)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			var got map[string]interface{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			if arr, ok := got["groups"].([]interface{}); ok {
				vals := make([]string, 0, len(arr))
				for _, v := range arr {
					if s, ok := v.(string); ok {
						vals = append(vals, s)
					}
				}
				for _, want := range tc.want {
					require.Contains(t, vals, want)
				}
			} else {
				t.Fatalf("expected groups array, got %T", got["groups"])
			}
		})
	}
}

// Negative test: JWKS refresh times out/unreachable -> middleware returns 401 with an error message.
func TestAuthMiddleware_JWKSUnreachable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// JWKS server: first request returns empty JWKS; second request sleeps longer than refresh timeout causing Refresh to fail
	emptyJWKS := map[string]interface{}{"keys": []interface{}{}}
	emptyJWKSBytes, err := json.Marshal(emptyJWKS)
	require.NoError(t, err)

	// Create the key that would have been used (not present initially)
	privNew, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "unreach-kid"
	nB64New := base64.RawURLEncoding.EncodeToString(privNew.N.Bytes())
	eBytesNew := big.NewInt(int64(privNew.E)).Bytes()
	eB64New := base64.RawURLEncoding.EncodeToString(eBytesNew)
	jwksWithKey := map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64New, "e": eB64New}}}
	jwksWithKeyBytes, err := json.Marshal(jwksWithKey)
	require.NoError(t, err)

	var reqCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&reqCount, 1)
		if c == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(emptyJWKSBytes)
			return
		}
		// Sleep to simulate an unreachable/slow JWKS during refresh
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksWithKeyBytes)
	}))
	defer srv.Close()

	// Use a small refresh timeout so refresh fails quickly
	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour, RefreshTimeout: 50 * time.Millisecond})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Create token signed with privNew (kid not present initially)
	claims := jwt.MapClaims{"sub": "uid-unreach", "exp": time.Now().Add(time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokStr, err := tok.SignedString(privNew)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	// Ensure an error message exists in response; exact text may vary by underlying error
	require.NotEmpty(t, got["error"])
}

func TestAuthMiddleware_NegativeTokenCases(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Prepare JWKS server and key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "neg-kid"
	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
	jwksObj := map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64}}}
	jwksBytes, err := json.Marshal(jwksObj)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// 1) Expired token
	claimsExp := jwt.MapClaims{"sub": "uid-exp", "exp": time.Now().Add(-time.Minute).Unix()}
	tokExp := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsExp)
	tokExp.Header["kid"] = kid
	tokExpStr, err := tokExp.SignedString(priv)
	require.NoError(t, err)
	reqExp := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqExp.Header.Set("Authorization", "Bearer "+tokExpStr)
	wExp := httptest.NewRecorder()
	router.ServeHTTP(wExp, reqExp)
	require.Equal(t, http.StatusUnauthorized, wExp.Code)

	// 2) Malformed token (random string)
	reqBad := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqBad.Header.Set("Authorization", "Bearer this-is-not-a-jwt")
	wBad := httptest.NewRecorder()
	router.ServeHTTP(wBad, reqBad)
	require.Equal(t, http.StatusUnauthorized, wBad.Code)

	// 3) Missing sub claim
	claimsNoSub := jwt.MapClaims{"email": "no-sub@example.com", "exp": time.Now().Add(time.Minute).Unix()}
	tokNoSub := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsNoSub)
	tokNoSub.Header["kid"] = kid
	tokNoSubStr, err := tokNoSub.SignedString(priv)
	require.NoError(t, err)
	reqNoSub := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqNoSub.Header.Set("Authorization", "Bearer "+tokNoSubStr)
	wNoSub := httptest.NewRecorder()
	router.ServeHTTP(wNoSub, reqNoSub)
	// The middleware will still accept JWT validity-wise, but downstream may rely on sub; we expect 200 from middleware
	require.Equal(t, http.StatusOK, wNoSub.Code)
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(wNoSub.Body.Bytes(), &got))
	// Ensure raw_claims present and sub is missing
	// Note: middleware sets raw_claims; downstream handler here doesn't echo it, so just ensure request passed.
}

func TestAuthMiddleware_ValidAndInvalidJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Generate an RSA keypair for signing
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a kid and build a JWKS with the RSA public key
	kid := "test-kid"
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

	// Serve the JWKS via httptest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	// Obtain a keyfunc.JWKS from the server
	options := keyfunc.Options{RefreshInterval: time.Hour}
	jwks, err := keyfunc.Get(srv.URL, options)
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	// Handler that echoes back values set by middleware for assertions
	handler := func(c *gin.Context) {
		resp := gin.H{}
		if v, ok := c.Get("user_id"); ok {
			resp["user_id"] = v
		}
		if v, ok := c.Get("email"); ok {
			resp["email"] = v
		}
		if v, ok := c.Get("username"); ok {
			resp["username"] = v
		}
		if v, ok := c.Get("groups"); ok {
			resp["groups"] = v
		}
		// include header presence for verification
		resp["auth_header"] = c.Request.Header.Get("Authorization")
		c.JSON(http.StatusOK, resp)
	}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", handler)

	// Create a token with map claims including groups that require normalization and duplicates
	claims := jwt.MapClaims{
		"sub":                "uid-123",
		"email":              "alice@example.com",
		"preferred_username": "alice",
		"groups":             []interface{}{"/team/admin", "/team/admin", "/ops/dev"},
		"exp":                time.Now().Add(time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokStr, err := tok.SignedString(priv)
	require.NoError(t, err)

	// Sanity-check: parse using the jwks keyfunc directly to ensure signature verifies
	{
		var parsedClaims jwt.MapClaims
		parsedTok, perr := jwt.ParseWithClaims(tokStr, &parsedClaims, jwks.Keyfunc)
		require.NoError(t, perr)
		require.True(t, parsedTok.Valid)
	}

	// Valid token request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	require.Equal(t, "uid-123", got["user_id"])
	require.Equal(t, "alice@example.com", got["email"])
	require.Equal(t, "alice", got["username"])
	// auth_header should be empty because middleware deletes it
	require.Equal(t, "", got["auth_header"])

	// groups normalized: expect admin and dev present (order possibly preserved)
	if groupsRaw, ok := got["groups"]; ok {
		if arr, ok := groupsRaw.([]interface{}); ok {
			// convert to strings
			vals := make([]string, 0, len(arr))
			for _, v := range arr {
				if s, ok := v.(string); ok {
					vals = append(vals, s)
				}
			}
			require.Contains(t, vals, "admin")
			require.Contains(t, vals, "dev")
		}
	}

	// Invalid signature: sign with different key
	badPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	badTok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	badTok.Header["kid"] = kid
	badStr, err := badTok.SignedString(badPriv)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "Bearer "+badStr)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusUnauthorized, w2.Code)
}

func TestAuthMiddleware_MissingOrWrongHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Minimal JWKS server that returns a valid key so middleware can be constructed
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "hdr-kid"
	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
	jwksObj := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64, "e": eB64},
		},
	}
	jwksBytes, err := json.Marshal(jwksObj)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	}))
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Missing header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	// Wrong header (not Bearer)
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("Authorization", "Basic abcdef")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusBadRequest, w2.Code)
}

func TestAuthMiddleware_RefreshOnMissingKid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create the key that will be introduced after refresh
	privNew, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "refresh-kid"
	nB64New := base64.RawURLEncoding.EncodeToString(privNew.N.Bytes())
	eBytesNew := big.NewInt(int64(privNew.E)).Bytes()
	eB64New := base64.RawURLEncoding.EncodeToString(eBytesNew)
	jwksWithKey := map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": nB64New, "e": eB64New}}}
	jwksWithKeyBytes, err := json.Marshal(jwksWithKey)
	require.NoError(t, err)

	// Initial JWKS that does NOT contain the kid
	emptyJWKS := map[string]interface{}{"keys": []interface{}{}}
	emptyJWKSBytes, err := json.Marshal(emptyJWKS)
	require.NoError(t, err)

	// Channels to coordinate refresh timing
	requestReceived := make(chan struct{}, 1)
	allowResponse := make(chan struct{})

	// Track if we've closed allowResponse to avoid double-close panic
	var closedOnce sync.Once

	// Atomic counter for requests
	var reqCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&reqCount, 1)
		if c == 1 {
			// initial keyfunc.Get request -> return empty JWKS immediately
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(emptyJWKSBytes)
			return
		}
		// For the refresh (second request), notify test and wait until allowed
		select {
		case requestReceived <- struct{}{}:
		default:
		}
		<-allowResponse
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksWithKeyBytes)
	}))
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	require.NoError(t, err)
	defer jwks.EndBackground()

	logger := zaptest.NewLogger(t).Sugar()
	auth := &AuthHandler{jwks: jwks, log: logger}

	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Create token signed with the new key (kid present in token header)
	claims := jwt.MapClaims{"sub": "uid-refresh", "exp": time.Now().Add(time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokStr, err := tok.SignedString(privNew)
	require.NoError(t, err)

	// Start the request in a goroutine so we can coordinate the refresh
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokStr)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		router.ServeHTTP(w, req)
		close(done)
	}()

	// Wait for the JWKS GET to be observed (with timeout to prevent hanging)
	select {
	case <-requestReceived:
		// Refresh was attempted, proceed
	case <-time.After(5 * time.Second):
		// If no refresh attempted within 5 seconds, force close the allowResponse channel
		// This prevents the test from hanging indefinitely
		closedOnce.Do(func() {
			close(allowResponse)
		})
	}

	// Allow the refresh handler to respond with the JWKS that includes the key
	closedOnce.Do(func() {
		close(allowResponse)
	})

	// Wait for request to finish (with timeout)
	select {
	case <-done:
		// Request completed
	case <-time.After(5 * time.Second):
		// Timeout - test took too long
		t.Fatal("Request did not complete within 5 seconds")
	}

	require.Equal(t, http.StatusOK, w.Code)
}

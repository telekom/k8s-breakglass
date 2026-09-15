package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
)

// observedLoggerForTest returns a logger whose entries can be asserted on.
func observedLoggerForTest() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.DebugLevel)
	return zap.New(core), logs
}

// newSSRFTestServer builds a minimal Server whose only configured (and therefore
// only allowlisted) OIDC authority is the supplied upstream URL.
func newSSRFTestServer(t *testing.T, authorityURL string, cfg config.Config) *Server {
	t.Helper()
	parsed, err := url.Parse(authorityURL)
	require.NoError(t, err)
	return &Server{
		log:           zaptest.NewLogger(t),
		auth:          &AuthHandler{},
		config:        cfg,
		idpConfig:     &config.IdentityProviderConfig{Authority: authorityURL},
		oidcAuthority: parsed,
	}
}

// proxyGet drives handleOIDCProxy for a single proxyPath, as the route wildcard would.
func proxyGet(t *testing.T, server *Server, proxyPath string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/oidc/authority"+proxyPath, nil)
	c.Params = gin.Params{{Key: "proxyPath", Value: proxyPath}}
	server.handleOIDCProxy(c)
	return w
}

// TestOIDCProxyDoesNotFollowRedirectToInternalHost pins the SSRF fix: the OIDC
// proxy validates only the first hop against the configured-authority
// allowlist, so a 30x from a trusted-but-redirecting IdP must never be followed
// server-side. Before the CheckRedirect fix this test fails, because Go's
// default client transparently fetches the redirect target — the "internal"
// server records a hit and its body is relayed with status 200.
func TestOIDCProxyDoesNotFollowRedirectToInternalHost(t *testing.T) {
	var internalHits int64
	// Stands in for an internal-only service (metadata endpoint, admin API, ...)
	// that is NOT in the OIDC authority allowlist.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&internalHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"internal":"secret-token"}`))
	}))
	defer internal.Close()

	// The configured, allowlisted authority — which redirects off-host.
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", internal.URL+"/latest/meta-data/")
		w.WriteHeader(http.StatusFound)
	}))
	defer authority.Close()

	server := newSSRFTestServer(t, authority.URL, config.Config{})

	w := proxyGet(t, server, "/.well-known/openid-configuration")

	require.Equal(t, int64(0), atomic.LoadInt64(&internalHits),
		"OIDC proxy must not issue a server-side request to the redirect target")
	require.Equal(t, http.StatusFound, w.Code,
		"the upstream 30x status should be relayed verbatim, not resolved")
	require.NotContains(t, w.Body.String(), "secret-token",
		"internal response body must not be relayed to the caller")
	require.Empty(t, w.Header().Get("Location"),
		"Location must remain stripped by the response header allowlist")
}

// TestOIDCProxyRefusesRedirectChainAcrossMultipleHops covers the multi-hop case:
// Go's default client follows up to 10 redirects, so a chain must be broken at
// the very first hop rather than merely bounded.
func TestOIDCProxyRefusesRedirectChainAcrossMultipleHops(t *testing.T) {
	var finalHits int64
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&finalHits, 1)
		_, _ = w.Write([]byte(`{"internal":"reached"}`))
	}))
	defer final.Close()

	var hop *httptest.Server
	hop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /hop1 -> /hop2 (same host) -> final (different host)
		if strings.HasSuffix(r.URL.Path, "/hop2") {
			w.Header().Set("Location", final.URL)
		} else {
			w.Header().Set("Location", hop.URL+"/hop2")
		}
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer hop.Close()

	server := newSSRFTestServer(t, hop.URL, config.Config{})

	w := proxyGet(t, server, "/.well-known/jwks.json")

	require.Equal(t, int64(0), atomic.LoadInt64(&finalHits),
		"no hop in the redirect chain may be fetched server-side")
	require.Equal(t, http.StatusMovedPermanently, w.Code)
}

// TestOIDCProxyRedirectFollowingRequiresExplicitOptIn documents the
// backwards-compatibility escape hatch: the zero value of the new config field
// keeps the secure default, and only an explicit true restores the old
// (redirect-following) behaviour for a non-conforming IdP.
func TestOIDCProxyRedirectFollowingRequiresExplicitOptIn(t *testing.T) {
	truthy := true
	falsy := false

	tests := []struct {
		name            string
		cfg             config.Config
		expectFollowed  bool
		expectedStatus  int
		expectedTargetH int64
	}{
		{
			name:            "unset field preserves secure default (refuse)",
			cfg:             config.Config{},
			expectFollowed:  false,
			expectedStatus:  http.StatusFound,
			expectedTargetH: 0,
		},
		{
			name:            "explicit false refuses redirects",
			cfg:             config.Config{Server: config.Server{AllowOIDCProxyRedirects: &falsy}},
			expectFollowed:  false,
			expectedStatus:  http.StatusFound,
			expectedTargetH: 0,
		},
		{
			name:            "explicit true opts back in to following",
			cfg:             config.Config{Server: config.Server{AllowOIDCProxyRedirects: &truthy}},
			expectFollowed:  true,
			expectedStatus:  http.StatusOK,
			expectedTargetH: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var targetHits int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				atomic.AddInt64(&targetHits, 1)
				_, _ = w.Write([]byte(`{"followed":true}`))
			}))
			defer target.Close()

			authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(http.StatusFound)
			}))
			defer authority.Close()

			server := newSSRFTestServer(t, authority.URL, tt.cfg)

			w := proxyGet(t, server, "/.well-known/openid-configuration")

			require.Equal(t, tt.expectedStatus, w.Code)
			require.Equal(t, tt.expectedTargetH, atomic.LoadInt64(&targetHits))
			if tt.expectFollowed {
				require.Contains(t, w.Body.String(), "followed")
			} else {
				require.NotContains(t, w.Body.String(), "followed")
			}
		})
	}
}

// TestOIDCProxyRelaysNormalDiscoveryResponse is the no-regression case: the
// redirect refusal must not disturb ordinary 200 discovery proxying.
func TestOIDCProxyRelaysNormalDiscoveryResponse(t *testing.T) {
	const body = `{"issuer":"https://idp.example.com","jwks_uri":"https://idp.example.com/jwks"}`
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer authority.Close()

	server := newSSRFTestServer(t, authority.URL, config.Config{})

	w := proxyGet(t, server, "/.well-known/openid-configuration")

	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, body, w.Body.String())
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

// TestOIDCProxyUnknownAuthorityStillForbidden guards the first-hop allowlist that
// makes this finding redirect-chain-limited rather than arbitrary SSRF: an
// attacker-supplied X-OIDC-Authority is rejected with 403 and never contacted.
func TestOIDCProxyUnknownAuthorityStillForbidden(t *testing.T) {
	var attackerHits int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&attackerHits, 1)
		_, _ = w.Write([]byte(`{"evil":true}`))
	}))
	defer attacker.Close()

	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"ok"}`))
	}))
	defer authority.Close()

	server := newSSRFTestServer(t, authority.URL, config.Config{})

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/oidc/authority/.well-known/openid-configuration", nil)
	c.Request.Header.Set("X-OIDC-Authority", attacker.URL)
	c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration"}}

	server.handleOIDCProxy(c)

	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, int64(0), atomic.LoadInt64(&attackerHits))
	require.Contains(t, w.Body.String(), errUnknownOIDCAuthority.Error())
}

// TestOIDCProxyCapsResponseBody pins the response-size cap. Before the
// io.LimitReader fix the whole oversized body is relayed, so a malicious or
// compromised authority can stream unbounded data through the proxy.
func TestOIDCProxyCapsResponseBody(t *testing.T) {
	oversize := maxOIDCProxyResponseBytes + (64 << 10)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("A", 32<<10)
		for written := int64(0); written < oversize; written += int64(len(chunk)) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer authority.Close()

	server := newSSRFTestServer(t, authority.URL, config.Config{})

	w := proxyGet(t, server, "/.well-known/jwks.json")

	require.Equal(t, maxOIDCProxyResponseBytes, int64(w.Body.Len()),
		fmt.Sprintf("relayed body must be capped at %d bytes", maxOIDCProxyResponseBytes))
}

// serveFixedSizeBody returns an authority that writes exactly size bytes.
func serveFixedSizeBody(t *testing.T, size int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat("A", 32<<10))
		for written := int64(0); written < size; {
			remaining := size - written
			if remaining < int64(len(chunk)) {
				chunk = chunk[:remaining]
			}
			n, err := w.Write(chunk)
			written += int64(n)
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestOIDCProxyExactlyMaxSizedBodyIsNotTruncated pins the off-by-one in the
// truncation check. io.LimitReader yields exactly maxOIDCProxyResponseBytes both
// when it truncated a larger document and when the document is exactly that
// size, so keying truncation off `copied == max` alone misreports a fully
// relayed exactly-1-MiB body as truncated: it logs oidc_proxy_response_truncated,
// increments the response_too_large failure counter, and skips the success
// counter. Reverting the oidcProxyBodyHasMore probe fails this test.
func TestOIDCProxyExactlyMaxSizedBodyIsNotTruncated(t *testing.T) {
	authority := serveFixedSizeBody(t, maxOIDCProxyResponseBytes)

	logger, logs := observedLoggerForTest()
	server := newSSRFTestServer(t, authority.URL, config.Config{})
	server.log = logger

	successBefore := testutil.ToFloat64(metrics.OIDCProxySuccess.WithLabelValues("authority"))
	tooLargeBefore := testutil.ToFloat64(metrics.OIDCProxyFailure.WithLabelValues("authority", "response_too_large"))

	w := proxyGet(t, server, "/.well-known/jwks.json")

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, maxOIDCProxyResponseBytes, int64(w.Body.Len()),
		"a body of exactly the cap must be relayed in full")
	require.Empty(t, logs.FilterMessage("oidc_proxy_response_truncated").All(),
		"an exactly-cap-sized body is complete and must not be logged as truncated")
	require.Equal(t, tooLargeBefore,
		testutil.ToFloat64(metrics.OIDCProxyFailure.WithLabelValues("authority", "response_too_large")),
		"response_too_large must not fire for a fully relayed body")
	require.Equal(t, successBefore+1,
		testutil.ToFloat64(metrics.OIDCProxySuccess.WithLabelValues("authority")),
		"a fully relayed body must be recorded as a success")
}

// TestOIDCProxyOneByteOverMaxIsTruncated is the other half of the boundary: a
// body one byte above the cap is genuinely truncated and must be reported as
// such, so the exactly-max fix must not silence real truncation.
func TestOIDCProxyOneByteOverMaxIsTruncated(t *testing.T) {
	authority := serveFixedSizeBody(t, maxOIDCProxyResponseBytes+1)

	logger, logs := observedLoggerForTest()
	server := newSSRFTestServer(t, authority.URL, config.Config{})
	server.log = logger

	successBefore := testutil.ToFloat64(metrics.OIDCProxySuccess.WithLabelValues("authority"))
	tooLargeBefore := testutil.ToFloat64(metrics.OIDCProxyFailure.WithLabelValues("authority", "response_too_large"))

	w := proxyGet(t, server, "/.well-known/jwks.json")

	require.Equal(t, maxOIDCProxyResponseBytes, int64(w.Body.Len()),
		"the relayed body must still be capped")
	require.NotEmpty(t, logs.FilterMessage("oidc_proxy_response_truncated").All(),
		"a body above the cap must be logged as truncated")
	require.Equal(t, tooLargeBefore+1,
		testutil.ToFloat64(metrics.OIDCProxyFailure.WithLabelValues("authority", "response_too_large")),
		"real truncation must increment response_too_large")
	require.Equal(t, successBefore,
		testutil.ToFloat64(metrics.OIDCProxySuccess.WithLabelValues("authority")),
		"a truncated relay must not be recorded as a success")
}

// TestOIDCProxyDoesNotTruncateNormalSizedDocuments confirms the cap leaves ample
// headroom for real discovery/JWKS documents.
func TestOIDCProxyDoesNotTruncateNormalSizedDocuments(t *testing.T) {
	// 256 KiB is far above any realistic JWKS, and still under the 1 MiB cap.
	payload := strings.Repeat("B", 256<<10)
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer authority.Close()

	server := newSSRFTestServer(t, authority.URL, config.Config{})

	w := proxyGet(t, server, "/.well-known/jwks.json")

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, len(payload), w.Body.Len())
}

// TestWarnOnInsecureOIDCAuthority covers the http-scheme authority assessment:
// the condition is surfaced to operators but never fails startup, and an https
// authority produces no warning.
func TestWarnOnInsecureOIDCAuthority(t *testing.T) {
	tests := []struct {
		name        string
		authority   string
		expectWarn  bool
		expectPanic bool
	}{
		{name: "http authority warns", authority: "http://idp.example.com/realms/x", expectWarn: true},
		{name: "uppercase HTTP authority warns", authority: "HTTP://idp.example.com", expectWarn: true},
		{name: "https authority is silent", authority: "https://idp.example.com/realms/x", expectWarn: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observedLoggerForTest()
			server := &Server{log: core, auth: &AuthHandler{}}
			parsed, err := url.Parse(tt.authority)
			require.NoError(t, err)

			// Must never fail closed — SetIdentityProvider keeps working.
			server.warnOnInsecureOIDCAuthority("test-idp", parsed)

			found := false
			for _, entry := range logs.All() {
				if entry.Message == "oidc_proxy_insecure_http_authority" {
					found = true
				}
			}
			require.Equal(t, tt.expectWarn, found)
		})
	}
}

// TestWarnOnInsecureOIDCAuthorityHandlesNils ensures the helper is defensive.
func TestWarnOnInsecureOIDCAuthorityHandlesNils(t *testing.T) {
	core, _ := observedLoggerForTest()
	(&Server{log: core}).warnOnInsecureOIDCAuthority("idp", nil)
	(&Server{log: nil}).warnOnInsecureOIDCAuthority("idp", &url.URL{Scheme: "http", Host: "x"})
}

// TestOIDCProxyRedirectsAllowedDefault verifies the config accessor's zero value.
func TestOIDCProxyRedirectsAllowedDefault(t *testing.T) {
	require.False(t, config.Config{}.OIDCProxyRedirectsAllowed(),
		"unset AllowOIDCProxyRedirects must default to refusing redirects")

	truthy := true
	require.True(t, config.Config{Server: config.Server{AllowOIDCProxyRedirects: &truthy}}.OIDCProxyRedirectsAllowed())

	falsy := false
	require.False(t, config.Config{Server: config.Server{AllowOIDCProxyRedirects: &falsy}}.OIDCProxyRedirectsAllowed())
}

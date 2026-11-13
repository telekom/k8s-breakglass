/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const stepUpHeader = "X-Breakglass-Step-Up-Challenge"

// TestStepUpAuthentication deploys API/frontend replicas of the real
// breakglass image with different stepUp settings and drives critical
// mutations with real Keycloak tokens. The main controller has no stepUp
// config, so it covers the default (disabled) path.
func TestStepUpAuthentication(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	oidc := s.TC.OIDCProvider()
	requester, approver := helpers.TestUsers.Requester, helpers.TestUsers.Approver

	suffix := helpers.GenerateUniqueName("")
	replicas := map[string]map[string]any{
		"fresh": {"enabled": true, "maxAuthAge": "5m"},
		"stale": {"enabled": true, "maxAuthAge": "10s"},
		"acr":   {"enabled": true, "requiredACR": []string{"gold"}},
		// Keycloak issues acr "1" for a fresh password login.
		"acr-ok": {"enabled": true, "requiredACR": []string{"1"}},
		// Strict settings that must have no effect while enabled is false.
		"disabled": {"enabled": false, "maxAuthAge": "1s", "requiredACR": []string{"gold"}},
		"invalid":  {"enabled": true},
	}
	names := map[string]string{}
	for variant, stepUp := range replicas {
		names[variant] = "e2e-stepup-" + variant + suffix
		helpers.DeployServerReplica(t, s, helpers.ServerReplica{
			Name:       names[variant],
			EditConfig: func(cfg map[string]any) { cfg["stepUp"] = stepUp },
		})
	}
	for variant, name := range names {
		if variant == "invalid" {
			continue // never becomes ready; asserted below
		}
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, s.Namespace, name, 5*time.Minute),
			"replica %s did not become ready", variant)
	}

	// newEscalation returns an escalation with its own group, so every
	// flow can create a fresh pending session.
	newEscalation := func(t *testing.T) *breakglassv1alpha1.BreakglassEscalation {
		t.Helper()
		esc := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-stepup-esc"), s.Namespace).
			WithAllowedClusters(s.Cluster).
			WithEscalatedGroup(helpers.GenerateUniqueName("system:e2e-stepup")).
			WithApproverUsers(approver.Email).
			WithLabels(helpers.E2ELabelsWithFeature("step-up")).
			Build()
		s.MustCreateResource(esc)
		helpers.WaitForEscalationReady(t, ctx, s.Client, esc.Name, s.Namespace, helpers.WaitForStateTimeout)
		time.Sleep(helpers.CachePropagationDelay)
		return esc
	}
	sessionRequest := func(esc *breakglassv1alpha1.BreakglassEscalation) BreakglassSessionRequest {
		return BreakglassSessionRequest{
			Clustername: s.Cluster,
			Username:    requester.Email,
			GroupName:   esc.Spec.EscalatedGroup,
			Reason:      "step-up e2e",
		}
	}
	created := func(t *testing.T, body []byte) *breakglassv1alpha1.BreakglassSession {
		t.Helper()
		var session breakglassv1alpha1.BreakglassSession
		require.NoError(t, json.Unmarshal(body, &session))
		require.NotEmpty(t, session.Name)
		s.Cleanup.Add(&breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: s.Namespace}})
		return &session
	}
	withReplica := func(t *testing.T, variant string) string {
		t.Helper()
		port, stop := helpers.StartPortForward(t, ctx, s.Namespace, names[variant], 8080, 0)
		t.Cleanup(stop)
		return fmt.Sprintf("http://localhost:%d", port)
	}

	t.Run("default-off/main-controller", func(t *testing.T) {
		esc := newEscalation(t)
		token := oidc.GetToken(t, ctx, requester.Username, requester.Password)
		r := stepUpCall(t, ctx, helpers.GetAPIBaseURL(), token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusCreated, r.status, "body: %s", r.body)
		assert.Empty(t, r.header.Get(stepUpHeader))
		created(t, r.body)
	})

	t.Run("disabled", func(t *testing.T) {
		base := withReplica(t, "disabled")
		esc := newEscalation(t)
		// A browser login carries auth_time (and acr "1"), so the ignored
		// maxAuthAge and requiredACR would both reject it if applied.
		token := browserLoginToken(t, ctx, requester.Username, requester.Password)
		require.Contains(t, jwtClaims(t, token), "auth_time")
		time.Sleep(2 * time.Second) // older than the ignored maxAuthAge
		r := stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusCreated, r.status, "body: %s", r.body)
		assert.Empty(t, r.header.Get(stepUpHeader))
		assert.Empty(t, r.header.Get("WWW-Authenticate"))
		session := created(t, r.body)

		approverToken := browserLoginToken(t, ctx, approver.Username, approver.Password)
		time.Sleep(2 * time.Second)
		r = stepUpCall(t, ctx, base, approverToken, http.MethodPost, sessionsAPIBasePath+"/"+session.Name+"/approve", "", nil)
		require.Equal(t, http.StatusOK, r.status, "body: %s", r.body)
	})

	t.Run("fresh", func(t *testing.T) {
		base := withReplica(t, "fresh")
		esc := newEscalation(t)
		token := browserLoginToken(t, ctx, requester.Username, requester.Password)
		claims := jwtClaims(t, token)
		require.Contains(t, claims, "auth_time", "browser-flow access tokens carry auth_time")
		req := sessionRequest(esc)

		t.Run("non-critical-read-unaffected", func(t *testing.T) {
			r := stepUpCall(t, ctx, base, token, http.MethodGet, sessionsAPIBasePath, "", nil)
			assert.Equal(t, http.StatusOK, r.status, "body: %s", r.body)
			assert.Empty(t, r.header.Get(stepUpHeader))
		})

		// Without a challenge the critical mutation is denied and a
		// challenge is issued.
		r := stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", req)
		require.Equal(t, http.StatusPreconditionRequired, r.status, "body: %s", r.body)
		first := r.header.Get(stepUpHeader)
		require.NotEmpty(t, first)

		// A wrong challenge is denied and replaces the outstanding one.
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "not-the-challenge", req)
		require.Equal(t, http.StatusPreconditionRequired, r.status, "body: %s", r.body)
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, first, req)
		require.Equal(t, http.StatusPreconditionRequired, r.status, "a replaced challenge must not be accepted")
		challenge := r.header.Get(stepUpHeader)
		require.NotEmpty(t, challenge)

		// The issued challenge completes the request.
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, challenge, req)
		require.Equal(t, http.StatusCreated, r.status, "body: %s", r.body)
		session := created(t, r.body)
		helpers.WaitForSessionState(t, ctx, s.Client, session.Name, s.Namespace, breakglassv1alpha1.SessionStatePending, helpers.WaitForConditionTimeout)

		// The challenge is single-use.
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, challenge, req)
		assert.Equal(t, http.StatusPreconditionRequired, r.status, "a consumed challenge must not be accepted")

		// Approval is critical too.
		approverToken := browserLoginToken(t, ctx, approver.Username, approver.Password)
		approve := sessionsAPIBasePath + "/" + session.Name + "/approve"
		r = stepUpCall(t, ctx, base, approverToken, http.MethodPost, approve, "", nil)
		require.Equal(t, http.StatusPreconditionRequired, r.status, "body: %s", r.body)
		// A challenge issued to the requester is not valid for the approver.
		r2 := stepUpCall(t, ctx, base, token, http.MethodPost, approve, "", nil)
		require.Equal(t, http.StatusPreconditionRequired, r2.status, "body: %s", r2.body)
		r2 = stepUpCall(t, ctx, base, approverToken, http.MethodPost, approve, r2.header.Get(stepUpHeader), nil)
		require.Equal(t, http.StatusPreconditionRequired, r2.status, "a challenge is bound to the user")
		r = stepUpCall(t, ctx, base, approverToken, http.MethodPost, approve, r2.header.Get(stepUpHeader), nil)
		require.Equal(t, http.StatusOK, r.status, "body: %s", r.body)
		helpers.WaitForSessionState(t, ctx, s.Client, session.Name, s.Namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForConditionTimeout)
	})

	t.Run("stale-authentication", func(t *testing.T) {
		base := withReplica(t, "stale")
		esc := newEscalation(t)
		token := browserLoginToken(t, ctx, requester.Username, requester.Password)
		time.Sleep(11 * time.Second) // older than maxAuthAge 10s
		r := stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusUnauthorized, r.status, "body: %s", r.body)
		www := r.header.Get("WWW-Authenticate")
		assert.Contains(t, www, `error="insufficient_user_authentication"`)
		assert.Contains(t, www, `error_description="authentication is not recent enough"`)
		assert.Contains(t, www, `max_age="10"`)
		assert.Empty(t, r.header.Get(stepUpHeader), "no challenge before re-authentication")

		r = stepUpCall(t, ctx, base, token, http.MethodGet, sessionsAPIBasePath, "", nil)
		assert.Equal(t, http.StatusOK, r.status, "non-critical reads are unaffected")

		// Re-authenticating satisfies maxAuthAge again.
		token = browserLoginToken(t, ctx, requester.Username, requester.Password)
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusPreconditionRequired, r.status, "body: %s", r.body)
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, r.header.Get(stepUpHeader), sessionRequest(esc))
		require.Equal(t, http.StatusCreated, r.status, "body: %s", r.body)
		created(t, r.body)
	})

	t.Run("acr-not-accepted", func(t *testing.T) {
		base := withReplica(t, "acr")
		esc := newEscalation(t)
		token := oidc.GetToken(t, ctx, requester.Username, requester.Password)
		r := stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusUnauthorized, r.status, "body: %s", r.body)
		www := r.header.Get("WWW-Authenticate")
		assert.Contains(t, www, `error="insufficient_user_authentication"`)
		assert.Contains(t, www, `error_description="authentication context class not accepted"`)
		assert.Contains(t, www, `acr_values="gold"`)
	})

	t.Run("acr-accepted", func(t *testing.T) {
		base := withReplica(t, "acr-ok")
		esc := newEscalation(t)
		token := oidc.GetToken(t, ctx, requester.Username, requester.Password)
		require.Equal(t, "1", jwtClaims(t, token)["acr"])
		r := stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, "", sessionRequest(esc))
		require.Equal(t, http.StatusPreconditionRequired, r.status, "body: %s", r.body)
		assert.Empty(t, r.header.Get("WWW-Authenticate"))
		r = stepUpCall(t, ctx, base, token, http.MethodPost, sessionsAPIBasePath, r.header.Get(stepUpHeader), sessionRequest(esc))
		require.Equal(t, http.StatusCreated, r.status, "body: %s", r.body)
		created(t, r.body)
	})

	t.Run("invalid-config-refuses-start", func(t *testing.T) {
		want := "fatal: register breakglass controllers: step-up configuration: stepUp.enabled requires stepUp.maxAuthAge or stepUp.requiredACR"
		require.Eventually(t, func() bool {
			return helpers.ServerReplicaLogsContain(t, ctx, s.Namespace, names["invalid"], want)
		}, 3*time.Minute, 2*time.Second)
		var d appsv1.Deployment
		require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: names["invalid"]}, &d))
		assert.Zero(t, d.Status.AvailableReplicas)
	})
}

type stepUpResponse struct {
	status int
	header http.Header
	body   []byte
}

func stepUpCall(t *testing.T, ctx context.Context, baseURL, token, method, path, challenge string, body any) stepUpResponse {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if challenge != "" {
		req.Header.Set(stepUpHeader, challenge)
	}
	resp, err := helpers.DefaultHTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return stepUpResponse{status: resp.StatusCode, header: resp.Header, body: data}
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

// browserLoginToken logs in through Keycloak's browser (authorization code +
// PKCE) flow and returns the access token. Keycloak sets auth_time only for
// interactive logins, not for the password grant that the other e2e tests
// use. Like e2e/get-token.sh, it talks to the forwarded Keycloak port and
// sends the in-cluster Host so the issuer matches the IdentityProvider.
func browserLoginToken(t *testing.T, ctx context.Context, username, password string) string {
	t.Helper()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	issuerHost := helpers.GetKeycloakIssuerHost()
	if issuerHost == "" {
		issuerHost = "breakglass-keycloak.breakglass-system.svc.cluster.local:8443"
	}
	relPath := "/" + strings.Trim(os.Getenv("KEYCLOAK_RELATIVE_PATH"), "/")
	realmURL := "https://localhost:" + port + strings.TrimSuffix(relPath, "/") + "/realms/" + helpers.GetKeycloakRealm() + "/protocol/openid-connect"
	const redirectURI = "http://localhost:28081/step-up-e2e"

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{
		Timeout:       30 * time.Second,
		Jar:           jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}, // #nosec G402 -- e2e Keycloak uses a self-signed certificate.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	do := func(method, target string, form url.Values) *http.Response {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		require.NoError(t, err)
		req.Host = issuerHost
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := c.Do(req)
		require.NoError(t, err)
		return resp
	}
	// Keycloak renders URLs with the issuer host; send them to the forward.
	local := func(raw string) string {
		u, err := url.Parse(html.UnescapeString(raw))
		require.NoError(t, err)
		u.Scheme, u.Host = "https", "localhost:"+port
		return u.String()
	}

	verifier := rand.Text() + rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	resp := do(http.MethodGet, realmURL+"/auth?"+url.Values{
		"client_id":             {"breakglass-ui"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"redirect_uri":          {redirectURI},
		"state":                 {rand.Text()},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	page, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "login page: %s", page)
	action := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if action == nil {
		action = regexp.MustCompile(`<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"`).FindSubmatch(page)
	}
	require.NotNil(t, action, "Keycloak login form not found")

	resp = do(http.MethodPost, local(string(action[1])), url.Values{"username": {username}, "password": {password}, "credentialId": {""}})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode, "login must redirect with a code")
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := location.Query().Get("code")
	require.NotEmpty(t, code, "redirect without code: %s", location)

	resp = do(http.MethodPost, realmURL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"breakglass-ui"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	require.NotEmpty(t, tok.AccessToken)
	return tok.AccessToken
}

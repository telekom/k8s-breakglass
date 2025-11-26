package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"

	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
)

var sessionIndexFnsEndToEnd = map[string]client.IndexerFunc{
	"spec.user": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.User}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.Cluster}
	},
	"spec.grantedGroup": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.GrantedGroup}
	},
}

var metadataNameIndexer = func(o client.Object) []string {
	return []string{o.GetName()}
}

const (
	e2eClusterName    = "cluster-e2e"
	e2eAltClusterName = "cluster-alt"
	e2eNamespace      = "default"
	e2eEscalation     = "allow-create"
	e2eGroup          = "breakglass-create-all"
	requesterEmail    = "requester@example.com"
	approverEmail     = "approver@example.com"
	requesterName     = "Requester"
	approverName      = "Approver"
	sarPathTemplate   = "/api/breakglass/webhook/authorize/%s"
	sessionsBasePath  = "/api/breakglassSessions"
)

type apiEndToEndEnv struct {
	t               *testing.T
	server          *Server
	handler         http.Handler
	sarServer       *httptest.Server
	sarRequests     int
	clusterName     string
	client          client.Client
	allowSessionSAR bool
}

func setupAPIEndToEndEnv(t *testing.T) *apiEndToEndEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	env := &apiEndToEndEnv{t: t, clusterName: e2eClusterName, allowSessionSAR: true}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")

	env.sarServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/apis/authorization.k8s.io/v1/subjectaccessreviews") {
			env.sarRequests++
			w.Header().Set("Content-Type", "application/json")
			resp := authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
				Status: authorizationv1.SubjectAccessReviewStatus{
					Allowed: env.allowSessionSAR,
					Reason:  "session allowed",
				},
			}
			if !env.allowSessionSAR {
				resp.Status.Reason = "session denied by target cluster"
			}
			_ = json.NewEncoder(w).Encode(&resp)
			return
		}
		http.NotFound(w, r)
	}))

	kubeconfig := buildKubeconfig(env.sarServer.URL)

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithStatusSubresource(&v1alpha1.BreakglassSession{})
	for name, fn := range sessionIndexFnsEndToEnd {
		builder = builder.WithIndex(&v1alpha1.BreakglassSession{}, name, fn)
	}
	builder = builder.WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexer)
	builder = builder.WithIndex(&v1alpha1.ClusterConfig{}, "metadata.name", metadataNameIndexer)

	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eEscalation,
			Namespace: e2eNamespace,
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{e2eClusterName},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: e2eGroup,
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{approverEmail},
			},
		},
	}

	clusterCfg := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eClusterName,
			Namespace: e2eNamespace,
		},
		Spec: v1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: v1alpha1.SecretKeyReference{
				Name:      "ccfg-secret",
				Namespace: e2eNamespace,
				Key:       "value",
			},
		},
	}

	clusterCfgAlt := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eAltClusterName,
			Namespace: e2eNamespace,
		},
		Spec: v1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: v1alpha1.SecretKeyReference{
				Name:      "ccfg-secret",
				Namespace: e2eNamespace,
				Key:       "value",
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ccfg-secret",
			Namespace: e2eNamespace,
		},
		Data: map[string][]byte{
			"value": kubeconfig,
		},
	}

	builder = builder.WithObjects(esc, clusterCfg, clusterCfgAlt, secret)
	cli := builder.Build()

	sessionManager := &breakglass.SessionManager{Client: cli}
	escalationManager := &breakglass.EscalationManager{Client: cli}
	logger := zaptest.NewLogger(t)
	provider := cluster.NewClientProvider(cli, logger.Sugar())

	cfg := config.Config{Frontend: config.Frontend{BaseURL: "https://breakglass.example"}}
	auth := NewAuth(logger.Sugar(), cfg)

	middleware := testIdentityMiddleware()
	sessionController := breakglass.NewBreakglassSessionController(logger.Sugar(), cfg, sessionManager, escalationManager, middleware, "", provider, cli, true)
	escalationController := breakglass.NewBreakglassEscalationController(logger.Sugar(), escalationManager, middleware, "")
	webhookController := webhook.NewWebhookController(logger.Sugar(), cfg, sessionManager, escalationManager, provider, policy.NewEvaluator(cli, logger.Sugar()))
	webhookController.SetCanDoFn(func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clusterName string) (bool, error) {
		return false, nil
	})

	server := NewServer(logger, cfg, true, auth)
	require.NoError(t, server.RegisterAll([]APIController{sessionController, escalationController, webhookController}))

	env.server = server
	env.handler = server.Handler()
	env.client = cli

	return env
}

func (env *apiEndToEndEnv) Close() {
	env.sarServer.Close()
}

func (env *apiEndToEndEnv) doRequest(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	reader := bytes.NewReader(body)
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	return rr
}

func (env *apiEndToEndEnv) createSession(t *testing.T) {
	t.Helper()
	env.createSessionWithRequest(t, breakglass.BreakglassSessionRequest{})
}

func (env *apiEndToEndEnv) createSessionWithRequest(t *testing.T, req breakglass.BreakglassSessionRequest) {
	t.Helper()
	if req.Clustername == "" {
		req.Clustername = env.clusterName
	}
	if req.Username == "" {
		req.Username = requesterEmail
	}
	if req.GroupName == "" {
		req.GroupName = e2eGroup
	}
	if req.Reason == "" {
		req.Reason = "need breakglass access"
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)
	rr := env.doRequest(t, http.MethodPost, sessionsBasePath, body)
	require.Equal(t, http.StatusCreated, rr.Code)
}

func (env *apiEndToEndEnv) listSessions(t *testing.T) []v1alpha1.BreakglassSession {
	t.Helper()
	rr := env.doRequest(t, http.MethodGet, sessionsBasePath, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var sessions []v1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &sessions))
	return sessions
}

func (env *apiEndToEndEnv) approveSession(t *testing.T, name string) {
	t.Helper()
	path := fmt.Sprintf("%s/%s/approve", sessionsBasePath, name)
	rr := env.doRequest(t, http.MethodPost, path, nil)
	require.Equal(t, http.StatusOK, rr.Code)
}

func (env *apiEndToEndEnv) invokeSAR(t *testing.T) webhook.SubjectAccessReviewResponse {
	return env.invokeSARForClusterWithModifier(t, env.clusterName, nil)
}

func (env *apiEndToEndEnv) invokeSARForCluster(t *testing.T, clusterName string) webhook.SubjectAccessReviewResponse {
	return env.invokeSARForClusterWithModifier(t, clusterName, nil)
}

func (env *apiEndToEndEnv) invokeSARForClusterWithModifier(t *testing.T, clusterName string, modify func(*authorizationv1.SubjectAccessReview)) webhook.SubjectAccessReviewResponse {
	t.Helper()
	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   requesterEmail,
			Groups: []string{"system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "create",
				Resource:  "pods",
			},
		},
	}
	if modify != nil {
		modify(&sar)
	}
	body, err := json.Marshal(sar)
	require.NoError(t, err)
	path := fmt.Sprintf(sarPathTemplate, clusterName)
	rr := env.doRequest(t, http.MethodPost, path, body)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp webhook.SubjectAccessReviewResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

func buildKubeconfig(serverURL string) []byte {
	cfg := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: "test",
		Clusters: map[string]*clientcmdapi.Cluster{
			"test": {Server: serverURL, InsecureSkipTLSVerify: true},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"test": {Token: "fake-token"},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "test", AuthInfo: "test"},
		},
	}
	data, err := clientcmd.Write(cfg)
	if err != nil {
		panic(err)
	}
	return data
}

func testIdentityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		switch {
		case c.Request.Method == http.MethodGet,
			strings.Contains(path, "/approve"),
			strings.Contains(path, "/reject"),
			strings.Contains(path, "/cancel"):
			c.Set("email", approverEmail)
			c.Set("username", approverName)
		default:
			c.Set("email", requesterEmail)
			c.Set("username", requesterName)
		}
		c.Set("groups", []string{"system:authenticated"})
		c.Next()
	}
}

func TestEndToEndSessionFlowAuthorizesSAR(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)

	env.approveSession(t, sessions[0].Name)
	sessions = env.listSessions(t)
	require.Equal(t, v1alpha1.SessionStateApproved, sessions[0].Status.State)

	resp := env.invokeSAR(t)
	require.True(t, resp.Status.Allowed, "expected SAR to be allowed after approved session")
	require.GreaterOrEqual(t, env.sarRequests, 1, "session SAR should have contacted the target cluster")
}

func TestEndToEndSARDeniedWithoutSession(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "expected SAR to be denied without sessions")
	require.Contains(t, resp.Status.Reason, "Access denied")
	require.Equal(t, 0, env.sarRequests, "no session SAR call should occur when no sessions are active")
}

func TestEndToEndSARDeniedWhileSessionPending(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	require.Equal(t, v1alpha1.SessionStatePending, sessions[0].Status.State)

	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "pending sessions must not authorize access")
	require.Contains(t, resp.Status.Reason, "Access denied")
	require.Equal(t, 0, env.sarRequests, "no SARs should hit the remote cluster while session is pending")
}

func TestEndToEndSARDeniedWithExpiredSession(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	expiredAt := metav1.NewTime(time.Now().Add(-1 * time.Hour))
	env.updateSessionStatus(t, sessions[0].Name, func(bs *v1alpha1.BreakglassSession) {
		bs.Status.ExpiresAt = expiredAt
		bs.Status.State = v1alpha1.SessionStateExpired
	})

	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "expired sessions must not authorize access")
	require.Contains(t, resp.Status.Reason, "Access denied")
	require.Equal(t, 0, env.sarRequests, "expired sessions must not trigger outbound SARs")
}

func TestEndToEndSARDeniedForDifferentCluster(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	resp := env.invokeSARForCluster(t, e2eAltClusterName)
	require.False(t, resp.Status.Allowed, "sessions must be cluster-scoped")
	require.Contains(t, resp.Status.Reason, e2eAltClusterName)
	require.Equal(t, 0, env.sarRequests, "cluster mismatch should not call downstream SAR")
}

func TestEndToEndSARDeniedForIDPIssuerMismatch(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	const (
		storedIssuer = "https://issuer.authorized"
		otherIssuer  = "https://issuer.mismatched"
	)
	env.updateSessionSpec(t, sessions[0].Name, func(bs *v1alpha1.BreakglassSession) {
		bs.Spec.IdentityProviderName = "trusted-idp"
		bs.Spec.IdentityProviderIssuer = storedIssuer
		bs.Spec.AllowIDPMismatch = false
	})

	resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.Extra = map[string]authorizationv1.ExtraValue{
			"identity.t-caas.telekom.com/issuer": {otherIssuer},
		}
	})
	require.False(t, resp.Status.Allowed, "issuer mismatches must deny the request")
	require.Contains(t, resp.Status.Reason, "different identity provider")
	require.Equal(t, 0, env.sarRequests, "issuer mismatch should not call downstream SAR")
}

func TestEndToEndSARDeniedByGlobalDenyPolicy(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	env.createDenyPolicy(t, "global-block", v1alpha1.DenyPolicySpec{
		AppliesTo: &v1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Rules: []v1alpha1.DenyRule{{
			Verbs:     []string{"create"},
			APIGroups: []string{""},
			Resources: []string{"pods"},
		}},
	})

	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "global deny policies should short-circuit authorization")
	require.Contains(t, resp.Status.Reason, "Denied by policy", "deny reason should reference policy")
	require.Equal(t, 0, env.sarRequests, "policy-denied requests never reach target cluster")
}

func TestEndToEndSARDeniedBySessionScopedPolicy(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	env.createDenyPolicy(t, "session-block", v1alpha1.DenyPolicySpec{
		AppliesTo: &v1alpha1.DenyPolicyScope{Sessions: []string{sessions[0].Name}},
		Rules: []v1alpha1.DenyRule{{
			Verbs:     []string{"create"},
			APIGroups: []string{""},
			Resources: []string{"pods"},
		}},
	})

	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "session-scoped deny policies should block only targeted session")
	require.Contains(t, resp.Status.Reason, "Denied by policy")
	require.Equal(t, 0, env.sarRequests, "session policy denial should happen before downstream SAR")
}

func TestEndToEndSessionSARDeniedByTargetCluster(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	env.allowSessionSAR = false
	resp := env.invokeSAR(t)
	require.False(t, resp.Status.Allowed, "target cluster RBAC denial should bubble up")
	require.Contains(t, resp.Status.Reason, "Access denied")
	require.Greater(t, env.sarRequests, 0, "session SAR should hit target cluster when impersonation runs")
}

func (env *apiEndToEndEnv) updateSessionStatus(t *testing.T, name string, mutate func(*v1alpha1.BreakglassSession)) {
	t.Helper()
	ctx := context.Background()
	var session v1alpha1.BreakglassSession
	require.NoError(t, env.client.Get(ctx, client.ObjectKey{Namespace: e2eNamespace, Name: name}, &session))
	mutate(&session)
	require.NoError(t, env.client.Status().Update(ctx, &session))
}

func (env *apiEndToEndEnv) updateSessionSpec(t *testing.T, name string, mutate func(*v1alpha1.BreakglassSession)) {
	t.Helper()
	ctx := context.Background()
	var session v1alpha1.BreakglassSession
	require.NoError(t, env.client.Get(ctx, client.ObjectKey{Namespace: e2eNamespace, Name: name}, &session))
	mutate(&session)
	require.NoError(t, env.client.Update(ctx, &session))
}

func (env *apiEndToEndEnv) createDenyPolicy(t *testing.T, name string, spec v1alpha1.DenyPolicySpec) {
	t.Helper()
	ctx := context.Background()
	dp := &v1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	require.NoError(t, env.client.Create(ctx, dp))
}

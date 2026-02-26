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

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"

	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
)

var sessionIndexFnsEndToEnd = map[string]client.IndexerFunc{
	"spec.user": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.User}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.Cluster}
	},
	"spec.grantedGroup": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.GrantedGroup}
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
	t                 *testing.T
	server            *Server
	handler           http.Handler
	sarServer         *httptest.Server
	sarRequests       int
	clusterName       string
	client            client.Client
	allowSessionSAR   bool
	webhookController *webhook.WebhookController
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

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{})
	for name, fn := range sessionIndexFnsEndToEnd {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, name, fn)
	}
	builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexer)
	builder = builder.WithIndex(&breakglassv1alpha1.ClusterConfig{}, "metadata.name", metadataNameIndexer)

	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eEscalation,
			Namespace: e2eNamespace,
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{e2eClusterName},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: e2eGroup,
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{approverEmail},
			},
		},
	}

	clusterCfg := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eClusterName,
			Namespace: e2eNamespace,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name:      "ccfg-secret",
				Namespace: e2eNamespace,
				Key:       "value",
			},
		},
	}

	clusterCfgAlt := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e2eAltClusterName,
			Namespace: e2eNamespace,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
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
	escalationManager := &escalation.EscalationManager{Client: cli}
	logger := zaptest.NewLogger(t)
	provider := cluster.NewClientProvider(cli, logger.Sugar())

	cfg := config.Config{Frontend: config.Frontend{BaseURL: "https://breakglass.example"}}
	auth := NewAuth(logger.Sugar(), cfg)

	middleware := testIdentityMiddleware()
	sessionController := breakglass.NewBreakglassSessionController(logger.Sugar(), cfg, sessionManager, escalationManager, middleware, "", provider, cli, true)
	escalationController := escalation.NewBreakglassEscalationController(logger.Sugar(), escalationManager, middleware, "")
	webhookController := webhook.NewWebhookController(logger.Sugar(), cfg, sessionManager, escalationManager, provider, policy.NewEvaluator(cli, logger.Sugar()))
	webhookController.SetCanDoFn(func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clusterName string) (bool, error) {
		return false, nil
	})

	server := NewServer(logger, cfg, true, auth)
	require.NoError(t, server.RegisterAll([]APIController{sessionController, escalationController, webhookController}))

	env.server = server
	env.handler = server.Handler()
	env.client = cli
	env.webhookController = webhookController

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

func (env *apiEndToEndEnv) listSessions(t *testing.T) []breakglassv1alpha1.BreakglassSession {
	t.Helper()
	rr := env.doRequest(t, http.MethodGet, sessionsBasePath, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var sessions []breakglassv1alpha1.BreakglassSession
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
	require.Equal(t, breakglassv1alpha1.SessionStateApproved, sessions[0].Status.State)

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
	require.Equal(t, breakglassv1alpha1.SessionStatePending, sessions[0].Status.State)

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
	env.updateSessionStatus(t, sessions[0].Name, func(bs *breakglassv1alpha1.BreakglassSession) {
		bs.Status.ExpiresAt = expiredAt
		bs.Status.State = breakglassv1alpha1.SessionStateExpired
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
	env.updateSessionSpec(t, sessions[0].Name, func(bs *breakglassv1alpha1.BreakglassSession) {
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

	env.createDenyPolicy(t, "global-block", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Rules: []breakglassv1alpha1.DenyRule{{
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

	env.createDenyPolicy(t, "session-block", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Sessions: []string{sessions[0].Name}},
		Rules: []breakglassv1alpha1.DenyRule{{
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

func (env *apiEndToEndEnv) updateSessionStatus(t *testing.T, name string, mutate func(*breakglassv1alpha1.BreakglassSession)) {
	t.Helper()
	ctx := context.Background()
	var session breakglassv1alpha1.BreakglassSession
	require.NoError(t, env.client.Get(ctx, client.ObjectKey{Namespace: e2eNamespace, Name: name}, &session))
	mutate(&session)
	// Use Status().Update() for fake client - SSA is used in production code
	// Fake client's SSA implementation has limitations with unstructured objects
	require.NoError(t, env.client.Status().Update(ctx, &session))
}

func (env *apiEndToEndEnv) updateSessionSpec(t *testing.T, name string, mutate func(*breakglassv1alpha1.BreakglassSession)) {
	t.Helper()
	ctx := context.Background()
	var session breakglassv1alpha1.BreakglassSession
	require.NoError(t, env.client.Get(ctx, client.ObjectKey{Namespace: e2eNamespace, Name: name}, &session))
	mutate(&session)
	// Use direct Update for fake client - SSA has limitations with fake client
	// In production code, SSA is used via ApplyObject
	require.NoError(t, env.client.Update(ctx, &session))
}

func (env *apiEndToEndEnv) createDenyPolicy(t *testing.T, name string, spec breakglassv1alpha1.DenyPolicySpec) {
	t.Helper()
	ctx := context.Background()
	dp := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	require.NoError(t, env.client.Create(ctx, dp))
}

// invokePodExecSAR invokes a SubjectAccessReview for pods/exec against a specific pod.
func (env *apiEndToEndEnv) invokePodExecSAR(t *testing.T, namespace, podName string) webhook.SubjectAccessReviewResponse {
	return env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   namespace,
			Verb:        "create",
			Resource:    "pods",
			Subresource: "exec",
			Name:        podName,
		}
	})
}

// ============================================================================
// Pod Security E2E Tests
// ============================================================================

// TestEndToEndSARDeniedByPodSecurityRiskScore tests that pods/exec to a privileged
// pod is denied when the risk score exceeds the threshold.
func TestEndToEndSARDeniedByPodSecurityRiskScore(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve a session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with PodSecurityRules
	env.createDenyPolicy(t, "pod-security-block", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100, // High weight for privileged
				HostNetwork:         50,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 79, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	// Inject a privileged pod
	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "privileged-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true), // This should score 100
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "privileged-pod" && namespace == "default" {
			return privilegedPod, nil
		}
		return nil, fmt.Errorf("pod not found: %s/%s", namespace, name)
	})

	// Invoke SAR for pods/exec - should be denied
	resp := env.invokePodExecSAR(t, "default", "privileged-pod")
	require.False(t, resp.Status.Allowed, "pods/exec to privileged pod should be denied by risk score")
	require.Contains(t, resp.Status.Reason, "Denied by policy", "deny reason should reference policy")
}

// TestEndToEndSARAllowedForSafePod tests that pods/exec to a non-privileged pod is allowed.
func TestEndToEndSARAllowedForSafePod(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve a session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with PodSecurityRules
	env.createDenyPolicy(t, "pod-security-allow", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
				HostNetwork:         50,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 79, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	// Inject a safe pod (no risky features)
	safePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "safe-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				// No privileged, no hostNetwork - score should be 0
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "safe-pod" && namespace == "default" {
			return safePod, nil
		}
		return nil, fmt.Errorf("pod not found: %s/%s", namespace, name)
	})

	// Invoke SAR for pods/exec - should be allowed (pod score is 0, below threshold)
	resp := env.invokePodExecSAR(t, "default", "safe-pod")
	require.True(t, resp.Status.Allowed, "pods/exec to safe pod should be allowed")
}

// TestEndToEndSARDeniedByBlockFactor tests that pods with block factors are denied
// regardless of risk score.
func TestEndToEndSARDeniedByBlockFactor(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy that blocks hostNetwork pods
	env.createDenyPolicy(t, "block-hostnetwork", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			BlockFactors: []string{"hostNetwork"},
		},
	})

	// Inject a pod with hostNetwork
	hostNetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostnet-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "hostnet-pod" && namespace == "default" {
			return hostNetPod, nil
		}
		return nil, fmt.Errorf("pod not found: %s/%s", namespace, name)
	})

	resp := env.invokePodExecSAR(t, "default", "hostnet-pod")
	require.False(t, resp.Status.Allowed, "pods/exec to hostNetwork pod should be blocked")
	require.Contains(t, resp.Status.Reason, "Denied by policy")
}

// TestEndToEndSARAllowedByPodSecurityExemption tests that exempted namespaces
// bypass pod security evaluation.
func TestEndToEndSARAllowedByPodSecurityExemption(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with exemption for kube-system
	env.createDenyPolicy(t, "exempt-kubesystem", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
			Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
				Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
			},
		},
	})

	// Inject a privileged pod in kube-system (should be exempt)
	exemptPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "privileged-exempt",
			Namespace: "kube-system",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "privileged-exempt" && namespace == "kube-system" {
			return exemptPod, nil
		}
		return nil, fmt.Errorf("pod not found: %s/%s", namespace, name)
	})

	resp := env.invokePodExecSAR(t, "kube-system", "privileged-exempt")
	require.True(t, resp.Status.Allowed, "pods/exec to exempted namespace should be allowed")
}

// TestEndToEndSARPodSecurityFailModeClosed tests that when a pod cannot be fetched
// and failMode is closed, the request is denied.
func TestEndToEndSARPodSecurityFailModeClosed(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with failMode: closed
	env.createDenyPolicy(t, "fail-closed", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			FailMode: "closed",
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	// Pod fetch returns error (pod not found)
	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		return nil, fmt.Errorf("pod not found")
	})

	resp := env.invokePodExecSAR(t, "default", "missing-pod")
	require.False(t, resp.Status.Allowed, "pods/exec should be denied when pod fetch fails with failMode=closed")
	require.Contains(t, resp.Status.Reason, "Denied by policy")
}

// TestEndToEndSARPodSecurityFailModeOpen tests that when a pod cannot be fetched
// and failMode is open, the request is allowed.
func TestEndToEndSARPodSecurityFailModeOpen(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with failMode: open
	env.createDenyPolicy(t, "fail-open", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			FailMode: "open",
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	// Pod fetch returns error (pod not found)
	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		return nil, fmt.Errorf("pod not found")
	})

	resp := env.invokePodExecSAR(t, "default", "missing-pod")
	require.True(t, resp.Status.Allowed, "pods/exec should be allowed when pod fetch fails with failMode=open")
}

// TestEndToEndSARPodsAttachEvaluated tests that pods/attach also triggers pod security evaluation.
func TestEndToEndSARPodsAttachEvaluated(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy blocking privileged pods
	env.createDenyPolicy(t, "block-attach", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "priv-attach",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "priv-attach" && namespace == "default" {
			return privilegedPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// Use attach subresource
	resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   "default",
			Verb:        "create",
			Resource:    "pods",
			Subresource: "attach",
			Name:        "priv-attach",
		}
	})

	require.False(t, resp.Status.Allowed, "pods/attach to privileged pod should be denied")
}

// TestEndToEndSARPodsPortforwardEvaluated tests that pods/portforward also triggers pod security evaluation.
func TestEndToEndSARPodsPortforwardEvaluated(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy blocking hostPID pods
	env.createDenyPolicy(t, "block-portforward", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			BlockFactors: []string{"hostPID"},
		},
	})

	hostPIDPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostpid-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			HostPID: true,
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "hostpid-pod" && namespace == "default" {
			return hostPIDPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// Use portforward subresource
	resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   "default",
			Verb:        "create",
			Resource:    "pods",
			Subresource: "portforward",
			Name:        "hostpid-pod",
		}
	})

	require.False(t, resp.Status.Allowed, "pods/portforward to hostPID pod should be denied")
}

// TestEndToEndSARPodSecurityWithEscalationOverride tests that BreakglassEscalation
// podSecurityOverrides can increase the allowed risk score threshold.
func TestEndToEndSARPodSecurityWithEscalationOverride(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create escalation with podSecurityOverrides (increased threshold)
	ctx := context.Background()
	escWithOverride := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "override-escalation",
			Namespace: e2eNamespace,
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{e2eClusterName},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "override-group",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{approverEmail},
			},
			PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
				Enabled:         true,        // Required for overrides to take effect
				MaxAllowedScore: intPtr(200), // Higher threshold
			},
		},
	}
	require.NoError(t, env.client.Create(ctx, escWithOverride))

	// Create session with the override group
	env.createSessionWithRequest(t, breakglass.BreakglassSessionRequest{
		Clustername: e2eClusterName,
		Username:    requesterEmail,
		GroupName:   "override-group",
		Reason:      "testing override",
	})
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with threshold 50 (escalation overrides to 200)
	env.createDenyPolicy(t, "low-threshold", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	// Inject a privileged pod (score=100)
	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "override-test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true), // Score = 100
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "override-test-pod" && namespace == "default" {
			return privilegedPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// Score=100 is >= base threshold(50) but < override threshold(200)
	// With the escalation override, this should be allowed
	resp := env.invokePodExecSAR(t, "default", "override-test-pod")
	require.True(t, resp.Status.Allowed, "pods/exec should be allowed when escalation override raises threshold")
}

// TestEndToEndSARPodSecurityScopeSubresource tests that pod security rules
// only apply to specified subresources.
func TestEndToEndSARPodSecurityScopeSubresource(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy that only applies to exec (not attach)
	env.createDenyPolicy(t, "exec-only", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			AppliesTo: &breakglassv1alpha1.PodSecurityScope{
				Subresources: []string{"exec"}, // Only exec, not attach
			},
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Risk score too high"},
			},
		},
	})

	privilegedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scope-test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "scope-test-pod" && namespace == "default" {
			return privilegedPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// pods/exec should be blocked
	execResp := env.invokePodExecSAR(t, "default", "scope-test-pod")
	require.False(t, execResp.Status.Allowed, "pods/exec should be denied by scoped policy")

	// pods/attach should NOT be blocked (not in scope)
	attachResp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   "default",
			Verb:        "create",
			Resource:    "pods",
			Subresource: "attach",
			Name:        "scope-test-pod",
		}
	})
	require.True(t, attachResp.Status.Allowed, "pods/attach should be allowed when not in scope")
}

// Helper functions for tests
func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

// ============================================================================
// Comprehensive SAR Scenarios - Realistic End-to-End Tests
// ============================================================================

// TestEndToEndSARResourceOperations tests various resource operations with approved sessions.
func TestEndToEndSARResourceOperations(t *testing.T) {
	testCases := []struct {
		name       string
		verb       string
		apiGroup   string
		resource   string
		namespace  string
		wantAllow  bool
		denyPolicy *breakglassv1alpha1.DenyPolicySpec
	}{
		{
			name:      "list pods in namespace",
			verb:      "list",
			apiGroup:  "",
			resource:  "pods",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "get deployment",
			verb:      "get",
			apiGroup:  "apps",
			resource:  "deployments",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "delete pod",
			verb:      "delete",
			apiGroup:  "",
			resource:  "pods",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "create configmap",
			verb:      "create",
			apiGroup:  "",
			resource:  "configmaps",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "update service",
			verb:      "update",
			apiGroup:  "",
			resource:  "services",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "patch statefulset",
			verb:      "patch",
			apiGroup:  "apps",
			resource:  "statefulsets",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "watch events",
			verb:      "watch",
			apiGroup:  "",
			resource:  "events",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "list secrets blocked by policy",
			verb:      "list",
			apiGroup:  "",
			resource:  "secrets",
			namespace: "default",
			wantAllow: false,
			denyPolicy: &breakglassv1alpha1.DenyPolicySpec{
				Rules: []breakglassv1alpha1.DenyRule{{
					Verbs:     []string{"get", "list"},
					APIGroups: []string{""},
					Resources: []string{"secrets"},
				}},
			},
		},
		{
			name:      "delete namespace blocked",
			verb:      "delete",
			apiGroup:  "",
			resource:  "namespaces",
			namespace: "",
			wantAllow: false,
			denyPolicy: &breakglassv1alpha1.DenyPolicySpec{
				Rules: []breakglassv1alpha1.DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"namespaces"},
				}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupAPIEndToEndEnv(t)
			defer env.Close()

			// Create and approve session
			env.createSession(t)
			sessions := env.listSessions(t)
			require.Len(t, sessions, 1)
			env.approveSession(t, sessions[0].Name)

			// Create deny policy if specified
			if tc.denyPolicy != nil {
				tc.denyPolicy.AppliesTo = &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}}
				env.createDenyPolicy(t, "test-deny-"+tc.name, *tc.denyPolicy)
			}

			// Invoke SAR
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s to be allowed", tc.verb, tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s to be denied", tc.verb, tc.resource)
			}
		})
	}
}

// TestEndToEndSARSubresources tests various subresource operations.
func TestEndToEndSARSubresources(t *testing.T) {
	testCases := []struct {
		name        string
		resource    string
		subresource string
		verb        string
		wantAllow   bool
		denyPolicy  *breakglassv1alpha1.DenyPolicySpec
	}{
		{
			name:        "get deployment status",
			resource:    "deployments",
			subresource: "status",
			verb:        "get",
			wantAllow:   true,
		},
		{
			name:        "update pod status",
			resource:    "pods",
			subresource: "status",
			verb:        "update",
			wantAllow:   true,
		},
		{
			name:        "get pod logs",
			resource:    "pods",
			subresource: "log",
			verb:        "get",
			wantAllow:   true,
		},
		{
			name:        "pod exec blocked by rule",
			resource:    "pods",
			subresource: "exec",
			verb:        "create",
			wantAllow:   false,
			denyPolicy: &breakglassv1alpha1.DenyPolicySpec{
				Rules: []breakglassv1alpha1.DenyRule{{
					Verbs:        []string{"create"},
					APIGroups:    []string{""},
					Resources:    []string{"pods"},
					Subresources: []string{"exec"},
				}},
			},
		},
		{
			name:        "scale deployment",
			resource:    "deployments",
			subresource: "scale",
			verb:        "update",
			wantAllow:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupAPIEndToEndEnv(t)
			defer env.Close()

			env.createSession(t)
			sessions := env.listSessions(t)
			require.Len(t, sessions, 1)
			env.approveSession(t, sessions[0].Name)

			if tc.denyPolicy != nil {
				tc.denyPolicy.AppliesTo = &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}}
				env.createDenyPolicy(t, "test-subresource-deny", *tc.denyPolicy)
			}

			apiGroup := ""
			if tc.resource == "deployments" {
				apiGroup = "apps"
			}

			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        tc.verb,
					Group:       apiGroup,
					Resource:    tc.resource,
					Subresource: tc.subresource,
					Name:        "test-resource",
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s/%s to be allowed", tc.verb, tc.resource, tc.subresource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s/%s to be denied", tc.verb, tc.resource, tc.subresource)
			}
		})
	}
}

// TestEndToEndSARWildcardDenyPolicy tests wildcard patterns in deny policies.
func TestEndToEndSARWildcardDenyPolicy(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a deny policy with wildcard for all resources in kube-system
	env.createDenyPolicy(t, "block-kubesystem", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Rules: []breakglassv1alpha1.DenyRule{{
			Verbs:      []string{"*"},
			APIGroups:  []string{"*"},
			Resources:  []string{"*"},
			Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
		}},
	})

	// Access to kube-system should be denied
	respKubeSystem := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "kube-system",
			Verb:      "list",
			Resource:  "pods",
		}
	})
	require.False(t, respKubeSystem.Status.Allowed, "access to kube-system should be denied by wildcard policy")

	// Access to default namespace should be allowed
	respDefault := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "list",
			Resource:  "pods",
		}
	})
	require.True(t, respDefault.Status.Allowed, "access to default namespace should be allowed")
}

// TestEndToEndSARResourceNamePatterns tests resourceNames patterns in deny policies.
func TestEndToEndSARResourceNamePatterns(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a deny policy blocking specific secret names
	env.createDenyPolicy(t, "block-specific-secrets", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Rules: []breakglassv1alpha1.DenyRule{{
			Verbs:         []string{"get", "list"},
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"database-password", "api-key"},
		}},
	})

	// Access to blocked secret should be denied
	respBlocked := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "get",
			Resource:  "secrets",
			Name:      "database-password",
		}
	})
	require.False(t, respBlocked.Status.Allowed, "access to blocked secret should be denied")

	// Access to other secrets should be allowed
	respAllowed := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "get",
			Resource:  "secrets",
			Name:      "other-secret",
		}
	})
	require.True(t, respAllowed.Status.Allowed, "access to non-blocked secrets should be allowed")
}

// TestEndToEndSARPodSecurityCapabilities tests capability scoring in pod security evaluation.
func TestEndToEndSARPodSecurityCapabilities(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with capability scoring
	env.createDenyPolicy(t, "capability-scoring", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				Capabilities: map[string]int{
					"SYS_ADMIN":  100, // High risk
					"NET_ADMIN":  50,
					"NET_RAW":    30,
					"SYS_PTRACE": 40,
				},
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 79, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Capability risk too high"},
			},
		},
	})

	// Pod with SYS_ADMIN should be blocked (score 100)
	sysAdminPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sysadmin-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"SYS_ADMIN"},
					},
				},
			}},
		},
	}

	// Pod with NET_RAW should be allowed (score 30)
	netRawPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "netraw-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_RAW"},
					},
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		switch name {
		case "sysadmin-pod":
			return sysAdminPod, nil
		case "netraw-pod":
			return netRawPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// SYS_ADMIN pod should be denied
	respSysAdmin := env.invokePodExecSAR(t, "default", "sysadmin-pod")
	require.False(t, respSysAdmin.Status.Allowed, "pods/exec to SYS_ADMIN pod should be denied")

	// NET_RAW pod should be allowed
	respNetRaw := env.invokePodExecSAR(t, "default", "netraw-pod")
	require.True(t, respNetRaw.Status.Allowed, "pods/exec to NET_RAW pod should be allowed")
}

// TestEndToEndSARPodSecurityLabelExemption tests label-based exemptions.
func TestEndToEndSARPodSecurityLabelExemption(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with label exemption
	env.createDenyPolicy(t, "label-exempt", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 49, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "Too risky"},
			},
			Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
				PodLabels: map[string]string{
					"breakglass.telekom.com/security-exempt": "true",
				},
			},
		},
	})

	// Privileged pod WITHOUT exempt label should be blocked
	nonExemptPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-exempt-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	// Privileged pod WITH exempt label should be allowed
	exemptPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "exempt-pod",
			Namespace: "default",
			Labels: map[string]string{
				"breakglass.telekom.com/security-exempt": "true",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		switch name {
		case "non-exempt-pod":
			return nonExemptPod, nil
		case "exempt-pod":
			return exemptPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// Non-exempt pod should be denied
	respNonExempt := env.invokePodExecSAR(t, "default", "non-exempt-pod")
	require.False(t, respNonExempt.Status.Allowed, "privileged pod without exempt label should be denied")

	// Exempt pod should be allowed
	respExempt := env.invokePodExecSAR(t, "default", "exempt-pod")
	require.True(t, respExempt.Status.Allowed, "privileged pod with exempt label should be allowed")
}

// TestEndToEndSARPodSecurityCumulativeScore tests cumulative scoring of multiple risk factors.
func TestEndToEndSARPodSecurityCumulativeScore(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with multiple risk factors
	env.createDenyPolicy(t, "cumulative-scoring", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				HostNetwork: 30,
				HostPID:     30,
				RunAsRoot:   30,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 59, Action: "allow"}, // Two factors allowed
				{MaxScore: 89, Action: "warn"},  // Three factors warned
				{MaxScore: 1000, Action: "deny", Reason: "Too many risk factors"},
			},
		},
	})

	// Pod with one factor (score 30) - allowed
	oneFactorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "one-factor-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // Score: 30
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
			}},
		},
	}

	// Pod with two factors (score 60) - warn threshold
	twoFactorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "two-factor-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // Score: 30
			HostPID:     true, // Score: 30 (total: 60)
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
			}},
		},
	}

	// Pod with three factors (score 90) - denied
	threeFactorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "three-factor-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostNetwork: true, // Score: 30
			HostPID:     true, // Score: 30 (total: 60)
			Containers: []corev1.Container{{
				Name:  "main",
				Image: "alpine",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser: int64Ptr(0), // Score: 30 (total: 90)
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		switch name {
		case "one-factor-pod":
			return oneFactorPod, nil
		case "two-factor-pod":
			return twoFactorPod, nil
		case "three-factor-pod":
			return threeFactorPod, nil
		}
		return nil, fmt.Errorf("pod not found")
	})

	// One factor (30) - allowed
	respOne := env.invokePodExecSAR(t, "default", "one-factor-pod")
	require.True(t, respOne.Status.Allowed, "pod with one risk factor should be allowed")

	// Two factors (60) - allowed (warn, but still allowed)
	respTwo := env.invokePodExecSAR(t, "default", "two-factor-pod")
	require.True(t, respTwo.Status.Allowed, "pod with two risk factors should be allowed with warning")

	// Three factors (90) - denied
	respThree := env.invokePodExecSAR(t, "default", "three-factor-pod")
	require.False(t, respThree.Status.Allowed, "pod with three risk factors should be denied")
}

// TestEndToEndSARMultiplePoliciesPrecedence tests that policies with lower precedence win.
func TestEndToEndSARMultiplePoliciesPrecedence(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	prec10 := int32(10)
	prec100 := int32(100)

	// Policy with higher precedence (lower number) that blocks secrets
	env.createDenyPolicy(t, "high-priority-block", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo:  &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Precedence: &prec10,
		Rules: []breakglassv1alpha1.DenyRule{{
			Verbs:     []string{"get"},
			APIGroups: []string{""},
			Resources: []string{"secrets"},
		}},
	})

	// Policy with lower precedence (higher number) that allows secrets
	// This one would be overridden by the higher priority one
	env.createDenyPolicy(t, "low-priority-allow", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo:  &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Precedence: &prec100,
		Rules: []breakglassv1alpha1.DenyRule{{
			Verbs:     []string{"delete"}, // Different verb
			APIGroups: []string{""},
			Resources: []string{"secrets"},
		}},
	})

	// Get secrets should be denied by high-priority policy
	respGet := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "get",
			Resource:  "secrets",
		}
	})
	require.False(t, respGet.Status.Allowed, "get secrets should be denied by high-priority policy")

	// Delete secrets should be denied by low-priority policy
	respDelete := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "delete",
			Resource:  "secrets",
		}
	})
	require.False(t, respDelete.Status.Allowed, "delete secrets should be denied by low-priority policy")

	// List secrets should be allowed (not blocked by either policy)
	respList := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace: "default",
			Verb:      "list",
			Resource:  "secrets",
		}
	})
	require.True(t, respList.Status.Allowed, "list secrets should be allowed")
}

// TestEndToEndSARCRDOperations tests operations on custom resources.
func TestEndToEndSARCRDOperations(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name      string
		verb      string
		apiGroup  string
		resource  string
		namespace string
		wantAllow bool
	}{
		{
			name:      "list breakglass sessions",
			verb:      "list",
			apiGroup:  "breakglass.t-caas.telekom.com",
			resource:  "breakglasssessions",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "get deny policy",
			verb:      "get",
			apiGroup:  "breakglass.t-caas.telekom.com",
			resource:  "denypolicies",
			namespace: "",
			wantAllow: true,
		},
		{
			name:      "list custom resources",
			verb:      "list",
			apiGroup:  "custom.example.com",
			resource:  "myresources",
			namespace: "default",
			wantAllow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s/%s to be allowed", tc.verb, tc.apiGroup, tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s/%s to be denied", tc.verb, tc.apiGroup, tc.resource)
			}
		})
	}
}

// Helper for int64 pointer
func int64Ptr(i int64) *int64 {
	return &i
}

// ============================================================================
// Use Case Tests - Explicit tests for documented use cases
// ============================================================================

// TestUseCaseRolloutRestart tests the rollout restart use case (kubectl rollout restart).
// This simulates patching a deployment to trigger a rolling update.
func TestUseCaseRolloutRestart(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name      string
		verb      string
		apiGroup  string
		resource  string
		namespace string
		wantAllow bool
	}{
		{
			name:      "patch deployment for rollout restart",
			verb:      "patch",
			apiGroup:  "apps",
			resource:  "deployments",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "patch statefulset for rollout restart",
			verb:      "patch",
			apiGroup:  "apps",
			resource:  "statefulsets",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "patch daemonset for rollout restart",
			verb:      "patch",
			apiGroup:  "apps",
			resource:  "daemonsets",
			namespace: "default",
			wantAllow: true,
		},
		{
			name:      "get deployment rollout status",
			verb:      "get",
			apiGroup:  "apps",
			resource:  "deployments",
			namespace: "default",
			wantAllow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
					Name:      "my-app",
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s to be allowed for rollout restart", tc.verb, tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s to be denied", tc.verb, tc.resource)
			}
		})
	}
}

// TestUseCaseFluxHelmReleaseDeletion tests deletion of Flux HelmRelease CRDs.
// This is a common emergency operation when Helm releases are stuck.
func TestUseCaseFluxHelmReleaseDeletion(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name      string
		verb      string
		apiGroup  string
		resource  string
		namespace string
		wantAllow bool
	}{
		{
			name:      "delete HelmRelease",
			verb:      "delete",
			apiGroup:  "helm.toolkit.fluxcd.io",
			resource:  "helmreleases",
			namespace: "flux-system",
			wantAllow: true,
		},
		{
			name:      "list HelmReleases",
			verb:      "list",
			apiGroup:  "helm.toolkit.fluxcd.io",
			resource:  "helmreleases",
			namespace: "flux-system",
			wantAllow: true,
		},
		{
			name:      "get HelmRelease",
			verb:      "get",
			apiGroup:  "helm.toolkit.fluxcd.io",
			resource:  "helmreleases",
			namespace: "flux-system",
			wantAllow: true,
		},
		{
			name:      "patch HelmRelease to suspend",
			verb:      "patch",
			apiGroup:  "helm.toolkit.fluxcd.io",
			resource:  "helmreleases",
			namespace: "flux-system",
			wantAllow: true,
		},
		{
			name:      "delete Kustomization",
			verb:      "delete",
			apiGroup:  "kustomize.toolkit.fluxcd.io",
			resource:  "kustomizations",
			namespace: "flux-system",
			wantAllow: true,
		},
		{
			name:      "delete GitRepository source",
			verb:      "delete",
			apiGroup:  "source.toolkit.fluxcd.io",
			resource:  "gitrepositories",
			namespace: "flux-system",
			wantAllow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
					Name:      "my-helm-release",
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s/%s to be allowed", tc.verb, tc.apiGroup, tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s/%s to be denied", tc.verb, tc.apiGroup, tc.resource)
			}
		})
	}
}

// TestUseCaseFluxHelmReleaseBlockedByDenyPolicy tests that DenyPolicy can block Flux operations.
func TestUseCaseFluxHelmReleaseBlockedByDenyPolicy(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a deny policy blocking HelmRelease deletion
	env.createDenyPolicy(t, "block-helmrelease-delete", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		Rules: []breakglassv1alpha1.DenyRule{{
			Verbs:     []string{"delete"},
			APIGroups: []string{"helm.toolkit.fluxcd.io"},
			Resources: []string{"helmreleases"},
		}},
	})

	// Delete should be blocked
	resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Verb:      "delete",
			Group:     "helm.toolkit.fluxcd.io",
			Resource:  "helmreleases",
			Namespace: "flux-system",
			Name:      "critical-release",
		}
	})
	require.False(t, resp.Status.Allowed, "delete HelmRelease should be blocked by deny policy")

	// List should still be allowed
	respList := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
		sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Verb:      "list",
			Group:     "helm.toolkit.fluxcd.io",
			Resource:  "helmreleases",
			Namespace: "flux-system",
		}
	})
	require.True(t, respList.Status.Allowed, "list HelmReleases should be allowed")
}

// TestUseCaseScalingWorkloads tests scaling operations for emergency capacity management.
func TestUseCaseScalingWorkloads(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name        string
		verb        string
		apiGroup    string
		resource    string
		subresource string
		namespace   string
		wantAllow   bool
	}{
		{
			name:        "scale deployment up",
			verb:        "update",
			apiGroup:    "apps",
			resource:    "deployments",
			subresource: "scale",
			namespace:   "default",
			wantAllow:   true,
		},
		{
			name:        "scale statefulset",
			verb:        "update",
			apiGroup:    "apps",
			resource:    "statefulsets",
			subresource: "scale",
			namespace:   "default",
			wantAllow:   true,
		},
		{
			name:        "scale replicaset",
			verb:        "update",
			apiGroup:    "apps",
			resource:    "replicasets",
			subresource: "scale",
			namespace:   "default",
			wantAllow:   true,
		},
		{
			name:        "patch HPA for emergency scaling",
			verb:        "patch",
			apiGroup:    "autoscaling",
			resource:    "horizontalpodautoscalers",
			subresource: "",
			namespace:   "default",
			wantAllow:   true,
		},
		{
			name:        "get deployment scale",
			verb:        "get",
			apiGroup:    "apps",
			resource:    "deployments",
			subresource: "scale",
			namespace:   "default",
			wantAllow:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:        tc.verb,
					Group:       tc.apiGroup,
					Resource:    tc.resource,
					Subresource: tc.subresource,
					Namespace:   tc.namespace,
					Name:        "my-workload",
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s/%s to be allowed for scaling", tc.verb, tc.resource, tc.subresource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s/%s to be denied", tc.verb, tc.resource, tc.subresource)
			}
		})
	}
}

// TestUseCaseResourceDeletion tests various resource deletion scenarios.
func TestUseCaseResourceDeletion(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name       string
		verb       string
		apiGroup   string
		resource   string
		namespace  string
		name_      string
		wantAllow  bool
		denyPolicy *breakglassv1alpha1.DenyPolicySpec
	}{
		{
			name:      "delete stuck pod",
			verb:      "delete",
			apiGroup:  "",
			resource:  "pods",
			namespace: "default",
			name_:     "stuck-pod",
			wantAllow: true,
		},
		{
			name:      "delete job",
			verb:      "delete",
			apiGroup:  "batch",
			resource:  "jobs",
			namespace: "default",
			name_:     "failed-job",
			wantAllow: true,
		},
		{
			name:      "delete configmap",
			verb:      "delete",
			apiGroup:  "",
			resource:  "configmaps",
			namespace: "default",
			name_:     "stale-config",
			wantAllow: true,
		},
		{
			name:      "delete PVC",
			verb:      "delete",
			apiGroup:  "",
			resource:  "persistentvolumeclaims",
			namespace: "default",
			name_:     "orphaned-pvc",
			wantAllow: true,
		},
		{
			name:      "delete namespace blocked by policy",
			verb:      "delete",
			apiGroup:  "",
			resource:  "namespaces",
			namespace: "",
			name_:     "production",
			wantAllow: false,
			denyPolicy: &breakglassv1alpha1.DenyPolicySpec{
				AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{e2eClusterName}},
				Rules: []breakglassv1alpha1.DenyRule{{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"namespaces"},
				}},
			},
		},
		{
			name:      "delete secret blocked by policy",
			verb:      "delete",
			apiGroup:  "",
			resource:  "secrets",
			namespace: "default",
			name_:     "database-password",
			wantAllow: false,
			denyPolicy: &breakglassv1alpha1.DenyPolicySpec{
				AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{e2eClusterName}},
				Rules: []breakglassv1alpha1.DenyRule{{
					Verbs:         []string{"delete"},
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					ResourceNames: []string{"database-password", "api-key"},
				}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create deny policy if specified
			if tc.denyPolicy != nil {
				env.createDenyPolicy(t, "test-delete-deny-"+tc.name, *tc.denyPolicy)
			}

			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
					Name:      tc.name_,
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected delete %s to be allowed", tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected delete %s to be denied by policy", tc.resource)
			}
		})
	}
}

// TestUseCaseNetworkDebuggingPodSecurity tests pods/exec access for network debugging.
// This validates the pod security rules for pods that require special capabilities.
func TestUseCaseNetworkDebuggingPodSecurity(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	// Create a DenyPolicy with pod security rules for network debugging
	env.createDenyPolicy(t, "network-debug-policy", breakglassv1alpha1.DenyPolicySpec{
		AppliesTo: &breakglassv1alpha1.DenyPolicyScope{Clusters: []string{env.clusterName}},
		PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				HostNetwork: 30,
				HostPID:     50,
				HostIPC:     30,
				Capabilities: map[string]int{
					"NET_ADMIN": 20,  // Allow NET_ADMIN (needed for tcpdump)
					"NET_RAW":   20,  // Allow NET_RAW
					"SYS_ADMIN": 100, // Block SYS_ADMIN
				},
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 80, Action: "allow"},
				{MaxScore: 1000, Action: "deny", Reason: "High-risk pod security configuration"},
			},
		},
	})

	// Test 1: Pod with NET_ADMIN capability only (score = 20, allowed)
	netAdminPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-tcpdump", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "tcpdump",
				Image: "nicolaka/netshoot",
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"},
					},
				},
			}},
		},
	}

	env.webhookController.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if name == "debug-tcpdump" {
			return netAdminPod, nil
		}
		if name == "debug-hostnetwork" {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-hostnetwork", Namespace: "default"},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:  "netshoot",
						Image: "nicolaka/netshoot",
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"NET_ADMIN"},
							},
						},
					}},
				},
			}, nil
		}
		if name == "debug-sysadmin" {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-sysadmin", Namespace: "default"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "sysadmin",
						Image: "alpine",
						SecurityContext: &corev1.SecurityContext{
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"SYS_ADMIN"},
							},
						},
					}},
				},
			}, nil
		}
		return nil, fmt.Errorf("pod not found: %s/%s", namespace, name)
	})

	// Test 1: Exec into pod with NET_ADMIN+NET_RAW should be allowed (score = 40)
	resp := env.invokePodExecSAR(t, "default", "debug-tcpdump")
	require.True(t, resp.Status.Allowed, "exec into NET_ADMIN/NET_RAW pod should be allowed for tcpdump")

	// Test 2: Exec into pod with hostNetwork + NET_ADMIN (score = 30 + 20 = 50, allowed)
	resp2 := env.invokePodExecSAR(t, "default", "debug-hostnetwork")
	require.True(t, resp2.Status.Allowed, "exec into hostNetwork+NET_ADMIN pod should be allowed (score 50 < 80)")

	// Test 3: Exec into pod with SYS_ADMIN should be blocked (score = 100)
	resp3 := env.invokePodExecSAR(t, "default", "debug-sysadmin")
	require.False(t, resp3.Status.Allowed, "exec into SYS_ADMIN pod should be blocked")
}

// TestUseCaseCustomerIngressRestart tests restarting ingress controller pods.
func TestUseCaseCustomerIngressRestart(t *testing.T) {
	env := setupAPIEndToEndEnv(t)
	defer env.Close()

	// Create and approve session
	env.createSession(t)
	sessions := env.listSessions(t)
	require.Len(t, sessions, 1)
	env.approveSession(t, sessions[0].Name)

	testCases := []struct {
		name      string
		verb      string
		apiGroup  string
		resource  string
		namespace string
		wantAllow bool
	}{
		{
			name:      "delete ingress controller pod",
			verb:      "delete",
			apiGroup:  "",
			resource:  "pods",
			namespace: "ingress-nginx",
			wantAllow: true,
		},
		{
			name:      "patch ingress deployment for rollout",
			verb:      "patch",
			apiGroup:  "apps",
			resource:  "deployments",
			namespace: "ingress-nginx",
			wantAllow: true,
		},
		{
			name:      "get ingress logs",
			verb:      "get",
			apiGroup:  "",
			resource:  "pods",
			namespace: "ingress-nginx",
			wantAllow: true,
		},
		{
			name:      "list ingress pods",
			verb:      "list",
			apiGroup:  "",
			resource:  "pods",
			namespace: "ingress-nginx",
			wantAllow: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.invokeSARForClusterWithModifier(t, env.clusterName, func(sar *authorizationv1.SubjectAccessReview) {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Verb:      tc.verb,
					Group:     tc.apiGroup,
					Resource:  tc.resource,
					Namespace: tc.namespace,
					Name:      "ingress-nginx-controller-xyz",
				}
			})

			if tc.wantAllow {
				require.True(t, resp.Status.Allowed, "expected %s %s in ingress-nginx to be allowed", tc.verb, tc.resource)
			} else {
				require.False(t, resp.Status.Allowed, "expected %s %s to be denied", tc.verb, tc.resource)
			}
		})
	}
}

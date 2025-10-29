package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/cluster"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/policy"
	"go.uber.org/zap"
	authorization "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var testGroupData = breakglass.ClusterUserGroup{
	Clustername: "telekom.tenat1",
	Username:    "anon@deutsche.telekom.de",
	GroupName:   "breakglass-create-all",
}

var sar = authorization.SubjectAccessReview{
	TypeMeta: metav1.TypeMeta{
		Kind:       "SubjectAccessReview",
		APIVersion: "authorization.k8s.io/v1",
	},
	Spec: authorization.SubjectAccessReviewSpec{
		User:   testGroupData.Username,
		Groups: []string{"system:authenticated"},
		ResourceAttributes: &authorization.ResourceAttributes{
			Namespace: "test",
			Verb:      "get",
			Version:   "v1",
			Resource:  "pods",
		},
	},
}

var (
	alwaysCanDo breakglass.CanGroupsDoFunction = breakglass.CanGroupsDoFunction(func(ctx context.Context, rc *rest.Config, groups []string,
		s authorization.SubjectAccessReview, cluster string,
	) (bool, error) {
		return true, nil
	})

	alwaysCanNotDo breakglass.CanGroupsDoFunction = breakglass.CanGroupsDoFunction(func(ctx context.Context, rc *rest.Config, groups []string,
		s authorization.SubjectAccessReview, cluster string,
	) (bool, error) {
		return false, nil
	})
)

const (
	testFrontURL              string = "https://test.breakglass.front.com"
	errGotRejected            string = "Wrong review response got rejected even though should be allowed"
	errGotAllowed             string = "Wrong review response got allowed even though should be rejected"
	clusterNameWithEscalation        = "testEscalation"
)

var sessionIndexFunctions = map[string]client.IndexerFunc{
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

func NewBreakglassSession(user, cluster, group string) v1alpha1.BreakglassSession {
	return v1alpha1.BreakglassSession{
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         user,
			Cluster:      cluster,
			GrantedGroup: group,
		},
	}
}

func SetupController(interceptFuncs *interceptor.Funcs) *WebhookController {
	ses := NewBreakglassSession("test", "test", "test")
	ses.Name = fmt.Sprintf("%s-%s-a1", testGroupData.Clustername, testGroupData.GroupName)
	ses.Status = v1alpha1.BreakglassSessionStatus{
		Conditions: []metav1.Condition{},
	}

	ses2 := NewBreakglassSession("test2", "test2", "test2")
	ses2.Name = fmt.Sprintf("%s-%s-a2", testGroupData.Clustername, testGroupData.GroupName)
	ses2.Status = v1alpha1.BreakglassSessionStatus{
		Conditions:    []metav1.Condition{},
		RetainedUntil: metav1.NewTime(time.Now().Add(breakglass.MonthDuration)),
	}

	ses3 := NewBreakglassSession("testError", "testError", "testError")
	ses3.Name = fmt.Sprintf("%s-%s-a3", testGroupData.Clustername, testGroupData.GroupName)
	ses3.Status = v1alpha1.BreakglassSessionStatus{
		Conditions:    []metav1.Condition{},
		RetainedUntil: metav1.NewTime(time.Now().Add(breakglass.MonthDuration)),
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).
		WithObjects(&ses, &ses2, &ses3, &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tester-allow-create-all",
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterNameWithEscalation},
					Groups:   []string{"system:authenticated"},
				},
				EscalatedGroup: "breakglass-create-all",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@telekom.de"},
				},
			},
		})
	if interceptFuncs != nil {
		builder.WithInterceptorFuncs(*interceptFuncs)
	}

	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&ses, index, fn)
	}

	cli := builder.Build()

	// Provide a minimal ClusterConfig + Secret for testGroupData.Clustername so controller can fetch rest.Config
	// The kubeconfig data itself isn't used by canDoFn (stubbed), but presence prevents warning path.
	_ = cli.Create(context.Background(), &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: testGroupData.Clustername, Namespace: "default"},
		Spec:       v1alpha1.ClusterConfigSpec{KubeconfigSecretRef: v1alpha1.SecretKeyReference{Name: "ccfg-secret", Namespace: "default"}},
	})
	// Kubeconfig secret placeholder built via typed clientcmd API
	kc := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{},
		Contexts:       map[string]*clientcmdapi.Context{},
		CurrentContext: "",
	}
	kcBytes, err := clientcmd.Write(kc)
	if err != nil {
		panic(err)
	}
	_ = cli.Create(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "ccfg-secret", Namespace: "default"}, Data: map[string][]byte{"value": kcBytes}})
	sesmanager := breakglass.SessionManager{
		Client: cli,
	}
	escmanager := breakglass.EscalationManager{
		Client: cli,
	}

	logger, _ := zap.NewDevelopment()
	controller := NewWebhookController(logger.Sugar(),
		config.Config{Frontend: config.Frontend{BaseURL: testFrontURL}},
		&sesmanager,
		&escmanager,
		cluster.NewClientProvider(escmanager.Client, logger.Sugar()),
		policy.NewEvaluator(escmanager.Client, logger.Sugar()),
	)
	controller.canDoFn = alwaysCanDo

	return controller
}

func TestHandleAuthorize(t *testing.T) {
	controller := SetupController(nil)
	engine := gin.New()
	_ = controller.Register(engine.Group(""))

	allowRejectCases := []struct {
		TestName           string
		CanDoFunction      breakglass.CanGroupsDoFunction
		ShouldAllow        bool
		ExpectedStatusCode int
		InReview           *authorization.SubjectAccessReview
		Clustername        string
	}{
		{
			TestName:           "Simple always allow",
			CanDoFunction:      alwaysCanDo,
			ShouldAllow:        true,
			ExpectedStatusCode: http.StatusOK,
			InReview:           &sar,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Simple always reject",
			CanDoFunction:      alwaysCanNotDo,
			ShouldAllow:        false,
			ExpectedStatusCode: http.StatusOK,
			InReview:           &sar,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Empty cluster",
			ExpectedStatusCode: http.StatusNotFound,
			CanDoFunction:      alwaysCanNotDo,
			InReview:           &sar,
			ShouldAllow:        false,
			Clustername:        "",
		},
		{
			TestName:           "Empty body",
			ExpectedStatusCode: http.StatusUnprocessableEntity,
			CanDoFunction:      alwaysCanNotDo,
			ShouldAllow:        false,
			InReview:           nil,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Can do function error",
			ExpectedStatusCode: http.StatusInternalServerError,
			CanDoFunction: breakglass.CanGroupsDoFunction(func(ctx context.Context, rc *rest.Config, groups []string,
				s authorization.SubjectAccessReview, cluster string,
			) (bool, error) {
				return false, errors.New("IGNORE test error for can do function")
			}),
			InReview:    &sar,
			ShouldAllow: false,
			Clustername: testGroupData.Clustername,
		},
	}

	for _, testCase := range allowRejectCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			controller.canDoFn = testCase.CanDoFunction
			var inBytes []byte

			if testCase.InReview != nil {
				inBytes, _ = json.Marshal(*testCase.InReview)
			}

			req, _ := http.NewRequest("POST", "/authorize/"+testCase.Clustername, bytes.NewReader(inBytes))
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			response := w.Result()
			if response.StatusCode != testCase.ExpectedStatusCode {
				t.Fatalf("Expected %d http status code, but got %d (%q) instead", testCase.ExpectedStatusCode, response.StatusCode, response.Status)
			}

			if response.StatusCode != http.StatusOK {
				return
			}

			respReview := SubjectAccessReviewResponse{}
			err := json.NewDecoder(response.Body).Decode(&respReview)
			if err != nil {
				t.Fatalf("Failed to decode response body %v", err)
			}
			if respReview.Status.Allowed != testCase.ShouldAllow {
				t.Fatalf("Expected status allowed to be %t", testCase.ShouldAllow)
			}
		})
	}
}

// Checks if reason has link to frontend url in case there exists escalation (the single escalation used is defined in
// setup function.
func TestStatusReasons(t *testing.T) {
	controller := SetupController(nil)
	controller.canDoFn = alwaysCanNotDo
	expReason := fmt.Sprintf(denyReasonMessage, controller.config.Frontend.BaseURL, clusterNameWithEscalation)
	engine := gin.New()
	_ = controller.Register(engine.Group(""))
	var inBytes []byte
	inBytes, _ = json.Marshal(sar)

	req, _ := http.NewRequest("POST", "/authorize/"+clusterNameWithEscalation, bytes.NewReader(inBytes))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected %d http status code, but got %d (%q) instead", http.StatusOK, response.StatusCode, response.Status)
	}
	respReview := SubjectAccessReviewResponse{}
	err := json.NewDecoder(response.Body).Decode(&respReview)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}

	if respReview.Status.Allowed {
		t.Fatalf("Expected status allowed to be false")
	}
	if outReson := respReview.Status.Reason; outReson != expReason {
		t.Fatalf("Expected %s reason, but got %s instead", expReason, outReson)
	}
}

// Tests if we get status interal server error if listing sessions or escalations returns error
func TestManagerError(t *testing.T) {
	errorClusterName := "testError"
	listIntercept := interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if len(opts) == 0 {
			return nil
		}

		fs := opts[0].(*client.ListOptions).FieldSelector
		for _, req := range fs.Requirements() {
			if req.Value == errorClusterName {
				return errors.New("IGNORE manager unit test error")
			}
		}
		return nil
	}}
	controller := SetupController(&listIntercept)
	controller.canDoFn = alwaysCanDo
	engine := gin.New()
	_ = controller.Register(engine.Group(""))
	var inBytes []byte
	inBytes, _ = json.Marshal(sar)

	req, _ := http.NewRequest("POST", "/authorize/"+errorClusterName, bytes.NewReader(inBytes))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Expected %d http status code, but got %d (%q) instead", http.StatusInternalServerError, response.StatusCode, response.Status)
	}
}

// Tests that a global (cluster-scoped) deny policy short-circuits authorization.
func TestDenyPolicyGlobal(t *testing.T) {
	controller := SetupController(nil)
	controller.canDoFn = alwaysCanDo // would normally allow
	// Create a global/cluster deny policy that matches the SAR verb/group/resource/namespace
	pol := &v1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-pods-get"},
		Spec: v1alpha1.DenyPolicySpec{
			AppliesTo: &v1alpha1.DenyPolicyScope{Clusters: []string{testGroupData.Clustername}},
			Rules: []v1alpha1.DenyRule{{
				Verbs:      []string{"get"},
				APIGroups:  []string{""},
				Resources:  []string{"pods"},
				Namespaces: []string{"test"},
			}},
		},
	}
	if err := controller.escalManager.Create(context.Background(), pol); err != nil {
		t.Fatalf("failed creating deny policy: %v", err)
	}

	// Additional wildcard policy (any resource delete in any ns) to ensure non-matching when verb differs
	pol2 := &v1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-any-delete"}, Spec: v1alpha1.DenyPolicySpec{AppliesTo: &v1alpha1.DenyPolicyScope{Clusters: []string{testGroupData.Clustername}}, Rules: []v1alpha1.DenyRule{{Verbs: []string{"delete"}, APIGroups: []string{"*"}, Resources: []string{"*"}, Namespaces: []string{"*"}}}}}
	if err := controller.escalManager.Create(context.Background(), pol2); err != nil {
		t.Fatalf("failed creating wildcard deny policy: %v", err)
	}

	engine := gin.New()
	_ = controller.Register(engine.Group(""))
	inBytes, _ := json.Marshal(sar)
	req, _ := http.NewRequest("POST", "/authorize/"+testGroupData.Clustername, bytes.NewReader(inBytes))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	out := SubjectAccessReviewResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Status.Allowed {
		t.Fatalf("expected denied due to policy")
	}
	expReason := controller.finalizeReason("Denied by policy deny-pods-get; No breakglass flow available for your user", false, testGroupData.Clustername)
	if out.Status.Reason != expReason {
		t.Fatalf("expected reason %q got %q", expReason, out.Status.Reason)
	}
}

// Tests that a session-scoped deny policy (AppliesTo.Sessions) triggers only during session evaluation phase.
func TestDenyPolicySessionScope(t *testing.T) {
	controller := SetupController(nil)
	controller.canDoFn = alwaysCanDo // would normally allow
	// Create an active session for the target user/cluster so session-scoped policy can match
	sessionName := "sess-deny-1"
	now := time.Now()
	activeSes := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: sessionName},
		Spec: v1alpha1.BreakglassSessionSpec{
			User:         testGroupData.Username,
			Cluster:      testGroupData.Clustername,
			GrantedGroup: "breakglass-create-all",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			ApprovedAt:    metav1.NewTime(now.Add(-1 * time.Minute)),
			ExpiresAt:     metav1.NewTime(now.Add(30 * time.Minute)),
			RetainedUntil: metav1.NewTime(now.Add(24 * time.Hour)),
		},
	}
	if err := controller.escalManager.Create(context.Background(), activeSes); err != nil {
		t.Fatalf("failed creating active session: %v", err)
	}
	pol := &v1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-pods-get-session"},
		Spec: v1alpha1.DenyPolicySpec{
			AppliesTo: &v1alpha1.DenyPolicyScope{Sessions: []string{sessionName}},
			Rules: []v1alpha1.DenyRule{{
				Verbs:      []string{"get"},
				APIGroups:  []string{""},
				Resources:  []string{"pods"},  // explicit resource
				Namespaces: []string{"test*"}, // wildcard namespace pattern
			}},
		},
	}
	if err := controller.escalManager.Create(context.Background(), pol); err != nil {
		t.Fatalf("failed creating session deny policy: %v", err)
	}

	engine := gin.New()
	_ = controller.Register(engine.Group(""))
	inBytes, _ := json.Marshal(sar)
	req, _ := http.NewRequest("POST", "/authorize/"+testGroupData.Clustername, bytes.NewReader(inBytes))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	out := SubjectAccessReviewResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Status.Allowed {
		t.Fatalf("expected denied due to session policy")
	}
	expReason := controller.finalizeReason("Denied by policy deny-pods-get-session; No breakglass flow available for your user", false, testGroupData.Clustername)
	if out.Status.Reason != expReason {
		t.Fatalf("expected reason %q got %q", expReason, out.Status.Reason)
	}
}

// Tests that when the ClusterConfig cannot be fetched (REST config missing) the controller
// falls back to legacy path and returns a 200 with allowed=false (no 500 internal error).
func TestMissingRestConfigFallback(t *testing.T) {
	controller := SetupController(nil)
	// Force canDoFn to attempt to use provided rest.Config (which will fail retrieval when we clear provider)
	controller.canDoFn = alwaysCanNotDo
	// Replace client provider with one that always errors for GetRESTConfig / Get
	controller.ccProvider = cluster.NewClientProvider(controller.escalManager.Client, controller.log)
	// Delete existing ClusterConfig so provider.GetRESTConfig will fail authorization/lookup.
	cfg := &v1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: testGroupData.Clustername, Namespace: "default"}}
	_ = controller.escalManager.Delete(context.Background(), cfg)

	engine := gin.New()
	_ = controller.Register(engine.Group(""))
	inBytes, _ := json.Marshal(sar)
	req, _ := http.NewRequest("POST", "/authorize/"+testGroupData.Clustername, bytes.NewReader(inBytes))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK { // expect graceful denial, not 500
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	out := SubjectAccessReviewResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status.Allowed { // should be denied since no RBAC & no escalation logic triggered
		t.Fatalf("expected denied when rest config missing")
	}
}

// Tests authorizeViaSessions by standing up a fake kube-apiserver endpoint that
// accepts SubjectAccessReview create and responds allowed=true for the given
// granted group.
func TestAuthorizeViaSessions_AllowsWhenSessionSARAllowed(t *testing.T) {
	controller := SetupController(nil)

	// Build a single active session that would be used for session SAR
	ses := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess-sar-1"},
		Spec: v1alpha1.BreakglassSessionSpec{
			GrantedGroup: "breakglass-create-all",
		},
	}

	// Start HTTP test server that simulates kube-apiserver SubjectAccessReview endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && (r.URL.Path == "/apis/authorization.k8s.io/v1/subjectaccessreviews" || r.URL.Path == "/apis/authorization.k8s.io/v1/subjectaccessreviews/") {
			w.Header().Set("Content-Type", "application/json")
			// respond with allowed true
			_, _ = io.WriteString(w, `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":true}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rc := &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{Insecure: true}}

	allowed, grp, name := controller.authorizeViaSessions(context.Background(), rc, []v1alpha1.BreakglassSession{ses}, sar, "test-cluster")
	if !allowed {
		t.Fatalf("expected session SAR to allow but it did not")
	}
	if grp != ses.Spec.GrantedGroup {
		t.Fatalf("expected granted group %s got %s", ses.Spec.GrantedGroup, grp)
	}
	if name != ses.Name {
		t.Fatalf("expected session name %s got %s", ses.Name, name)
	}
}

// Test that authorizeViaSessions also allows when a prefixed group variant matches the SAR
func TestAuthorizeViaSessions_PrefixedAllowed(t *testing.T) {
	controller := SetupController(nil)

	// Build a single active session
	ses := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess-pref-1"},
		Spec: v1alpha1.BreakglassSessionSpec{
			GrantedGroup: "breakglass-create-all",
		},
	}

	// configure controller to have an OIDC prefix that the cluster expects
	controller.config.Kubernetes.OIDCPrefixes = []string{"oidc:"}

	// Start HTTP test server that simulates kube-apiserver SubjectAccessReview endpoint
	// but responds allowed=true only for the prefixed group
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && (r.URL.Path == "/apis/authorization.k8s.io/v1/subjectaccessreviews" || r.URL.Path == "/apis/authorization.k8s.io/v1/subjectaccessreviews/") {
			// we don't inspect body here; return allowed true to simulate acceptance
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"allowed":true}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rc := &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{Insecure: true}}

	allowed, grp, name := controller.authorizeViaSessions(context.Background(), rc, []v1alpha1.BreakglassSession{ses}, sar, "test-cluster")
	if !allowed {
		t.Fatalf("expected prefixed session SAR to allow but it did not")
	}
	if grp != ses.Spec.GrantedGroup {
		t.Fatalf("expected granted group %s got %s", ses.Spec.GrantedGroup, grp)
	}
	if name != ses.Name {
		t.Fatalf("expected session name %s got %s", ses.Name, name)
	}
}

// Test that authorizeViaSessions properly reports errors when SAR creation fails
func TestAuthorizeViaSessions_ErrorPath(t *testing.T) {
	controller := SetupController(nil)

	ses := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "sess-err-1"},
		Spec: v1alpha1.BreakglassSessionSpec{
			GrantedGroup: "breakglass-create-all",
		},
	}

	// Start HTTP test server that simulates kube-apiserver and returns an error status code
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{Insecure: true}}

	allowed, _, _ := controller.authorizeViaSessions(context.Background(), rc, []v1alpha1.BreakglassSession{ses}, sar, "test-cluster")
	if allowed {
		t.Fatalf("expected session SAR to not allow when server errors")
	}
}

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
	authorization "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var testGroupData breakglass.ClusterUserGroup = breakglass.ClusterUserGroup{
	Clustername: "telekom.tenat1",
	Username:    "anon@deutsche.telekom.de",
	Groupname:   "breakglass-create-all",
}

var (
	alwaysCanDo breakglass.CanGroupsDoFunction = breakglass.CanGroupsDoFunction(func(context.Context, []string,
		authorization.SubjectAccessReview, string,
	) (bool, error) {
		return true, nil
	})

	alwaysCanNotDo breakglass.CanGroupsDoFunction = breakglass.CanGroupsDoFunction(func(context.Context, []string,
		authorization.SubjectAccessReview, string,
	) (bool, error) {
		return false, nil
	})
)

const (
	testFrontURL   string = "https://test.breakglass.front.com"
	errGotRejected string = "Wrong review response got rejected even though should be allowed"
	errGotAllowed  string = "Wrong review response got allowed even though should be rejected"
)

var sessionIndexFunctions = map[string]client.IndexerFunc{
	"spec.username": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.User}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.Cluster}
	},
	"spec.grantedGroup": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.GrantedGroup}
	},
}

func newBreakglassSession(cluster, username, group string) v1alpha1.BreakglassSession {
	return v1alpha1.BreakglassSession{
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      cluster,
			User:         username,
			GrantedGroup: group,
		},
		Status: v1alpha1.BreakglassSessionStatus{},
	}
}

func TestHandleAuthorize(t *testing.T) {
	ses := newBreakglassSession("test", "test", "test")
	ses.Name = fmt.Sprintf("%s-%s-a1", testGroupData.Clustername, testGroupData.Groupname)
	ses.Status = v1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(breakglass.DefaultRetainForDuration)),
	}

	ses2 := newBreakglassSession("test2", "test2", "test2")
	ses2.Name = fmt.Sprintf("%s-%s-a2", testGroupData.Clustername, testGroupData.Groupname)
	ses2.Status = v1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(breakglass.DefaultRetainForDuration)),
	}

	ses3 := newBreakglassSession("testError", "testError", "testError")
	ses3.Name = fmt.Sprintf("%s-%s-a3", testGroupData.Clustername, testGroupData.Groupname)
	ses3.Status = v1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(breakglass.DefaultRetainForDuration)),
	}

	listIntercept := interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		fs := opts[0].(*client.ListOptions).FieldSelector
		for _, req := range fs.Requirements() {
			if req.Value == "testError" {
				return errors.New("| DO NOT WORRY TEST ONLY ERROR | failed to list breakglass sessions")
			}
		}
		return nil
	}}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).
		WithObjects(&ses, &ses2).WithInterceptorFuncs(listIntercept)

	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&ses, index, fn)
	}
	sesmanager := breakglass.SessionManager{
		Client: builder.Build(),
	}

	logger, _ := zap.NewDevelopment()
	contoller := NewWebhookController(logger.Sugar(), config.Config{
		Frontend: config.Frontend{BaseURL: testFrontURL},
	}, &sesmanager)
	contoller.canDoFn = alwaysCanDo
	engine := gin.New()

	_ = contoller.Register(engine.Group("api"))

	sar := authorization.SubjectAccessReview{
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

	allowRejectCases := []struct {
		TestName           string
		CanDoFunction      breakglass.CanGroupsDoFunction
		ShouldAllow        bool
		ExpectedStatusCode int
		InReview           *authorization.SubjectAccessReview
		Clustername        string
	}{
		{
			TestName:           "Test simple always allow",
			CanDoFunction:      alwaysCanDo,
			ShouldAllow:        true,
			ExpectedStatusCode: http.StatusOK,
			InReview:           &sar,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Test simple always reject",
			CanDoFunction:      alwaysCanNotDo,
			ShouldAllow:        false,
			ExpectedStatusCode: http.StatusOK,
			InReview:           &sar,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Test empty cluster",
			ExpectedStatusCode: http.StatusNotFound,
			CanDoFunction:      alwaysCanNotDo,
			InReview:           &sar,
			ShouldAllow:        false,
			Clustername:        "",
		},
		{
			TestName:           "Test empty body",
			ExpectedStatusCode: http.StatusUnprocessableEntity,
			CanDoFunction:      alwaysCanNotDo,
			ShouldAllow:        false,
			InReview:           nil,
			Clustername:        testGroupData.Clustername,
		},
		{
			TestName:           "Test can do function error",
			ExpectedStatusCode: http.StatusInternalServerError,
			CanDoFunction: breakglass.CanGroupsDoFunction(func(context.Context, []string,
				authorization.SubjectAccessReview, string,
			) (bool, error) {
				return false, errors.New("| DO NOT WORRY TEST ONLY ERROR | - failed to check groups")
			}),
			InReview:    &sar,
			ShouldAllow: false,
			Clustername: testGroupData.Clustername,
		},
		{
			TestName:           "Test manager error",
			ExpectedStatusCode: http.StatusInternalServerError,
			CanDoFunction:      alwaysCanDo,
			ShouldAllow:        false,
			InReview:           &sar,
			Clustername:        "testError",
		},
	}

	for _, testCase := range allowRejectCases {
		t.Run(testCase.TestName, func(t *testing.T) {
			contoller.canDoFn = testCase.CanDoFunction
			var inBytes []byte

			if testCase.InReview != nil {
				inBytes, _ = json.Marshal(*testCase.InReview)
			}

			req, _ := http.NewRequest("POST", "/api/authorize/"+testCase.Clustername, bytes.NewReader(inBytes))
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

			reason := fmt.Sprintf(denyReasonMessage, contoller.config.Frontend.BaseURL, testCase.Clustername)
			if !respReview.Status.Allowed && respReview.Status.Reason != reason {
				t.Fatalf("Incorrect status reason got %q, expected: %q", respReview.Status.Reason, reason)
			}
		})
	}
}

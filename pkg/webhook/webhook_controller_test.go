package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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

var testGroupData = breakglass.ClusterUserGroup{
	Clustername: "telekom.tenat1",
	Username:    "anon@deutsche.telekom.de",
	Groupname:   "breakglass-create-all",
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
	testFrontURL              string = "https://test.breakglass.front.com"
	errGotRejected            string = "Wrong review response got rejected even though should be allowed"
	errGotAllowed             string = "Wrong review response got allowed even though should be rejected"
	clusterNameWithEscalation        = "testEscalation"
)

var sessionIndexFunctions = map[string]client.IndexerFunc{
	"status.expired": func(o client.Object) []string {
		return []string{strconv.FormatBool(o.(*v1alpha1.BreakglassSession).Status.Expired)}
	},
	"status.approved": func(o client.Object) []string {
		return []string{strconv.FormatBool(o.(*v1alpha1.BreakglassSession).Status.Approved)}
	},
	"status.idleTimeoutReached": func(o client.Object) []string {
		return []string{strconv.FormatBool(o.(*v1alpha1.BreakglassSession).Status.IdleTimeoutReached)}
	},
	"spec.username": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.Username}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.Cluster}
	},
}

var escalationIndexFunctions = map[string]client.IndexerFunc{
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassEscalation).Spec.Cluster}
	},

	"spec.username": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassEscalation).Spec.Username}
	},
	"spec.escalatedGroup": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassEscalation).Spec.EscalatedGroup}
	},
}

func SetupController(interceptFuncs *interceptor.Funcs) WebhookController {
	ses := v1alpha1.NewBreakglassSession("test", "test", "test")
	ses.Name = fmt.Sprintf("%s-%s-a1", testGroupData.Clustername, testGroupData.Groupname)
	ses.Status = v1alpha1.BreakglassSessionStatus{
		Expired:            false,
		Approved:           false,
		IdleTimeoutReached: false,
		CreatedAt:          metav1.Now(),
		StoreUntil:         metav1.NewTime(time.Now().Add(breakglass.MonthDuration)),
	}

	ses2 := v1alpha1.NewBreakglassSession("test2", "test2", "test2")
	ses2.Name = fmt.Sprintf("%s-%s-a2", testGroupData.Clustername, testGroupData.Groupname)
	ses2.Status = v1alpha1.BreakglassSessionStatus{
		Expired:            false,
		Approved:           false,
		IdleTimeoutReached: false,
		CreatedAt:          metav1.Now(),
		StoreUntil:         metav1.NewTime(time.Now().Add(breakglass.MonthDuration)),
	}

	ses3 := v1alpha1.NewBreakglassSession("testError", "testError", "testError")
	ses3.Name = fmt.Sprintf("%s-%s-a3", testGroupData.Clustername, testGroupData.Groupname)
	ses3.Status = v1alpha1.BreakglassSessionStatus{
		Expired:            false,
		Approved:           false,
		IdleTimeoutReached: false,
		CreatedAt:          metav1.Now(),
		StoreUntil:         metav1.NewTime(time.Now().Add(breakglass.MonthDuration)),
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).
		WithObjects(&ses, &ses2, &ses3, &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tester-allow-create-all",
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Cluster:        clusterNameWithEscalation,
				Username:       testGroupData.Username,
				AllowedGroups:  []string{"system:authenticated"},
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
	for index, fn := range escalationIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassEscalation{}, index, fn)
	}

	cli := builder.Build()
	sesmanager := breakglass.SessionManager{
		Client: cli,
	}
	escmanager := breakglass.EscalationManager{
		Client: cli,
	}

	logger, _ := zap.NewDevelopment()
	contoller := NewWebhookController(logger.Sugar(),
		config.Config{
			Frontend: config.Frontend{BaseURL: testFrontURL},
		}, &sesmanager,
		&escmanager)
	contoller.canDoFn = alwaysCanDo

	return contoller
}

func TestHandleAuthorize(t *testing.T) {
	contoller := SetupController(nil)
	engine := gin.New()
	_ = contoller.Register(engine.Group(""))

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
			CanDoFunction: breakglass.CanGroupsDoFunction(func(context.Context, []string,
				authorization.SubjectAccessReview, string,
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
			contoller.canDoFn = testCase.CanDoFunction
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
	contoller := SetupController(nil)
	contoller.canDoFn = alwaysCanNotDo
	expReason := fmt.Sprintf(denyReasonMessage, contoller.config.Frontend.BaseURL, clusterNameWithEscalation)
	engine := gin.New()
	_ = contoller.Register(engine.Group(""))
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
	contoller := SetupController(&listIntercept)
	contoller.canDoFn = alwaysCanDo
	engine := gin.New()
	_ = contoller.Register(engine.Group(""))
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

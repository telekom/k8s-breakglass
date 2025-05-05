package breakglass

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
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type FakeMailSender struct {
	LastRecivers          []string
	LastSubject, LastBody string
	OnSendError           error
}

func (s *FakeMailSender) Send(receivers []string, subject, body string) error {
	s.LastRecivers = receivers
	s.LastSubject = subject
	s.LastBody = body
	return s.OnSendError
}

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

func TestRequestApproveRejectGetSession(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tester-allow-create-all",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Users:    []string{"tester@telekom.de"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "breakglass-create-all",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@telekom.de"},
			},
		},
	})
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{
		Client: cli,
	}
	escmanager := EscalationManager{
		Client: cli,
	}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{},
		&sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				c.Next()
				return
			}

			switch c.Request.Method {
			case http.MethodGet:
				c.Set("email", "approver@telekom.de")
				c.Set("username", "Approver")
			case http.MethodPost:
				url := c.Request.URL.String()
				if url == "/request" {
					c.Set("email", "tester@telekom.de")
					c.Set("username", "Tester")
				} else if strings.HasPrefix(url, "/approve") || strings.HasPrefix(url, "/reject") {
					c.Set("email", "approver@telekom.de")
					c.Set("username", "Approver")
				}
			}

			c.Next()
		})

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("", ctrl.Handlers()...))

	// create request
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "tester@telekom.de",
		Groupname:   "breakglass-create-all",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/request", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status CREATED (201) got '%d' instead", response.StatusCode)
	}

	// get created request and check if proper fields are set
	getSession := func() v1alpha1.BreakglassSession {
		req, _ := http.NewRequest("GET", "/status", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		response := w.Result()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
		}
		respSessions := []v1alpha1.BreakglassSession{}
		err := json.NewDecoder(response.Body).Decode(&respSessions)
		if err != nil {
			t.Fatalf("Failed to decode response body %v", err)
		}
		if l := len(respSessions); l != 1 {
			t.Fatalf("Expected one breakglass session to be created go %d instead. (%#v)", l, respSessions)
		}
		return respSessions[0]
	}

	ses := getSession()
	if stat := ses.Status.RetainedUntil; stat.Day() != time.Now().Add(MonthDuration).Day() {
		t.Fatalf("Incorrect session store until date day status %#v", stat)
	}

	// approve session
	req, _ = http.NewRequest("POST",
		fmt.Sprintf("/approve/%s", ses.Name),
		nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}

	// check if session status is approved
	ses = getSession()
	if ses.Status.ApprovedAt.Day() != time.Now().Day() {
		t.Fatalf("Expected session to be approved, but it is not.")
	}

	// reject session
	req, _ = http.NewRequest("POST",
		fmt.Sprintf("/reject/%s", ses.Name),
		nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}

	// check if session status is back to rejected
	ses = getSession()
	if !ses.Status.ApprovedAt.IsZero() {
		t.Fatalf("Expected session to be rejected, but it is not.")
	}
}

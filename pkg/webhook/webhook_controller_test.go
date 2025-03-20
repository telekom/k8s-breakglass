package webhook

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var testGroupData breakglass.ClusterUserGroup = breakglass.ClusterUserGroup{
	Clustername: "telekom.tenat1",
	Username:    "anon@deutsche.telekom.de",
	Groupname:   "breakglass-create-all",
}

const testFrontURL string = "https://test.breakglass.front.com"

func TestHandleAuthorize(t *testing.T) {
	ses := v1alpha1.NewBreakglassSession("test", "test", "test")
	ses.GenerateName = fmt.Sprintf("%s-%s-", testGroupData.Clustername, testGroupData.Groupname)

	sesmanager := breakglass.SessionManager{
		Client: fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build(),
	}

	fmt.Println(sesmanager)
	fmt.Println(sesmanager.AddBreakglassSession(context.Background(), ses))
	fmt.Println(sesmanager.GetAllBreakglassSessions(context.Background()))

	logger, _ := zap.NewDevelopment()
	contoller := NewWebhookController(logger.Sugar(), config.Config{
		Frontend: config.Frontend{BaseURL: testFrontURL},
	}, &sesmanager)
	engine := gin.New()
	_ = contoller.Register(engine.Group("api"))
	w := httptest.NewRecorder()

	// "resourceAttributes":{
	//    "namespace":"default",
	//    "verb":"get",
	//    "version":"v1",
	//    "resource":"pods",
	//    "name":"breakglass-deployment-867d954d7c-jzf7n"
	// },
	sar := authorization.SubjectAccessReview{
		TypeMeta: v1.TypeMeta{
			Kind:       "SubjectAccessReview",
			APIVersion: "authorization.k8s.io/v1",
		},
		Spec: authorization.SubjectAccessReviewSpec{
			User:   testGroupData.Username,
			Groups: []string{"system:authenticated"},
		},
	}
	fmt.Println(sar)
	req, _ := http.NewRequest("POST", "/api/authorize/"+testGroupData.Clustername, nil)
	fmt.Println(w)
	engine.ServeHTTP(w, req)
}

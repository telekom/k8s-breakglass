package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCheckSessionLimits_MissingIDP(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	wc := &BreakglassSessionController{
		sessionManager: &SessionManager{
			Client: fakeClient,
		},
	}

	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
	}

	err := wc.checkSessionLimits(context.Background(), esc, "missing-idp", "test@example.com", []string{"developers"}, log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityProvider \"missing-idp\" not found")
}

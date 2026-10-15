// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSessionListReturnsMappedRequesterMetadataWithoutEmail(t *testing.T) {
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "mapped-session", Namespace: "default"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{User: "cluster:k834798", RequesterUsername: "provider:k834798", IdentityProviderName: "corporate", IdentityProviderIssuer: "https://issuer.example"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateWithdrawn, Approver: "provider:k834798", ApproverIdentityProvider: "corporate"},
	}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).Build()
	controller := &BreakglassSessionController{log: zap.NewNop().Sugar(), identityProvider: KeycloakIdentityProvider{}, sessionManager: &SessionManager{Client: cli}}
	for _, filter := range []string{"mine", "approvedByMe"} {
		for _, provider := range []string{"corporate", "different-provider"} {
			t.Run(filter+"/"+provider, func(t *testing.T) {
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodGet, "/sessions?"+filter+"=true", nil)
				c.Set("authenticated_username", "provider:k834798")
				c.Set("username", "provider:k834798")
				c.Set("identity_provider_name", provider)
				c.Set("issuer", "https://issuer.example")
				controller.handleGetBreakglassSessionStatus(c)
				require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
				var response struct {
					Items []EnrichedSessionResponse `json:"items"`
				}
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
				if provider != "corporate" {
					require.Empty(t, response.Items)
					return
				}
				require.Len(t, response.Items, 1)
				item := response.Items[0]
				require.Equal(t, "cluster:k834798", item.Spec.User)
				require.True(t, item.IsRequester)
				require.True(t, item.ApprovedByMe)
			})
		}
	}
}

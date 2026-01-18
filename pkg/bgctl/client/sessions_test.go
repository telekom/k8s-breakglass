package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSessionsList(t *testing.T) {
	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1"},
			Spec:       v1alpha1.BreakglassSessionSpec{User: "user@example.com"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)

		// Check query params
		query := r.URL.Query()
		if cluster := query.Get("cluster"); cluster != "" {
			require.Equal(t, "test-cluster", cluster)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sessions)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().List(context.Background(), SessionListOptions{
		Cluster: "test-cluster",
	})
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, "session-1", result[0].Name)
}

func TestSessionsGet(t *testing.T) {
	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
		Spec:       v1alpha1.BreakglassSessionSpec{User: "user@example.com"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		// API returns wrapped response with session and approvalMeta
		response := map[string]interface{}{
			"session": session,
			"approvalMeta": map[string]interface{}{
				"canApprove":  false,
				"isApprover":  false,
				"isRequester": true,
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Get(context.Background(), "session-123")
	require.NoError(t, err)
	require.Equal(t, "session-123", result.Name)
}

func TestSessionsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req SessionRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		require.Equal(t, "test-cluster", req.Cluster)
		require.Equal(t, "admin", req.Group)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-new"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      req.Cluster,
				GrantedGroup: req.Group,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Request(context.Background(), SessionRequest{
		Cluster: "test-cluster",
		Group:   "admin",
		User:    "user@example.com",
		Reason:  "testing",
	})
	require.NoError(t, err)
	require.Equal(t, "session-new", result.Name)
}

func TestSessionsApprove(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123/approve", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req SessionActionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		require.Equal(t, "approved for testing", req.Reason)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateApproved,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Approve(context.Background(), "session-123", "approved for testing")
	require.NoError(t, err)
	require.Equal(t, v1alpha1.SessionStateApproved, result.Status.State)
}

func TestSessionsReject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123/reject", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req SessionActionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		require.Equal(t, "not authorized", req.Reason)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateRejected,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Reject(context.Background(), "session-123", "not authorized")
	require.NoError(t, err)
	require.Equal(t, v1alpha1.SessionStateRejected, result.Status.State)
}

func TestSessionsWithdraw(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123/withdraw", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateWithdrawn,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Withdraw(context.Background(), "session-123")
	require.NoError(t, err)
	require.Equal(t, v1alpha1.SessionStateWithdrawn, result.Status.State)
}

func TestSessionsDrop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123/drop", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateExpired,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Drop(context.Background(), "session-123")
	require.NoError(t, err)
	require.Equal(t, v1alpha1.SessionStateExpired, result.Status.State)
}

func TestSessionsCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions/session-123/cancel", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
			Status: v1alpha1.BreakglassSessionStatus{
				State: v1alpha1.SessionStateExpired,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().Cancel(context.Background(), "session-123")
	require.NoError(t, err)
	require.Equal(t, v1alpha1.SessionStateExpired, result.Status.State)
}

func TestSessionsList_WithFilters(t *testing.T) {
	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassSessions", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)

		// Verify query params
		query := r.URL.Query()
		require.Equal(t, "test-cluster", query.Get("cluster"))
		require.Equal(t, "user@example.com", query.Get("user"))
		require.Equal(t, "true", query.Get("mine"))
		require.Equal(t, "true", query.Get("activeOnly"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sessions)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Sessions().List(context.Background(), SessionListOptions{
		Cluster:    "test-cluster",
		User:       "user@example.com",
		Mine:       true,
		ActiveOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, result, 1)
}

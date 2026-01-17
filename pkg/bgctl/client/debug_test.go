/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionsList(t *testing.T) {
	now := time.Now()
	startsAt := metav1.NewTime(now)
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	response := DebugSessionListResponse{
		Sessions: []DebugSessionSummary{
			{
				Name:         "debug-session-1",
				TemplateRef:  "template-1",
				Cluster:      "cluster-a",
				RequestedBy:  "user@example.com",
				State:        v1alpha1.DebugSessionStateActive,
				StartsAt:     &startsAt,
				ExpiresAt:    &expiresAt,
				Participants: 2,
				AllowedPods:  5,
			},
		},
		Total: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)

		// Verify query params are passed
		query := r.URL.Query()
		if cluster := query.Get("cluster"); cluster != "" {
			assert.Equal(t, "cluster-a", cluster)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().List(context.Background(), DebugSessionListOptions{
		Cluster: "cluster-a",
	})
	require.NoError(t, err)
	require.Len(t, result.Sessions, 1)
	assert.Equal(t, "debug-session-1", result.Sessions[0].Name)
	assert.Equal(t, v1alpha1.DebugSessionStateActive, result.Sessions[0].State)
}

func TestDebugSessionsGet(t *testing.T) {
	debugSession := v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
		Spec: v1alpha1.DebugSessionSpec{
			TemplateRef: "template-1",
			Cluster:     "test-cluster",
			RequestedBy: "user@example.com",
		},
		Status: v1alpha1.DebugSessionStatus{
			State: v1alpha1.DebugSessionStateActive,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DebugSessionDetailResponse{
			DebugSession: debugSession,
		})
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Get(context.Background(), "debug-session-123", "")
	require.NoError(t, err)
	assert.Equal(t, "debug-session-123", result.Name)
	assert.Equal(t, v1alpha1.DebugSessionStateActive, result.Status.State)
}

func TestDebugSessionsCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req CreateDebugSessionRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "template-1", req.TemplateRef)
		assert.Equal(t, "cluster-a", req.Cluster)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-new"},
				Spec: v1alpha1.DebugSessionSpec{
					TemplateRef: req.TemplateRef,
					Cluster:     req.Cluster,
					RequestedBy: "test@example.com",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Create(context.Background(), CreateDebugSessionRequest{
		TemplateRef: "template-1",
		Cluster:     "cluster-a",
		Reason:      "testing",
	})
	require.NoError(t, err)
	assert.Equal(t, "debug-session-new", result.Name)
}

func TestDebugSessionsTerminate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/terminate", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
				Status: v1alpha1.DebugSessionStatus{
					State: v1alpha1.DebugSessionStateTerminated,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Terminate(context.Background(), "debug-session-123", "")
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.DebugSessionStateTerminated, result.Status.State)
}

func TestDebugSessionsApprove(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/approve", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req ApprovalRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "approved for testing", req.Reason)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
				Status: v1alpha1.DebugSessionStatus{
					State: v1alpha1.DebugSessionStateActive,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Approve(context.Background(), "debug-session-123", "approved for testing", "")
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.DebugSessionStateActive, result.Status.State)
}

func TestDebugSessionsReject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/reject", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
				Status: v1alpha1.DebugSessionStatus{
					State: v1alpha1.DebugSessionStateTerminated,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Reject(context.Background(), "debug-session-123", "not needed", "")
	require.NoError(t, err)
	assert.Equal(t, v1alpha1.DebugSessionStateTerminated, result.Status.State)
}

func TestDebugSessionsJoin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/join", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req JoinDebugSessionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "participant", req.Role)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Join(context.Background(), "debug-session-123", "participant", "")
	require.NoError(t, err)
	assert.Equal(t, "debug-session-123", result.Name)
}

func TestDebugSessionsLeave(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/leave", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Leave(context.Background(), "debug-session-123", "")
	require.NoError(t, err)
	assert.Equal(t, "debug-session-123", result.Name)
}

func TestDebugSessionsRenew(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/renew", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req RenewDebugSessionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "30m", req.ExtendBy)

		response := DebugSessionDetailResponse{
			DebugSession: v1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug-session-123"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().Renew(context.Background(), "debug-session-123", "30m", "")
	require.NoError(t, err)
	assert.Equal(t, "debug-session-123", result.Name)
}

func TestDebugTemplatesList(t *testing.T) {
	response := DebugTemplateListResponse{
		Templates: []DebugSessionTemplateSummary{
			{
				Name:             "template-1",
				DisplayName:      "Debug Template",
				Mode:             "workload",
				TargetNamespace:  "debug-ns",
				RequiresApproval: true,
			},
		},
		Total: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/templates", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugTemplates().List(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Templates, 1)
	assert.Equal(t, "template-1", result.Templates[0].Name)
}

func TestDebugTemplatesGet(t *testing.T) {
	template := v1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template-1"},
		Spec: v1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Debug Template",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/templates/template-1", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(template)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugTemplates().Get(context.Background(), "template-1")
	require.NoError(t, err)
	assert.Equal(t, "template-1", result.Name)
}

func TestDebugPodTemplatesList(t *testing.T) {
	response := DebugPodTemplateListResponse{
		Templates: []DebugPodTemplateSummary{
			{
				Name:        "pod-template-1",
				DisplayName: "Pod Template",
				Description: "Test pod template",
				Containers:  1,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/podTemplates", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugPodTemplates().List(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Templates, 1)
	assert.Equal(t, "pod-template-1", result.Templates[0].Name)
}

func TestDebugPodTemplatesGet(t *testing.T) {
	template := v1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-template-1"},
		Spec: v1alpha1.DebugPodTemplateSpec{
			DisplayName: "Pod Template",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/podTemplates/pod-template-1", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(template)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugPodTemplates().Get(context.Background(), "pod-template-1")
	require.NoError(t, err)
	assert.Equal(t, "pod-template-1", result.Name)
}

func TestInjectEphemeralContainer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/injectEphemeralContainer", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		var req InjectEphemeralContainerRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "default", req.Namespace)
		assert.Equal(t, "test-pod", req.PodName)
		assert.Equal(t, "alpine:3.20", req.Image)

		response := map[string]interface{}{
			"success":       true,
			"containerName": "debug",
			"podName":       "test-pod",
			"namespace":     "default",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().InjectEphemeralContainer(context.Background(), "debug-session-123", "", InjectEphemeralContainerRequest{
		Namespace:     "default",
		PodName:       "test-pod",
		ContainerName: "debug",
		Image:         "alpine:3.20",
	})
	require.NoError(t, err)
	assert.True(t, result["success"].(bool))
}

func TestCreatePodCopy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/createPodCopy", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := map[string]interface{}{
			"success":   true,
			"debugPod":  "test-pod-debug-abc123",
			"namespace": "default",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().CreatePodCopy(context.Background(), "debug-session-123", "", CreatePodCopyRequest{
		Namespace: "default",
		PodName:   "test-pod",
	})
	require.NoError(t, err)
	assert.True(t, result["success"].(bool))
}

func TestCreateNodeDebugPod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/debug-session-123/createNodeDebugPod", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)

		response := map[string]interface{}{
			"success":  true,
			"debugPod": "node-debug-abc123",
			"nodeName": "worker-1",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.DebugSessions().CreateNodeDebugPod(context.Background(), "debug-session-123", "", CreateNodeDebugPodRequest{
		NodeName: "worker-1",
	})
	require.NoError(t, err)
	assert.True(t, result["success"].(bool))
}

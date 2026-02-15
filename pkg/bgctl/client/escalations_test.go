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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEscalationsList(t *testing.T) {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-1"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a", "cluster-b"},
					Groups:   []string{"developers"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-2"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-c"},
					Groups:   []string{"readers"},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/breakglassEscalations", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(escalations)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	result, err := client.Escalations().List(context.Background())
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, "escalation-1", result[0].Name)
	assert.Equal(t, "admin", result[0].Spec.EscalatedGroup)
}

func TestEscalationsGet(t *testing.T) {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-1"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-2"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(escalations)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	// Get existing escalation
	result, err := client.Escalations().Get(context.Background(), "escalation-1")
	require.NoError(t, err)
	assert.Equal(t, "escalation-1", result.Name)
	assert.Equal(t, "admin", result.Spec.EscalatedGroup)

	// Get by name
	result, err = client.Escalations().Get(context.Background(), "escalation-2")
	require.NoError(t, err)
	assert.Equal(t, "escalation-2", result.Name)
}

func TestEscalationsGet_NotFound(t *testing.T) {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-1"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(escalations)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	_, err = client.Escalations().Get(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestEscalationsListClusters(t *testing.T) {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-1"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a", "cluster-b"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "escalation-2"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-b", "cluster-c"}, // cluster-b is duplicate
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(escalations)
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	clusters, err := client.Escalations().ListClusters(context.Background())
	require.NoError(t, err)
	// Should return unique clusters: a, b, c
	assert.Len(t, clusters, 3)
	assert.Contains(t, clusters, "cluster-a")
	assert.Contains(t, clusters, "cluster-b")
	assert.Contains(t, clusters, "cluster-c")
}

func TestEscalationsListClusters_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]v1alpha1.BreakglassEscalation{})
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	clusters, err := client.Escalations().ListClusters(context.Background())
	require.NoError(t, err)
	assert.Empty(t, clusters)
}

func TestEscalationsList_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	_, err = client.Escalations().List(context.Background())
	require.Error(t, err)

	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/clustervalidator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
)

type fakeReadOnlyClient struct{}

func (fakeReadOnlyClient) ListNodes(context.Context, metav1.ListOptions) (*corev1.NodeList, error) {
	return &corev1.NodeList{}, nil
}
func (fakeReadOnlyClient) ListNamespaces(context.Context, metav1.ListOptions) (*corev1.NamespaceList, error) {
	return &corev1.NamespaceList{}, nil
}
func (fakeReadOnlyClient) ListPods(context.Context, metav1.ListOptions) (*corev1.PodList, error) {
	return &corev1.PodList{}, nil
}

type fakeReadOnlyDiscovery struct{}

func (fakeReadOnlyDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	return &metav1.APIGroupList{}, nil
}
func (fakeReadOnlyDiscovery) ServerVersion() (*version.Info, error) {
	return &version.Info{GitVersion: "v1.36.1"}, nil
}

func TestExtensionCheckUsesReadOnlyFacades(t *testing.T) {
	result := (extensionCheck{}).Run(context.Background(), fakeReadOnlyClient{}, fakeReadOnlyDiscovery{})
	require.Equal(t, clustervalidator.CheckResult{
		Name:    extensionName,
		Status:  clustervalidator.StatusReady,
		Message: "extension read-only contract succeeded",
	}, result)
}

var _ clustervalidator.ReadOnlyClient = fakeReadOnlyClient{}
var _ clustervalidator.ReadOnlyDiscovery = fakeReadOnlyDiscovery{}

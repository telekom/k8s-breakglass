// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package clusterconfiglookup

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSingleByName(t *testing.T) {
	items := []breakglassv1alpha1.ClusterConfig{
		{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "unique", Namespace: "tenant-b"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "tenant-c"}},
	}

	t.Run("returns unique match", func(t *testing.T) {
		got, err := SingleByName(items, "unique")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, "tenant-b", got.Namespace)
	})

	t.Run("returns nil for missing name", func(t *testing.T) {
		got, err := SingleByName(items, "missing")
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("returns conflict for duplicate names", func(t *testing.T) {
		got, err := SingleByName(items, "shared")
		require.Nil(t, got)
		require.True(t, apierrors.IsConflict(err))
		require.Contains(t, err.Error(), "tenant-a,tenant-c")
	})
}

func TestSingleByNameOrNotFound(t *testing.T) {
	got, err := SingleByNameOrNotFound(nil, "missing")
	require.Nil(t, got)
	require.True(t, apierrors.IsNotFound(err))
}

func TestIsNameIndexError(t *testing.T) {
	require.True(t, IsNameIndexError(errors.New("field index metadata.name does not exist")))
	require.True(t, IsNameIndexError(errors.New("no indexer found for metadata.name")))
	require.False(t, IsNameIndexError(errors.New("connection refused")))
}

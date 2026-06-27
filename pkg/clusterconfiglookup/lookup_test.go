/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

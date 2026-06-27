// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package clusterconfiglookup

import (
	"fmt"
	"sort"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var clusterConfigResource = schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "clusterconfigs"}

// NameIndex resolves ClusterConfig metadata.name lookups in O(1) while
// preserving duplicate-name conflict behavior.
type NameIndex struct {
	unique     map[string]*breakglassv1alpha1.ClusterConfig
	duplicates map[string][]string
}

// NewNameIndex builds an index for ClusterConfig metadata.name lookups.
func NewNameIndex(items []breakglassv1alpha1.ClusterConfig) NameIndex {
	index := NameIndex{
		unique:     make(map[string]*breakglassv1alpha1.ClusterConfig, len(items)),
		duplicates: make(map[string][]string),
	}
	for i := range items {
		item := &items[i]
		if existing, ok := index.unique[item.Name]; ok {
			index.duplicates[item.Name] = append(index.duplicates[item.Name], existing.Namespace, item.Namespace)
			delete(index.unique, item.Name)
			continue
		}
		if namespaces, ok := index.duplicates[item.Name]; ok {
			index.duplicates[item.Name] = append(namespaces, item.Namespace)
			continue
		}
		index.unique[item.Name] = item
	}
	for name := range index.duplicates {
		sort.Strings(index.duplicates[name])
	}
	return index
}

// Single returns the ClusterConfig with the given metadata.name when that name is globally unique.
func (i NameIndex) Single(name string) (*breakglassv1alpha1.ClusterConfig, error) {
	if namespaces, ok := i.duplicates[name]; ok {
		return nil, apierrors.NewConflict(
			clusterConfigResource,
			name,
			fmt.Errorf("clusterconfig name %q is not unique; found in namespaces: %s", name, strings.Join(namespaces, ",")),
		)
	}
	if clusterConfig, ok := i.unique[name]; ok {
		return clusterConfig, nil
	}
	return nil, nil
}

// SingleByName returns the ClusterConfig with the given metadata.name when that
// name is globally unique across namespaces. Duplicate names are ambiguous for
// debug-session cluster binding because the external API uses names as cluster IDs.
func SingleByName(items []breakglassv1alpha1.ClusterConfig, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	return NewNameIndex(items).Single(name)
}

// SingleByNameOrNotFound returns NotFound when no ClusterConfig has the given metadata.name.
func SingleByNameOrNotFound(items []breakglassv1alpha1.ClusterConfig, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	clusterConfig, err := SingleByName(items, name)
	if clusterConfig != nil || err != nil {
		return clusterConfig, err
	}
	return nil, NotFound(name)
}

// NotFound builds a typed NotFound error for ClusterConfig metadata.name lookups.
func NotFound(name string) error {
	return apierrors.NewNotFound(clusterConfigResource, name)
}

// IsNameIndexError returns true for cache clients that do not have the metadata.name field index.
func IsNameIndexError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "field index") ||
		strings.Contains(msg, "no indexer") ||
		strings.Contains(msg, "no index with name") ||
		strings.Contains(msg, "field label not supported") ||
		strings.Contains(msg, "Index with name")
}

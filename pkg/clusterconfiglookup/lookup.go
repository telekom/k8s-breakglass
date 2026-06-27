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
	"fmt"
	"sort"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var clusterConfigResource = schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "clusterconfigs"}

// SingleByName returns the ClusterConfig with the given metadata.name when that
// name is globally unique across namespaces. Duplicate names are ambiguous for
// debug-session cluster binding because the external API uses names as cluster IDs.
func SingleByName(items []breakglassv1alpha1.ClusterConfig, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	matching := make([]*breakglassv1alpha1.ClusterConfig, 0, len(items))
	for i := range items {
		if items[i].Name == name {
			matching = append(matching, &items[i])
		}
	}

	switch len(matching) {
	case 0:
		return nil, nil
	case 1:
		return matching[0], nil
	default:
		namespaces := make([]string, 0, len(matching))
		for _, clusterConfig := range matching {
			namespaces = append(namespaces, clusterConfig.Namespace)
		}
		sort.Strings(namespaces)
		return nil, apierrors.NewConflict(
			clusterConfigResource,
			name,
			fmt.Errorf("clusterconfig name %q is not unique; found in namespaces: %s", name, strings.Join(namespaces, ",")),
		)
	}
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

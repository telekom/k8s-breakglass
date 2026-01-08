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

package helpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetupConfig_Defaults(t *testing.T) {
	cfg := &setupConfig{
		timeout:   MediumTestTimeout,
		namespace: "default",
		cluster:   "test-cluster",
	}

	assert.Equal(t, MediumTestTimeout, cfg.timeout)
	assert.Equal(t, "default", cfg.namespace)
	assert.Equal(t, "test-cluster", cfg.cluster)
	assert.False(t, cfg.skipE2ECheck)
	assert.False(t, cfg.requireWebhook)
	assert.False(t, cfg.requireMetrics)
	assert.False(t, cfg.requireAudit)
}

func TestSetupOptions(t *testing.T) {
	t.Run("WithTimeout", func(t *testing.T) {
		cfg := &setupConfig{}
		WithTimeout(30 * time.Second)(cfg)
		assert.Equal(t, 30*time.Second, cfg.timeout)
	})

	t.Run("WithShortTimeout", func(t *testing.T) {
		cfg := &setupConfig{}
		WithShortTimeout()(cfg)
		assert.Equal(t, ShortTestTimeout, cfg.timeout)
	})

	t.Run("WithMediumTimeout", func(t *testing.T) {
		cfg := &setupConfig{}
		WithMediumTimeout()(cfg)
		assert.Equal(t, MediumTestTimeout, cfg.timeout)
	})

	t.Run("WithLongTimeout", func(t *testing.T) {
		cfg := &setupConfig{}
		WithLongTimeout()(cfg)
		assert.Equal(t, LongTestTimeout, cfg.timeout)
	})

	t.Run("WithNamespace", func(t *testing.T) {
		cfg := &setupConfig{}
		WithNamespace("custom-ns")(cfg)
		assert.Equal(t, "custom-ns", cfg.namespace)
	})

	t.Run("WithCluster", func(t *testing.T) {
		cfg := &setupConfig{}
		WithCluster("custom-cluster")(cfg)
		assert.Equal(t, "custom-cluster", cfg.cluster)
	})

	t.Run("WithWebhookRequired", func(t *testing.T) {
		cfg := &setupConfig{}
		WithWebhookRequired()(cfg)
		assert.True(t, cfg.requireWebhook)
	})

	t.Run("WithMetricsRequired", func(t *testing.T) {
		cfg := &setupConfig{}
		WithMetricsRequired()(cfg)
		assert.True(t, cfg.requireMetrics)
	})

	t.Run("WithAuditRequired", func(t *testing.T) {
		cfg := &setupConfig{}
		WithAuditRequired()(cfg)
		assert.True(t, cfg.requireAudit)
	})

	t.Run("SkipE2ECheck", func(t *testing.T) {
		cfg := &setupConfig{}
		SkipE2ECheck()(cfg)
		assert.True(t, cfg.skipE2ECheck)
	})
}

func TestGenerateUniqueName(t *testing.T) {
	name1 := GenerateUniqueName("test")
	name2 := GenerateUniqueName("test")

	// Names should start with prefix
	assert.Contains(t, name1, "test-")
	assert.Contains(t, name2, "test-")

	// Names should be unique
	assert.NotEqual(t, name1, name2)

	// Names should have reasonable length
	assert.Greater(t, len(name1), len("test-"))
	assert.Less(t, len(name1), 50)
}

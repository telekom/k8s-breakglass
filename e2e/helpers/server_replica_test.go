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

	"github.com/stretchr/testify/assert"
)

func TestOverrideFlags(t *testing.T) {
	got := OverrideFlags(
		[]string{"--config-path=/config/config.yaml", "--enable-cleanup=true", "--enable-api"},
		map[string]string{"enable-cleanup": "false", "enable-api": "false"},
	)
	assert.Equal(t, "--config-path=/config/config.yaml", got[0])
	assert.ElementsMatch(t, []string{"--config-path=/config/config.yaml", "--enable-cleanup=false", "--enable-api=false"}, got)
	assert.Equal(t, "/config/config.yaml", flagValue(got, "config-path"))
	assert.Empty(t, flagValue(got, "missing"))
}

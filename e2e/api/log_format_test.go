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

package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestControllerLogLevelAndFormat starts a replica of the real breakglass
// image with --log-level=debug --log-format=json and proves that every log
// line, including debug lines, is a JSON object with the documented fields
// (docs/logging-and-debugging.md#log-format).
func TestControllerLogLevelAndFormat(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	name := "e2e-log-json" + helpers.GenerateUniqueName("")
	helpers.DeployServerReplica(t, s, helpers.ServerReplica{
		Name: name,
		// The main controller runs with debug console output; the replica
		// must not inherit the deprecated alias or the console format.
		Flags: map[string]string{"debug": "false", "log-level": "debug", "log-format": "json"},
	})
	require.NoError(t, helpers.WaitForDeploymentReady(s.Ctx, s.Client, s.Namespace, name, 5*time.Minute))

	var logs []byte
	require.Eventually(t, func() bool {
		all := helpers.ServerReplicaLogs(t, s.Ctx, s.Namespace, name, false)
		if len(all) != 1 {
			return false
		}
		logs = all[0]
		return bytes.Contains(logs, []byte(`"msg":"Debug logging enabled"`))
	}, 2*time.Minute, 2*time.Second, "replica did not log its debug startup line")

	var debugLines int
	for _, line := range bytes.Split(bytes.TrimSpace(logs), []byte("\n")) {
		var entry map[string]any
		require.NoError(t, json.Unmarshal(line, &entry), "log line is not JSON: %s", line)
		for _, key := range []string{"level", "ts", "caller", "msg"} {
			assert.Contains(t, entry, key, "log line: %s", line)
		}
		if entry["level"] != "debug" {
			continue
		}
		debugLines++
		if entry["msg"] == "Debug logging enabled" {
			assert.Equal(t, "debug", entry["logLevel"])
			assert.Equal(t, "json", entry["logFormat"])
		}
	}
	assert.Positive(t, debugLines, "no debug-level JSON line")
}

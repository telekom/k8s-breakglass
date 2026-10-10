#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

python3 - <<'PY'
import json
import subprocess

import yaml

chart = "charts/escalation-config"
fence = {
    "ephemeralContainers": {"selectorTerms": [{"matchLabels": {"team": "payments"}}]},
    "podCopy": {"patterns": ["payments-*"]},
}

def render(binding):
    values = {"debugSessionBindings": [{"name": "kubectl-debug", "templateRef": {"name": "debug"}, "clusters": ["c1"], **binding}]}
    return subprocess.run(
        ["helm", "template", "test", chart, "--show-only", "templates/debugsessionclusterbinding.yaml",
         "--values", chart + "/ci/test-values.yaml", "--values", "-"],
        input=json.dumps(values), text=True, capture_output=True,
    )

def spec(result):
    if result.returncode != 0:
        raise SystemExit(result.stderr)
    return yaml.safe_load(result.stdout)["spec"]

rendered = spec(render({"kubectlDebugTargetNamespaces": fence}))
assert rendered["kubectlDebugTargetNamespaces"] == fence, rendered
assert "kubectlDebugTargetNamespaces" not in spec(render({}))

for invalid in (
    {"kubectlDebugTargetNamespaces": {"unknown": {"patterns": ["x"]}}},
    {"kubectlDebugTargetNamespaces": {"ephemeralContainers": {}}},
    {"kubectlDebugTargetNamespaces": {"podCopy": {"patterns": []}}},
    {"kubectlDebugTargetNamespaces": {"ephemeralContainers": {"selectorTerms": []}}},
    {"kubectlDebugTargetNamespaces": {"podCopy": {"patterns": [""]}}},
    {"kubectlDebugTargetNamespaces": {"podCopy": {"names": ["x"]}}},
    {"kubectlDebugTargetNamespaces": {"podCopy": {"selectorTerms": [{}]}}},
    {"kubectlDebugTargetNamespaces": {"ephemeralContainers": {"selectorTerms": [{"matchLabel": {"team": "payments"}}]}}},
    {"kubectlDebugTargetNamespaces": {"podCopy": {"selectorTerms": [{"matchExpressions": [{"key": "team", "operator": "In", "values": []}]}]}}},
    {"kubectlDebugTargetNamespaces": {"ephemeralContainers": {"selectorTerms": [{"matchExpressions": [{"key": "team", "operator": "Exists", "values": ["payments"]}]}]}}},
):
    if render(invalid).returncode == 0:
        raise SystemExit(f"schema accepted invalid kubectlDebugTargetNamespaces: {invalid}")
print("kubectlDebugTargetNamespaces render checks passed")
PY

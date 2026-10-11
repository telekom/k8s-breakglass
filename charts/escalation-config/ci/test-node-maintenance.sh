#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart=charts/escalation-config
helm lint "$chart" --strict --values "$chart/test-values/node-maintenance.yaml"

python3 - <<'PY'
import re
import subprocess

chart = "charts/escalation-config"
default = subprocess.check_output(
    ["helm", "template", "test-release", chart, "--values", chart + "/ci/test-values.yaml"],
    text=True,
)
assert "kind: DebugSessionTemplate" not in default, "maintenance templates must remain default-off"
rendered = subprocess.check_output(
    ["helm", "template", "test-release", chart, "--values", chart + "/test-values/node-maintenance.yaml",
     "--show-only", "templates/node-maintenance.yaml"],
    text=True,
)
assert rendered.count("kind: DebugSessionTemplate\n") == 1, rendered
for line in (
    "apiVersion: breakglass.t-caas.telekom.com/v1alpha1",
    "kind: DebugSessionTemplate",
    '  name: "exact-neighbor-repair-example"',
    "spec:",
    "  allowed:",
    "    clusters:",
    "    - supported-cluster",
    "    - requester@example.invalid",
    "  approvers:",
    "    - independent-approver@example.invalid",
    "  constraints:",
    "    defaultDuration: 5m",
    "    maxDuration: 5m",
    "  mode: workload",
    "  nodeMaintenance:",
    "    action: neighbor-replace",
    "    allowedTargets:",
    '    - entryMAC: "02:00:00:00:00:02"',
    "      interface: eth0",
    "      neighborAddress: 192.0.2.2",
    "      targetNode: supported-node",
    "      targetNodeUID: replace-with-live-node-uid",
    "    image: registry.example.invalid/node-maintenance@sha256:" + "a" * 64,
    "  requestReason:",
    "    mandatory: true",
    "  targetNamespace: breakglass-node-maintenance",
):
    assert line in rendered.splitlines(), (line, rendered)
assert not re.search(
    r"^\s+(autoApproveFor|workloadType|podTemplateString|podTemplateRef|podOverrides|extraDeployVariables|impersonation):",
    rendered, re.M,
), "typed fixture must not introduce generic execution or approval overrides"
print("PASS default-off and exact node-maintenance template/approval/tuple/image rendering")
PY

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
motd = {"message": "Purpose: test\nTerminate: drop the session", "runbookURL": "https://example.com/runbook#section"}


def render(values):
    return subprocess.run(
        ["helm", "template", "test", chart,
         "--values", chart + "/ci/test-values.yaml", "--values", "-"],
        input=json.dumps(values), text=True, capture_output=True,
    )


escalation = {"name": "motd", "allowed": {"groups": ["dev"]}, "escalatedGroup": "admin"}
binding = {"name": "motd", "templateRef": {"name": "t"}, "clusters": ["c"], "allowed": {"groups": ["dev"]}}

result = render({
    "escalations": [{**escalation, "annotations": {"example.com/runbook": "docs/runbook.md#section"}, "motd": motd}],
    "debugSessionBindings": [{**binding, "motd": motd}],
})
if result.returncode:
    raise SystemExit(result.stderr)
docs = {d["kind"]: d for d in yaml.safe_load_all(result.stdout) if d and d.get("metadata", {}).get("name") == "motd"}
assert docs["BreakglassEscalation"]["spec"]["motd"] == motd, docs["BreakglassEscalation"]
assert docs["BreakglassEscalation"]["metadata"]["annotations"] == {"example.com/runbook": "docs/runbook.md#section"}
assert docs["DebugSessionClusterBinding"]["spec"]["motd"] == motd, docs["DebugSessionClusterBinding"]

result = render({"escalations": [escalation], "debugSessionBindings": [binding]})
if result.returncode:
    raise SystemExit(result.stderr)
for doc in yaml.safe_load_all(result.stdout):
    if doc and doc.get("metadata", {}).get("name") == "motd":
        assert "motd" not in doc["spec"], doc
        assert "annotations" not in doc["metadata"], doc

for name, values in {
    "EscalationHTTPRunbook": {"escalations": [{**escalation, "motd": {**motd, "runbookURL": "http://example.com"}}]},
    "EscalationBareRunbook": {"escalations": [{**escalation, "motd": {**motd, "runbookURL": "https://"}}]},
    "BindingRunbookWhitespace": {"debugSessionBindings": [{**binding, "motd": {**motd, "runbookURL": "https://example.com/a b"}}]},
    "EscalationEmptyMessage": {"escalations": [{**escalation, "motd": {"message": ""}}]},
    "BindingUnknownField": {"debugSessionBindings": [{**binding, "motd": {**motd, "banner": "x"}}]},
}.items():
    if render(values).returncode == 0:
        raise SystemExit(f"{name}: expected schema rejection")
print("escalation-config MOTD rendering checks passed")
PY

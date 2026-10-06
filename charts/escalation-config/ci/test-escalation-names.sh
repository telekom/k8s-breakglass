#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

python3 - <<'PY'
import hashlib
import json
import re
import subprocess

chart = "charts/escalation-config"

def render(escalations):
    values = {"escalations": [
        {"allowed": {"groups": ["dev"]}, "escalatedGroup": "admin", **esc}
        for esc in escalations
    ]}
    return subprocess.run(
        ["helm", "template", "test", chart,
         "--values", chart + "/ci/test-values.yaml", "--values", "-"],
        input=json.dumps(values), text=True, capture_output=True,
    )

def shortened(name):
    prefix = re.sub(r"[^a-z0-9]+$", "", name[:54])
    return prefix + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]

long_name = "admin-escalation-" + "a" * 50 + "-dev-0.1.0"
cases = [
    ({}, "escalation-0", None),
    ({"name": "short.name"}, "short.name", None),
    ({"name": "short-"}, "short", None),
    ({"name": "a" * 62 + "-"}, "a" * 62, None),
    ({"name": "a" * 63}, "a" * 63, None),
    ({"name": "a" * 64}, shortened("a" * 64), "a" * 64),
    ({"name": long_name}, shortened(long_name), long_name),
    ({"name": long_name + "-other"}, shortened(long_name + "-other"), long_name + "-other"),
    ({"name": long_name, "displayName": "Production admin: on call"}, shortened(long_name), "Production admin: on call"),
    ({"name": long_name, "displayName": ""}, shortened(long_name), long_name),
    ({"name": "short", "displayName": 'Admin "on call"'}, "short", 'Admin "on call"'),
    ({"name": "short", "displayName": "界" * 253}, "short", "界" * 253),
    ({"name": "a" * 254, "displayName": "Long-name admin"}, shortened("a" * 254), "Long-name admin"),
]
for punctuation in (".", "_", "-", ".-_"):
    name = "a" * (54 - len(punctuation)) + punctuation + "b" * 20
    cases.append(({"name": name}, shortened(name), name))

for esc, expected_name, expected_display in cases:
    result = render([esc])
    assert result.returncode == 0, result.stderr
    document = next(doc for doc in result.stdout.split("---") if "kind: BreakglassEscalation\n" in doc)
    name_match = re.search(r'^  name: (".*")$', document, re.M)
    display_match = re.search(r'^  displayName: (".*")$', document, re.M)
    actual_name = json.loads(name_match.group(1))
    actual_display = json.loads(display_match.group(1)) if display_match else None
    assert actual_name == expected_name, (actual_name, expected_name)
    assert actual_display == expected_display, (actual_display, expected_display)
    assert len(actual_name) <= 63, actual_name
    assert re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", actual_name), actual_name

# Names differing only beyond the old truncation boundary stay distinct in one release.
result = render([{"name": long_name}, {"name": long_name + "-other"}])
assert result.returncode == 0, result.stderr
rendered_names = [
    re.search(r'^  name: (".*")$', doc, re.M).group(1)
    for doc in result.stdout.split("---") if "kind: BreakglassEscalation\n" in doc
]
assert [json.loads(name) for name in rendered_names] == [shortened(long_name), shortened(long_name + "-other")]
assert shortened(long_name) != shortened(long_name + "-other")

result = render([{"name": "short", "displayName": "x" * 254}])
assert result.returncode != 0, "displayName exceeding 253 characters must fail schema validation"
assert "displayName" in result.stderr, result.stderr
print(f"Escalation name rendering passed: {len(cases)} cases, distinct suffixes, display-name length rejection")
PY

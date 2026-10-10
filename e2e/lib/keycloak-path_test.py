#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
import subprocess

e2e = Path(__file__).resolve().parents[1]
common = (e2e / "lib/common.sh").read_text()
normalization = common.split("KEYCLOAK_RELATIVE_PATH=", 1)[1].split(
    "# Get the IP address of the Keycloak container", 1
)[0]
for script in ("kind-setup-single.sh", "kind-setup-multi.sh"):
    default = next(
        line for line in (e2e / script).read_text().splitlines()
        if line.startswith("KEYCLOAK_RELATIVE_PATH=")
    )
    for value, expected in ((None, "/auth"), ("", ""), ("/", ""), ("/auth/", "/auth"), ("custom", "/custom")):
        env = os.environ.copy()
        env.pop("KEYCLOAK_RELATIVE_PATH", None)
        if value is not None:
            env["KEYCLOAK_RELATIVE_PATH"] = value
        result = subprocess.check_output(
            ["bash", "-c", default + "\nKEYCLOAK_RELATIVE_PATH=" + normalization
             + '\nprintf "%s" "$KEYCLOAK_RELATIVE_PATH"'],
            env=env, text=True,
        )
        assert result == expected, (script, value, expected, result)
print("PASS: both setup scripts preserve unset, root, auth and custom paths")

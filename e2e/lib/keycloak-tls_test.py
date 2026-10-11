#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

e2e = Path(__file__).resolve().parents[1]
common = (e2e / "lib/common.sh").read_text()
setup = (e2e / "kind-setup-multi.sh").read_text()


def function(source, name):
    match = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}", source)
    assert match, name
    return match.group()


generators = "\n".join(function(common, name) for name in (
    "generate_ca_cert", "generate_server_cert", "generate_keycloak_container_tls", "generate_keycloak_tls",
))
directory = Path.cwd() / f".keycloak-tls-proof-{os.getpid()}"
directory.mkdir()
env = dict(os.environ, TLS_DIR=str(directory), OPENSSL="openssl", KEYCLOAK_CONTAINER_NAME="e2e-keycloak",
           NAMESPACE="breakglass-system")
prefix = "set -eu\nlog() { :; }\nlog_error() { printf '%s\\n' \"$*\" >&2; }\n" + generators + "\n"
try:
    subprocess.run(["bash", "-c", prefix + 'generate_keycloak_container_tls "$TLS_DIR/keycloak" >/dev/null'],
                   env=env, check=True, timeout=30)
    certificate = directory / "keycloak/tls.crt"
    before = hashlib.sha256(certificate.read_bytes()).digest()
    subprocess.run(["bash", "-c", prefix
                    + '\ngenerate_breakglass_tls() { printf "%s" "$2" > "$TLS_DIR/hub-generated"; }\n'
                    + function(setup, "generate_tls_certificates")
                    + '\ngenerate_tls_certificates 192.0.2.10'],
                   env=env, check=True, timeout=30)
    assert (directory / "hub-generated").read_text() == "192.0.2.10"
    assert hashlib.sha256(certificate.read_bytes()).digest() == before, "hub setup replaced mounted container TLS"
    subprocess.run(["openssl", "verify", "-CAfile", str(directory / "keycloak/ca.crt"),
                    "-verify_hostname", "e2e-keycloak", str(certificate)], check=True, timeout=10)
    print("PASS: hub bootstrap preserves container TLS and verifies the exact OIDC issuer hostname")
finally:
    shutil.rmtree(directory)

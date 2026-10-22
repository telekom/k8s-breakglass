// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

test('audit delivery passes a complete image argument and cleans up after success or test failure', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-delivery-stubs-'));
  try {
    for (const tool of ['kind', 'docker', 'kubectl', 'go']) {
      fs.writeFileSync(path.join(directory, tool), `#!/usr/bin/env bash
set -euo pipefail
tool="$(basename "$0")"
printf '%s %s\\n' "$tool" "$*" >> "$STUB_LOG"
if [[ "$tool" == kind && "\${1:-}" == create ]]; then
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == --image ]]; then
      [[ "\${2:-}" == kindest/node:v*@sha256:* ]] || exit 91
      printf 'IMAGE_OK\\n' >> "$STUB_LOG"
    fi
    shift
  done
fi
if [[ "$tool" == go ]]; then exit "\${STUB_TEST_EXIT:-0}"; fi
`, { mode: 0o755 });
    }
    for (const exitCode of [0, 23]) {
      const log = path.join(directory, `commands-${exitCode}`);
      const result = spawnSync('bash', ['hack/audit-delivery-kind.sh'], {
        encoding: 'utf8',
        env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, STUB_LOG: log, STUB_TEST_EXIT: String(exitCode) },
      });
      assert.equal(result.status, exitCode, result.stderr);
      const commands = fs.readFileSync(log, 'utf8');
      assert.match(commands, /IMAGE_OK/);
      assert.match(commands, /kubectl apply --server-side/);
      assert.match(commands, /go test -race/);
      assert.match(commands, /kind delete cluster --name audit-delivery-/);
      const name = /kind create cluster --name (\S+)/.exec(commands)[1];
      assert.equal(fs.existsSync(path.join('.scratch', name)), false);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

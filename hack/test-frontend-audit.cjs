// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { summary } = require("./frontend-audit.cjs");

const report = {
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 } },
  vulnerabilities: { "<script>": { severity: "high", fixAvailable: true, via: [] } },
};
assert.match(summary(JSON.stringify(report)).body, /\| high \| 1 \|/);
assert.ok(!summary(JSON.stringify(report)).body.includes("<script>"));
assert.throws(() => summary('{"error":{"code":"ENOTFOUND"}}'), /npm audit error/);
assert.throws(() => summary("{}"), /Invalid npm audit report/);
assert.throws(() => summary("not JSON"));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "frontend-audit-"));
try {
  fs.mkdirSync(path.join(dir, "frontend"));
  fs.mkdirSync(path.join(dir, "bin"));
  fs.writeFileSync(path.join(dir, "bin/npm"),
    '#!/bin/sh\nprintf "%s" "$AUDIT_REPORT"\nexit "$AUDIT_STATUS"\n', { mode: 0o755 });
  function run(status, text) {
    return spawnSync(process.execPath, [path.join(__dirname, "frontend-audit.cjs"), "--run"], {
      cwd: path.join(dir, "frontend"),
      env: { ...process.env, PATH: `${dir}/bin:${process.env.PATH}`,
        GITHUB_STEP_SUMMARY: path.join(dir, "summary.md"),
        AUDIT_STATUS: String(status), AUDIT_REPORT: text },
      encoding: "utf8",
    });
  }
  assert.equal(run(1, JSON.stringify(report)).status, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, "npm-audit.json"))), report);
  assert.match(fs.readFileSync(path.join(dir, "summary.md"), "utf8"), /high/);
  assert.notEqual(run(1, '{"error":{"code":"ENOTFOUND"}}').status, 0);
  assert.notEqual(run(2, JSON.stringify(report)).status, 0);
  assert.notEqual(run(0, "{}").status, 0);
  report.metadata.vulnerabilities.high = 0;
  report.metadata.vulnerabilities.total = 0;
  report.vulnerabilities = {};
  assert.equal(run(0, JSON.stringify(report)).status, 0);
  assert.notEqual(run(1, JSON.stringify(report)).status, 0);
} finally {
  fs.rmSync(dir, { recursive: true });
}
console.log("Frontend audit reporting checks passed");

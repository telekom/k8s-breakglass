// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

const fs = require("node:fs");
const { spawnSync } = require("node:child_process");

function summary(text) {
  const audit = JSON.parse(text);
  if (audit.error) throw new Error(`npm audit error: ${JSON.stringify(audit.error)}`);
  const counts = audit.metadata?.vulnerabilities;
  const severities = ["info", "low", "moderate", "high", "critical"];
  if (!counts || !severities.every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0) ||
      counts.total !== severities.reduce((sum, key) => sum + counts[key], 0) ||
      !audit.vulnerabilities || typeof audit.vulnerabilities !== "object" ||
      Array.isArray(audit.vulnerabilities)) {
    throw new Error("Invalid npm audit report");
  }
  const lines = [
    "Frontend vulnerability findings are advisory; scanner and installation failures still fail CI.",
    "",
    "| Severity | Count |",
    "|---|---:|",
    ...severities.map(key => `| ${key} | ${counts[key]} |`),
    "",
  ];
  for (const [name, issue] of Object.entries(audit.vulnerabilities).slice(0, 40)) {
    if (!severities.includes(issue.severity)) throw new Error("Invalid vulnerability severity");
    const escaped = name.replace(/[&<>"'`*_[\]\\|]/g, character => `&#${character.charCodeAt(0)};`)
      .replace(/[\r\n]/g, " ");
    lines.push(`- ${escaped}: **${issue.severity}**, fix ${issue.fixAvailable ? "available" : "not reported"}`);
    for (const advisory of issue.via || []) {
      if (typeof advisory === "object" && /^https:\/\/github\.com\/advisories\/GHSA-[a-z0-9-]+$/.test(advisory.url)) {
        lines.push(`  ${advisory.url}`);
      }
    }
  }
  return { total: counts.total, body: lines.join("\n") };
}

module.exports = { summary };

if (require.main === module) {
  if (process.argv[2] !== "--run") throw new Error("Expected --run");
  const result = spawnSync("npm", ["audit", "--audit-level=high", "--json"], {
    encoding: "utf8", maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.stderr) process.stderr.write(result.stderr);
  if (![0, 1].includes(result.status)) throw new Error(`npm audit exited ${result.status}`);
  const report = summary(result.stdout);
  if (result.status === 1 && report.total === 0) throw new Error("npm audit failed without vulnerability findings");
  fs.writeFileSync("../npm-audit.json", result.stdout);
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Frontend Security Audit\n\n${report.body}\n`);
  if (report.total > 0) console.log("::warning::Frontend vulnerabilities found; see the audit report and PR comment.");
}

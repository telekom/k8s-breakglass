#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

/**
 * Keep the frontend Node.js baseline at or above the Node 24 engine floor
 * declared by the dependency lockfile, and keep every setup-node workflow pin
 * at that same baseline.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const frontendDirectory = path.join(repositoryRoot, "frontend");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function parseVersion(value, label) {
  const match = String(value).match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    throw new Error(`${label} must be an exact major.minor.patch version, got ${value}`);
  }
  return match.slice(1).map(Number);
}

function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

function versionText(version) {
  return version.join(".");
}

function assertAtLeast(version, minimum, label) {
  if (compareVersions(version, minimum) < 0) {
    throw new Error(`${label} ${versionText(version)} is below ${versionText(minimum)}`);
  }
}

function node24Versions(engine) {
  return [...String(engine).matchAll(/(?:^|[^\d])(?:\^|>=|>|~|=)?(24\.\d+\.\d+)/g)].map((match) =>
    parseVersion(match[1], `dependency engine ${engine}`),
  );
}

function workflowFiles(directory) {
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        return workflowFiles(entryPath);
      }
      return /\.(?:yml|yaml)$/.test(entry.name) ? [entryPath] : [];
    });
}

function main() {
  const packageJson = readJson(path.join(frontendDirectory, "package.json"));
  const lockfile = readJson(path.join(frontendDirectory, "package-lock.json"));
  const packageEngine = packageJson.engines?.node;
  const lockfileEngine = lockfile.packages?.[""]?.engines?.node;
  const packageMatch = String(packageEngine ?? "").match(/^>=\s*(\d+\.\d+\.\d+)$/);
  if (!packageMatch) {
    throw new Error(`frontend/package.json must declare an exact >= engine floor, got ${packageEngine}`);
  }
  if (lockfileEngine !== packageEngine) {
    throw new Error(
      `frontend/package-lock.json root engine ${lockfileEngine} does not match package.json ${packageEngine}`,
    );
  }

  const dependencyFloors = [];
  for (const [packageName, packageMetadata] of Object.entries(lockfile.packages ?? {})) {
    if (packageName === "") {
      continue;
    }
    for (const version of node24Versions(packageMetadata.engines?.node ?? "")) {
      dependencyFloors.push({ packageName, version });
    }
  }
  if (dependencyFloors.length === 0) {
    throw new Error("could not find a Node 24 dependency engine floor in frontend/package-lock.json");
  }
  const dependencyFloor = dependencyFloors.reduce(
    (highest, entry) => (compareVersions(entry.version, highest) > 0 ? entry.version : highest),
    [0, 0, 0],
  );
  const packageVersion = parseVersion(packageMatch[1], "frontend/package.json engine");
  assertAtLeast(packageVersion, dependencyFloor, "frontend/package.json engine");

  const pins = [];
  for (const workflowPath of workflowFiles(path.join(repositoryRoot, ".github", "workflows"))) {
    const contents = fs.readFileSync(workflowPath, "utf8");
    for (const match of contents.matchAll(/^\s*node-version:\s*['"]?([^'"\s#]+)['"]?/gm)) {
      const version = parseVersion(match[1], `${path.relative(repositoryRoot, workflowPath)} node-version`);
      assertAtLeast(version, dependencyFloor, `${path.relative(repositoryRoot, workflowPath)} node-version`);
      pins.push({ workflowPath, version });
    }
  }
  if (pins.length === 0) {
    throw new Error("could not find any setup-node workflow version pins");
  }

  console.log(
    `Node version contract OK: baseline ${versionText(packageVersion)}, dependency floor ${versionText(
      dependencyFloor,
    )} (${dependencyFloors.length} lockfile engine declarations), ${pins.length} workflow pins checked`,
  );
}

try {
  main();
} catch (error) {
  console.error(`Node version contract failed: ${error.message}`);
  process.exitCode = 1;
}

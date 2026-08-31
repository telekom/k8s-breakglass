#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

/**
 * Keep the frontend Node.js baseline aligned with the Node.js engine ranges
 * declared by the dependency lockfile, and keep every setup-node workflow pin
 * at that baseline.
 */

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const frontendDirectory = path.join(repositoryRoot, "frontend");
const requireFromFrontend = createRequire(path.join(frontendDirectory, "package.json"));
const semver = requireFromFrontend("semver");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function parseVersion(value, label) {
  const text = String(value);
  if (!/^v?\d+\.\d+\.\d+$/.test(text)) {
    throw new Error(`${label} must be an exact major.minor.patch version, got ${value}`);
  }
  const parsed = semver.parse(text);
  if (!parsed || parsed.prerelease.length || parsed.build.length) {
    throw new Error(`${label} must be an exact stable semver version, got ${value}`);
  }
  return [parsed.major, parsed.minor, parsed.patch];
}

function versionText(version) {
  return version.join(".");
}

function parseRange(engine) {
  const text = String(engine).trim();
  if (!text) {
    return [];
  }
  try {
    return new semver.Range(text).set;
  } catch (error) {
    throw new Error(`unsupported Node.js engine range ${engine}: ${error.message}`);
  }
}

function compareVersions(left, right) {
  return semver.compare(versionText(left), versionText(right));
}

function includesVersionInComparatorSet(version, comparatorSet) {
  const parsed = new semver.SemVer(versionText(version));
  return comparatorSet.every((comparator) => comparator.test(parsed));
}

function includesVersion(engine, version) {
  return parseRange(engine).some((comparatorSet) => includesVersionInComparatorSet(version, comparatorSet));
}

function minimumVersionInMajor(engine, major) {
  const candidateFloor = [major, 0, 0];
  const candidates = [];
  for (const comparatorSet of parseRange(engine)) {
    const minimum = semver.minVersion(comparatorSet.map((comparator) => comparator.value).join(" "));
    if (!minimum || minimum.major > major) {
      continue;
    }
    const candidate = minimum.major === major ? [minimum.major, minimum.minor, minimum.patch] : candidateFloor;
    if (includesVersionInComparatorSet(candidate, comparatorSet)) {
      candidates.push(candidate);
    }
  }
  return candidates.reduce(
    (minimum, candidate) => (!minimum || compareVersions(candidate, minimum) < 0 ? candidate : minimum),
    null,
  );
}

function hasUnboundedBranchAtMajor(engine, major) {
  const version = [major, 0, 0];
  return parseRange(engine).some(
    (comparatorSet) =>
      !comparatorSet.some((comparator) => comparator.operator === "<" || comparator.operator === "<=") &&
      includesVersionInComparatorSet(version, comparatorSet),
  );
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
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
  const packageFloor = minimumVersionInMajor(packageEngine ?? "", 24);
  const packageNode25Floor = minimumVersionInMajor(packageEngine ?? "", 25);
  if (!packageFloor || packageNode25Floor || !hasUnboundedBranchAtMajor(packageEngine ?? "", 26)) {
    throw new Error(
      `frontend/package.json must support Node 24 from its dependency floor, exclude Node 25, and support Node 26+, got ${packageEngine}`,
    );
  }
  if (lockfileEngine !== packageEngine) {
    throw new Error(
      `frontend/package-lock.json root engine ${lockfileEngine} does not match package.json ${packageEngine}`,
    );
  }
  const projectNodeVersions = [packageFloor, [24, 99, 99], [26, 0, 0], [27, 0, 0], [100, 0, 0]];

  const dependencyRanges = [];
  const node24DependencyRanges = [];
  for (const [packageName, packageMetadata] of Object.entries(lockfile.packages ?? {})) {
    if (packageName === "" || !packageMetadata.engines?.node) {
      continue;
    }
    const engine = packageMetadata.engines.node;
    const floor = minimumVersionInMajor(engine, 24);
    const entry = { packageName, engine, floor };
    dependencyRanges.push(entry);
    if (floor) {
      node24DependencyRanges.push(entry);
    }
  }
  if (node24DependencyRanges.length === 0) {
    throw new Error("could not find a Node 24 dependency engine range in frontend/package-lock.json");
  }
  const dependencyFloor = node24DependencyRanges.reduce(
    (highest, entry) => (!highest || compareVersions(entry.floor, highest) > 0 ? entry.floor : highest),
    null,
  );
  if (compareVersions(packageFloor, dependencyFloor) !== 0) {
    throw new Error(
      `frontend/package.json Node 24 floor ${versionText(packageFloor)} does not match dependency floor ${versionText(dependencyFloor)}`,
    );
  }
  for (const { packageName, engine } of dependencyRanges) {
    assert(
      projectNodeVersions.every((version) => includesVersion(engine, version)) && hasUnboundedBranchAtMajor(engine, 26),
      `${packageName} engine ${engine} does not support the project Node range ${packageEngine}`,
    );
  }

  const pins = [];
  for (const workflowPath of workflowFiles(path.join(repositoryRoot, ".github", "workflows"))) {
    const contents = fs.readFileSync(workflowPath, "utf8");
    for (const match of contents.matchAll(/^\s*node-version:\s*['"]?([^'"\s#]+)['"]?/gm)) {
      const version = parseVersion(match[1], `${path.relative(repositoryRoot, workflowPath)} node-version`);
      assert(
        includesVersion(packageEngine, version),
        `${path.relative(repositoryRoot, workflowPath)} node-version ${versionText(version)} is outside ${packageEngine}`,
      );
      if (compareVersions(version, packageFloor) !== 0) {
        throw new Error(
          `${path.relative(repositoryRoot, workflowPath)} node-version ${versionText(version)} does not match Node 24 baseline ${versionText(packageFloor)}`,
        );
      }
      pins.push({ workflowPath, version });
    }
  }
  if (pins.length === 0) {
    throw new Error("could not find any setup-node workflow version pins");
  }

  console.log(
    `Node version contract OK: range ${packageEngine}, Node 24 floor ${versionText(packageFloor)}, dependency floor ${versionText(
      dependencyFloor,
    )} (${dependencyRanges.length} lockfile engine ranges), ${pins.length} workflow pins checked`,
  );
}

export {
  compareVersions,
  hasUnboundedBranchAtMajor,
  includesVersion,
  minimumVersionInMajor,
  parseRange,
  parseVersion,
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Node version contract failed: ${error.message}`);
    process.exitCode = 1;
  }
}

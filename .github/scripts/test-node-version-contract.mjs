#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

/**
 * Keep the frontend Node.js baseline aligned with the Node.js engine ranges
 * declared by the dependency lockfile, and keep every setup-node workflow pin
 * at that baseline.
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
  const match = String(value).match(/^v?(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    throw new Error(`${label} must be an exact major.minor.patch version, got ${value}`);
  }
  return match.slice(1).map(Number);
}

function parseRangeVersion(value, label) {
  const match = String(value).match(/^v?(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?$/);
  if (!match) {
    throw new Error(`${label} is not a supported semver version, got ${value}`);
  }
  const parts = match.slice(1);
  const wildcardComponent =
    parts[1] !== undefined && /^[xX*]$/.test(parts[1]) ? 0 : parts[2] !== undefined && /^[xX*]$/.test(parts[2]) ? 1 : null;
  const precision = parts[1] === undefined ? 1 : parts[2] === undefined ? 2 : 3;
  return {
    version: parts.map((part) => (part === undefined || /^[xX*]$/.test(part) ? 0 : Number(part))),
    precision,
    wildcard: parts.slice(1).some((part) => part !== undefined && /^[xX*]$/.test(part)),
    wildcardComponent,
  };
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

function incrementVersion(version, component) {
  const next = [...version];
  next[component] += 1;
  for (let index = component + 1; index < next.length; index += 1) {
    next[index] = 0;
  }
  return next;
}

function incrementPatch(version) {
  return incrementVersion(version, 2);
}

function updateLower(current, version, inclusive) {
  if (!current) {
    return { version, inclusive };
  }
  const comparison = compareVersions(version, current.version);
  return comparison > 0 || (comparison === 0 && !inclusive && current.inclusive)
    ? { version, inclusive }
    : current;
}

function updateUpper(current, version, inclusive) {
  if (!current) {
    return { version, inclusive };
  }
  const comparison = compareVersions(version, current.version);
  return comparison < 0 || (comparison === 0 && !inclusive && current.inclusive)
    ? { version, inclusive }
    : current;
}

function parseRange(engine) {
  const normalized = String(engine)
    .replace(/([<>]=?|[~^=])\s+/g, "$1")
    .trim();
  if (!normalized) {
    return [];
  }

  return normalized.split(/\s*\|\|\s*/).map((alternative) => {
    const tokens = alternative.trim().split(/\s+/).filter(Boolean);
    let lower;
    let upper;
    for (const token of tokens) {
      const match = token.match(/^(\^|~|>=|<=|>|<|=)?(v?\d+(?:\.(?:\d+|x|X|\*))?(?:\.(?:\d+|x|X|\*))?)$/);
      if (!match) {
        throw new Error(`unsupported Node.js engine range token ${token} in ${engine}`);
      }
      const operator = match[1] ?? "";
      const parsed = parseRangeVersion(match[2], `dependency engine ${engine}`);
      const version = parsed.version;
      if (operator === "^") {
        lower = updateLower(lower, version, true);
        const upperComponent = version[0] > 0 ? 0 : version[1] > 0 ? 1 : 2;
        upper = updateUpper(upper, incrementVersion(version, upperComponent), false);
      } else if (operator === "~") {
        lower = updateLower(lower, version, true);
        upper = updateUpper(upper, incrementVersion(version, parsed.precision === 1 ? 0 : 1), false);
      } else if (operator === ">=") {
        lower = updateLower(lower, version, true);
      } else if (operator === ">") {
        lower = updateLower(lower, version, false);
      } else if (operator === "<=") {
        upper = updateUpper(upper, version, true);
      } else if (operator === "<") {
        upper = updateUpper(upper, version, false);
      } else if (operator === "=") {
        lower = updateLower(lower, version, true);
        upper = updateUpper(upper, version, true);
      } else if (parsed.precision === 1 || parsed.wildcard) {
        lower = updateLower(lower, version, true);
        upper = updateUpper(
          upper,
          incrementVersion(version, parsed.wildcardComponent === null ? 0 : parsed.wildcardComponent),
          false,
        );
      } else {
        lower = updateLower(lower, version, true);
        upper = updateUpper(upper, version, true);
      }
    }
    return { lower, upper };
  });
}

function includesVersionFromBounds(version, { lower, upper }) {
  const comparisonToLower = lower ? compareVersions(version, lower.version) : 1;
  const comparisonToUpper = upper ? compareVersions(version, upper.version) : -1;
  return (
    (!lower || comparisonToLower > 0 || (comparisonToLower === 0 && lower.inclusive)) &&
    (!upper || comparisonToUpper < 0 || (comparisonToUpper === 0 && upper.inclusive))
  );
}

function includesVersion(engine, version) {
  return parseRange(engine).some((bounds) => includesVersionFromBounds(version, bounds));
}

function minimumVersionInMajor(engine, major) {
  const candidateFloor = [major, 0, 0];
  const candidates = [];
  for (const bounds of parseRange(engine)) {
    let candidate = candidateFloor;
    if (bounds.lower) {
      if (bounds.lower.version[0] > major) {
        continue;
      }
      if (bounds.lower.version[0] === major) {
        candidate = bounds.lower.inclusive ? bounds.lower.version : incrementPatch(bounds.lower.version);
      }
    }
    if (candidate[0] === major && includesVersionFromBounds(candidate, bounds)) {
      candidates.push(candidate);
    }
  }
  return candidates.reduce(
    (minimum, candidate) => (!minimum || compareVersions(candidate, minimum) < 0 ? candidate : minimum),
    null,
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
  if (!packageFloor || packageNode25Floor || !includesVersion(packageEngine, [26, 0, 0])) {
    throw new Error(
      `frontend/package.json must support Node 24 from its dependency floor, exclude Node 25, and support Node 26+, got ${packageEngine}`,
    );
  }
  if (lockfileEngine !== packageEngine) {
    throw new Error(
      `frontend/package-lock.json root engine ${lockfileEngine} does not match package.json ${packageEngine}`,
    );
  }

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
      includesVersion(engine, packageFloor) && includesVersion(engine, [24, 99, 99]) && includesVersion(engine, [26, 0, 0]),
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

export { compareVersions, includesVersion, minimumVersionInMajor, parseRange, parseVersion };

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`Node version contract failed: ${error.message}`);
    process.exitCode = 1;
  }
}

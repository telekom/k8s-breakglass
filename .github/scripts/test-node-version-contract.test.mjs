// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  hasUnboundedBranchAtMajor,
  includesVersion,
  minimumVersionInMajor,
  parseRange,
} from "./test-node-version-contract.mjs";

test("minimum Node 24 version uses the earliest union branch", () => {
  assert.deepEqual(minimumVersionInMajor("^24.15 || ^24.16", 24), [24, 15, 0]);
});

test("an upper bound below Node 24.15 does not become a false floor", () => {
  assert.deepEqual(minimumVersionInMajor("<24.15", 24), [24, 0, 0]);
  assert.equal(includesVersion("<24.15", [24, 15, 0]), false);
});

test("Node range semantics exclude Node 25 while retaining Node 26", () => {
  const engine = "^24.15.0 || >=26.0.0";
  assert.equal(includesVersion(engine, [24, 15, 0]), true);
  assert.equal(includesVersion(engine, [24, 99, 99]), true);
  assert.equal(includesVersion(engine, [25, 0, 0]), false);
  assert.equal(includesVersion(engine, [26, 0, 0]), true);
  assert.equal(minimumVersionInMajor(engine, 25), null);
  assert.deepEqual(minimumVersionInMajor(">=24.15.0", 25), [25, 0, 0]);
});

test("comparator ranges and spaced operators are evaluated semantically", () => {
  assert.equal(includesVersion(">= 24.15.0 < 25", [24, 20, 0]), true);
  assert.equal(includesVersion(">= 24.15.0 < 25", [25, 0, 0]), false);
  assert.deepEqual(minimumVersionInMajor(">24.15.0 <25", 24), [24, 15, 1]);
  assert.deepEqual(minimumVersionInMajor(">24.15 <25", 24), [24, 16, 0]);
  assert.equal(includesVersion(">24.15", [24, 15, 1]), false);
  assert.equal(includesVersion(">24.15", [24, 16, 0]), true);
  assert.equal(includesVersion("<=24.15", [24, 15, 99]), true);
  assert.equal(includesVersion("<=24.15", [24, 16, 0]), false);
  assert.equal(includesVersion("=24.15", [24, 15, 99]), true);
  assert.equal(includesVersion("24.15", [24, 15, 99]), true);
  assert.equal(includesVersion("~24.15", [24, 15, 99]), true);
  assert.equal(includesVersion("~24.15", [24, 16, 0]), false);
  assert.equal(parseRange("^24.15 || ^24.16").length, 2);
});

test("wildcard ranges include full matching major and exclude next major", () => {
  assert.equal(includesVersion("*", [100, 0, 0]), true);
  assert.equal(includesVersion("24.*", [24, 99, 99]), true);
  assert.equal(includesVersion("24.*", [25, 0, 0]), false);
  assert.equal(includesVersion("24.15.x", [24, 15, 99]), true);
  assert.equal(includesVersion("24.15.x", [24, 16, 0]), false);
  assert.equal(includesVersion("6.* || 8.* || >= 10.*", [6, 99, 99]), true);
  assert.equal(includesVersion("6.* || 8.* || >= 10.*", [9, 0, 0]), false);
});

test("hyphen ranges use inclusive endpoints and partial upper bounds", () => {
  assert.equal(includesVersion("24.15.0 - 24.99.99", [24, 15, 0]), true);
  assert.equal(includesVersion("24.15.0 - 24.99.99", [24, 99, 99]), true);
  assert.equal(includesVersion("24.15.0 - 24.99.99", [25, 0, 0]), false);
  assert.equal(includesVersion("24.15 - 26", [24, 15, 0]), true);
  assert.equal(includesVersion("24.15 - 26", [26, 99, 99]), true);
  assert.equal(includesVersion("24.15 - 26", [27, 0, 0]), false);
});

test("Node 26 support requires an unbounded branch", () => {
  const project = "^24.15.0 || >=26.0.0";
  assert.equal(hasUnboundedBranchAtMajor(project, 26), true);
  assert.equal(hasUnboundedBranchAtMajor("^24.15.0 || ^26.0.0", 26), false);
  assert.equal(hasUnboundedBranchAtMajor(">=24.15.0 <27.0.0", 26), false);
  assert.equal(includesVersion(project, [27, 0, 0]), true);
  assert.equal(includesVersion(project, [100, 0, 0]), true);
});

test("malformed or unsupported range syntax fails closed", () => {
  assert.throws(() => parseRange("24.x.15"), /unsupported Node.js engine range/);
  assert.throws(() => parseRange("24.15.0 -"), /unsupported Node.js engine range/);
});

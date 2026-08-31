// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: CC0-1.0

import assert from "node:assert/strict";
import test from "node:test";

import { includesVersion, minimumVersionInMajor, parseRange } from "./test-node-version-contract.mjs";

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
  assert.equal(includesVersion("~24.15", [24, 15, 99]), true);
  assert.equal(includesVersion("~24.15", [24, 16, 0]), false);
  assert.equal(parseRange("^24.15 || ^24.16").length, 2);
});

test("wildcard ranges include full matching major and exclude next major", () => {
  assert.equal(includesVersion("24.*", [24, 99, 99]), true);
  assert.equal(includesVersion("24.*", [25, 0, 0]), false);
});

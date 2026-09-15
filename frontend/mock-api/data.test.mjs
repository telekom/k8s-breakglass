import test from "node:test";
import assert from "node:assert/strict";
import { createDebugSession, findDebugSession, listSessions, rejectDebugSession } from "./data.mjs";

test("bounds mock scale allocation", () => {
  assert.equal(listSessions({ mockScale: "999999999" }).length, 1000);
});

test("rejects a debug session through the mock rejection operation", () => {
  const session = createDebugSession({ reason: "needs approval" });
  const rejected = rejectDebugSession(session.metadata.name, "policy");

  assert.equal(rejected.status.state, "Rejected");
  assert.equal(rejected.status.rejectionReason, "policy");
});

test("built-in rejected session uses the rejection state", () => {
  const rejected = findDebugSession("debug-rejected-001");
  assert.equal(rejected.status.state, "Rejected");
  assert.equal(rejected.status.rejectionReason, "Insufficient justification for node-level access");
});

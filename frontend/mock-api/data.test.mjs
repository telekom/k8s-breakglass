import test from "node:test";
import assert from "node:assert/strict";
import { createDebugSession, listSessions, rejectDebugSession } from "./data.mjs";

test("bounds mock scale allocation", () => {
  assert.equal(listSessions({ mockScale: "999999999" }).length, 1000);
});

test("rejects a debug session through the mock API route handler", () => {
  const session = createDebugSession({ reason: "needs approval" });
  const rejected = rejectDebugSession(session.metadata.name, "policy");

  assert.equal(rejected.status.state, "Rejected");
  assert.equal(rejected.status.rejectionReason, "policy");
});

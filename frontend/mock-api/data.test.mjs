import test from "node:test";
import assert from "node:assert/strict";
import { createDebugSession, listSessions, updateDebugSessionState } from "./data.mjs";

test("bounds mock scale allocation", () => {
  assert.equal(listSessions({ mockScale: "999999999" }).length, 1000);
});

test("rejects a debug session with the rejected state", () => {
  const session = createDebugSession({ reason: "needs approval" });
  const rejected = updateDebugSessionState(session.metadata.name, "Rejected", { reason: "policy" });

  assert.equal(rejected.status.state, "Rejected");
  assert.equal(rejected.status.rejectionReason, "policy");
});

import test from "node:test";
import assert from "node:assert/strict";
import {
  breakglassEscalations,
  createDebugSession,
  createSessionFromRequest,
  findDebugSession,
  findSession,
  identityProviderConfig,
  listSessions,
  MOCK_APPROVER_GROUPS,
  rejectDebugSession,
  runtimeConfig,
} from "./data.mjs";

test("mock requests preserve omitted, empty and freeform ticket references", () => {
  const omitted = createSessionFromRequest();
  assert.equal(Object.hasOwn(omitted.spec, "ticketSystemID"), false);
  for (const ticketSystemID of ["", "generic 雪\nreference"]) {
    const session = createSessionFromRequest({ ticketSystemID });
    assert.equal(session.spec.ticketSystemID, ticketSystemID);
    assert.equal(findSession(session.metadata.name).spec.ticketSystemID, ticketSystemID);
    assert.equal(listSessions({ name: session.metadata.name })[0].spec.ticketSystemID, ticketSystemID);
  }
});

test("generic mock identities and clusters stay consistent across request flows", () => {
  const session = createSessionFromRequest();
  const debugSession = createDebugSession();

  assert.equal(session.spec.cluster, "production-eu");
  assert.equal(session.spec.grantedGroup, "platform-emergency");
  assert.equal(debugSession.spec.cluster, session.spec.cluster);
  assert.ok(MOCK_APPROVER_GROUPS.includes(session.spec.grantedGroup));
  assert.ok(
    breakglassEscalations.some(
      (escalation) =>
        escalation.spec.allowed.clusters.includes(session.spec.cluster) &&
        escalation.spec.allowed.groups.includes(session.spec.grantedGroup),
    ),
  );
  assert.equal(new URL(runtimeConfig.frontend.oidcAuthority).hostname, "keycloak.example.com");
  assert.equal(identityProviderConfig.keycloak.realm, "platform");
});

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

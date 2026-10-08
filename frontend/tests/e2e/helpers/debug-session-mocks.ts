// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import type { Page, Route } from "@playwright/test";

/*
 * The kind fixtures auto-approve debug sessions and never run a debug pod, so
 * UI checks that need an active session with a pod or a session awaiting
 * approval serve these debug-session responses through page.route(); the UI
 * under test is still the deployed bundle.
 */
export const DEBUG_ACTIVE = "kbd-debug-active";
export const DEBUG_PENDING = "kbd-debug-pending";

function debugSessionFixtures(owner: string) {
  const now = Date.now();
  const iso = (offsetMinutes: number) => new Date(now + offsetMinutes * 60_000).toISOString();
  const pod = {
    name: "kbd-debug-pod",
    namespace: "breakglass-debug",
    nodeName: "node-1",
    ready: true,
    phase: "Running",
  };
  const operations = { exec: true, attach: true, logs: true, portForward: true };
  const base = (name: string, state: string, requestedBy: string) => ({
    name,
    templateRef: "kbd-debug-template",
    cluster: "kbd-cluster",
    requestedBy,
    state,
    startsAt: state === "Active" ? iso(-10) : undefined,
    expiresAt: iso(50),
  });
  const summaries = [
    {
      ...base(DEBUG_ACTIVE, "Active", owner),
      requestedByDisplayName: "Keyboard Owner",
      participants: 1,
      isParticipant: true,
      allowedPods: 1,
      allowedPodOperations: operations,
    },
    {
      ...base(DEBUG_PENDING, "PendingApproval", "someone-else@example.com"),
      requestedByDisplayName: "Someone Else",
      participants: 1,
      isParticipant: false,
      allowedPods: 0,
      canApprove: true,
      canReject: true,
    },
  ];
  const details = Object.fromEntries(
    summaries.map((s) => [
      s.name,
      {
        metadata: { name: s.name, namespace: "breakglass-system", creationTimestamp: iso(-30) },
        spec: {
          templateRef: s.templateRef,
          cluster: s.cluster,
          requestedBy: s.requestedBy,
          requestedByEmail: s.requestedBy,
          requestedDuration: "1h",
          reason: "Keyboard verification",
        },
        status: {
          state: s.state,
          startsAt: s.startsAt,
          expiresAt: s.expiresAt,
          participants: [{ user: s.requestedBy, email: s.requestedBy, role: "owner", joinedAt: iso(-30) }],
          allowedPods: s.state === "Active" ? [pod] : [],
          allowedPodOperations: operations,
        },
        canApprove: s.canApprove ?? false,
        canReject: s.canReject ?? false,
      },
    ]),
  );
  return { summaries, details };
}

/** Serves debug-session list and detail responses; everything else goes to the controller. */
export async function mockDebugSessions(page: Page, owner: string) {
  const { summaries, details } = debugSessionFixtures(owner);
  await page.route(/\/api\/debugSessions(\/[^/?]+)?(\?.*)?$/, (route: Route) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() !== "GET") return route.continue();
    if (path.endsWith("/api/debugSessions")) {
      return route.fulfill({ json: { sessions: summaries, total: summaries.length } });
    }
    const detail = details[decodeURIComponent(path.split("/").pop() ?? "")];
    return detail ? route.fulfill({ json: detail }) : route.continue();
  });
}

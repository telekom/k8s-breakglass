// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import {
  TEST_USERS,
  fillScaleTextarea,
  findEscalationCardByName,
  waitForScaleModal,
  waitForScaleToast,
  type TestUser,
} from "./helpers";

interface SessionListItem {
  metadata?: { name?: string };
  status?: { state?: string };
}

interface SessionListResponse {
  items?: SessionListItem[];
}

interface DebugSessionSummary {
  name?: string;
  state?: string;
}

interface DebugSessionListResponse {
  sessions?: DebugSessionSummary[];
}

const videoDir = resolve(process.env.BREAKGLASS_UI_VIDEO_DIR || "test-results/ui-recording-segments");
const segmentsFile = resolve(process.env.BREAKGLASS_UI_SEGMENTS_FILE || `${videoDir}/segments.txt`);
const recordingPauseMs = Number(process.env.BREAKGLASS_RECORD_UI_PAUSE_MS || 2000);

async function showExplainer(page: Page, title: string, explanation: string): Promise<void> {
  await page.evaluate(
    ({ title: bannerTitle, explanation: bannerExplanation }) => {
      const id = "breakglass-recording-explainer";
      let banner = document.getElementById(id);
      if (!banner) {
        banner = document.createElement("div");
        banner.id = id;
        Object.assign(banner.style, {
          position: "fixed",
          right: "24px",
          bottom: "24px",
          left: "24px",
          zIndex: "2147483647",
          padding: "14px 18px",
          border: "2px solid #e20074",
          borderRadius: "8px",
          background: "#171717",
          color: "#ffffff",
          fontFamily: "system-ui, sans-serif",
          fontSize: "16px",
          lineHeight: "1.35",
          boxShadow: "0 4px 18px rgba(0, 0, 0, 0.35)",
          pointerEvents: "none",
        });
        document.body.appendChild(banner);
      }
      banner.textContent = `${bannerTitle}: ${bannerExplanation}`;
    },
    { title, explanation },
  );
  await page.waitForTimeout(recordingPauseMs);
}

async function loginViaUi(page: Page, user: TestUser): Promise<void> {
  await page.goto("/");
  await page.waitForLoadState("networkidle");

  const loginButton = page.getByRole("button", { name: /Log In/i }).first();
  if (await loginButton.isVisible().catch(() => false)) {
    await loginButton.click({ force: true });
    await page.waitForURL(/(?:keycloak|\/protocol\/openid-connect\/auth)/, { timeout: 60_000 });
    await page.fill("#username", user.username);
    await page.fill("#password", user.password);
    await page.click("#kc-login");
    await page.waitForURL(/localhost:\d+/, { timeout: 60_000 });
    await page.waitForLoadState("networkidle", { timeout: 60_000 });
  }

  await expect(
    page.locator('[data-testid="user-menu"], [data-testid="escalation-list"], h1:has-text("Request access")').first(),
  ).toBeVisible({ timeout: 30_000 });
}

async function getAccessToken(page: Page): Promise<string> {
  const token = await page.evaluate(() => {
    for (const storage of [window.sessionStorage, window.localStorage]) {
      for (let index = 0; index < storage.length; index++) {
        const key = storage.key(index);
        if (!key?.startsWith("oidc.user:")) continue;
        const value = storage.getItem(key);
        if (!value) continue;
        const userData = JSON.parse(value) as { access_token?: string };
        if (userData.access_token) return userData.access_token;
      }
    }
    return "";
  });
  if (!token) throw new Error("No access token found in browser storage");
  return token;
}

async function cleanupOwnBreakglassSessions(page: Page): Promise<void> {
  const token = await getAccessToken(page);
  await page.evaluate(async (authToken) => {
    const response = await fetch("/api/breakglassSessions?mine=true", {
      headers: { Accept: "application/json", Authorization: `Bearer ${authToken}` },
    });
    if (!response.ok) return;
    const data = (await response.json()) as SessionListResponse;
    for (const session of data.items || []) {
      const name = session.metadata?.name;
      const state = session.status?.state;
      if (!name) continue;
      const action = state === "Pending" ? "withdraw" : state === "Approved" ? "drop" : "";
      if (action) {
        await fetch(`/api/breakglassSessions/${encodeURIComponent(name)}/${action}`, {
          method: "POST",
          headers: { Authorization: `Bearer ${authToken}` },
        });
      }
    }
  }, token);
}

async function cleanupOwnDebugSessions(page: Page): Promise<void> {
  const token = await getAccessToken(page);
  await page.evaluate(async (authToken) => {
    const response = await fetch("/api/debugSessions?mine=true", {
      headers: { Accept: "application/json", Authorization: `Bearer ${authToken}` },
    });
    if (!response.ok) return;
    const data = (await response.json()) as DebugSessionListResponse;
    for (const session of data.sessions || []) {
      if (session.name && (session.state === "Pending" || session.state === "Active")) {
        await fetch(`/api/debugSessions/${encodeURIComponent(session.name)}/terminate`, {
          method: "POST",
          headers: { Authorization: `Bearer ${authToken}` },
        });
      }
    }
  }, token);
}

async function closeSegment(context: BrowserContext, page: Page, name: string): Promise<void> {
  const video = page.video();
  await context.close();
  if (!video) throw new Error(`No video was created for segment ${name}`);
  const path = await video.path();
  appendFileSync(segmentsFile, `${name}\t${path}\n`);
}

test.describe("Breakglass UI recording", () => {
  test.skip(!process.env.BREAKGLASS_RECORD_UI, "Set BREAKGLASS_RECORD_UI=true to create the UI recording");

  test("shows request, approval, and DebugSession workflows", async ({ browser }) => {
    test.setTimeout(300_000);
    mkdirSync(videoDir, { recursive: true });
    writeFileSync(segmentsFile, "");

    let requesterContext: BrowserContext | undefined;
    let requesterPage: Page | undefined;
    let approverContext: BrowserContext | undefined;
    let approverPage: Page | undefined;
    let finalRequesterContext: BrowserContext | undefined;
    let finalRequesterPage: Page | undefined;
    let debugContext: BrowserContext | undefined;
    let debugPage: Page | undefined;

    try {
      requesterContext = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1024, height: 768 },
        recordVideo: { dir: videoDir, size: { width: 1024, height: 768 } },
      });
      requesterPage = await requesterContext.newPage();
      await loginViaUi(requesterPage, TEST_USERS.uiE2eReqSession);
      await cleanupOwnBreakglassSessions(requesterPage);
      await requesterPage.goto("/");
      await requesterPage.waitForLoadState("networkidle");

      const escalationCard = await findEscalationCardByName(requesterPage, "ui-e2e-request-session-group", {
        requireAvailable: true,
      });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await showExplainer(
        requesterPage,
        "Step 1 - Requester",
        "Choose the escalation and submit a reason for temporary access.",
      );
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await waitForScaleModal(requesterPage, '[data-testid="request-modal"]');
      await fillScaleTextarea(
        requesterPage,
        '[data-testid="reason-input"]',
        "INC-UI-DEMO-001: inspect the service configuration",
      );
      await requesterPage.click('[data-testid="submit-request-button"]');
      await waitForScaleToast(requesterPage, "success-toast");
      await requesterPage.goto("/requests/mine");
      await requesterPage.waitForLoadState("networkidle");
      await expect(requesterPage.locator('[data-testid-generic="pending-request-card"]').first()).toBeVisible({
        timeout: 30_000,
      });
      await showExplainer(
        requesterPage,
        "Step 1 - Pending",
        "The request is recorded and waits for an authorized approver.",
      );
      await closeSegment(requesterContext, requesterPage, "requester-pending");
      requesterContext = undefined;
      requesterPage = undefined;

      approverContext = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1024, height: 768 },
        recordVideo: { dir: videoDir, size: { width: 1024, height: 768 } },
      });
      approverPage = await approverContext.newPage();
      await loginViaUi(approverPage, TEST_USERS.uiE2eApprover);
      await approverPage.goto("/approvals/pending");
      await approverPage.waitForLoadState("networkidle");
      await showExplainer(
        approverPage,
        "Step 2 - Approver",
        "Self-approval is blocked; review the requester, reason, target cluster, and expiry before approving.",
      );
      const targetCard = approverPage
        .locator('[data-testid^="pending-session-card-"]')
        .filter({ hasText: TEST_USERS.uiE2eReqSession.email })
        .first();
      await expect(targetCard).toBeVisible({ timeout: 30_000 });
      await targetCard.locator('[data-testid="review-button"]').click();
      await expect(approverPage.locator('[data-testid="requester"]')).toBeVisible({ timeout: 20_000 });
      const approvalReason = approverPage.locator('[data-testid="approval-reason-input"]');
      if (await approvalReason.isVisible().catch(() => false)) {
        await fillScaleTextarea(
          approverPage,
          '[data-testid="approval-reason-input"]',
          "Approved for the incident review",
        );
      }
      await approverPage.locator('[data-testid="approve-button"]').click();
      await waitForScaleToast(approverPage, "success-toast");
      await showExplainer(approverPage, "Step 2 - Approved", "The approver action changes the session to Approved.");
      await closeSegment(approverContext, approverPage, "approver-approval");
      approverContext = undefined;
      approverPage = undefined;

      finalRequesterContext = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1024, height: 768 },
        recordVideo: { dir: videoDir, size: { width: 1024, height: 768 } },
      });
      finalRequesterPage = await finalRequesterContext.newPage();
      await loginViaUi(finalRequesterPage, TEST_USERS.uiE2eReqSession);
      await finalRequesterPage.goto("/sessions");
      await finalRequesterPage.waitForLoadState("networkidle");
      const approvedRow = finalRequesterPage
        .locator('[data-testid="session-row"]')
        .filter({ hasText: TEST_USERS.uiE2eReqSession.email })
        .first();
      await expect(approvedRow).toContainText(/approved/i, { timeout: 30_000 });
      await showExplainer(
        finalRequesterPage,
        "Step 3 - Granted",
        "The requester can now see the approved, time-bounded access session.",
      );
      await cleanupOwnBreakglassSessions(finalRequesterPage);
      await closeSegment(finalRequesterContext, finalRequesterPage, "requester-approved");
      finalRequesterContext = undefined;
      finalRequesterPage = undefined;

      debugContext = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1024, height: 768 },
        recordVideo: { dir: videoDir, size: { width: 1024, height: 768 } },
      });
      debugPage = await debugContext.newPage();
      await loginViaUi(debugPage, TEST_USERS.requester);
      await cleanupOwnDebugSessions(debugPage);
      await debugPage.goto("/debug-sessions/create");
      await debugPage.waitForLoadState("networkidle");
      await expect(debugPage.locator('[data-testid="template-select"]')).toBeVisible({ timeout: 20_000 });
      await showExplainer(
        debugPage,
        "Step 4 - DebugSession",
        "Select the auto-approved debug template, cluster, namespace, and reason.",
      );
      const templateSelect = debugPage.locator('[data-testid="template-select"]');
      await templateSelect.click();
      await templateSelect.press("ArrowDown");
      await templateSelect.press("Enter");
      await debugPage.waitForLoadState("networkidle");
      await debugPage.locator('[data-testid="next-button"]').click();
      await debugPage.waitForLoadState("networkidle");
      await debugPage.locator(".cluster-card").first().click();
      await debugPage.waitForLoadState("networkidle");
      await fillScaleTextarea(debugPage, '[data-testid="reason-input"]', "INC-UI-DEMO-001: inspect the network path");
      await debugPage.locator('[data-testid="create-session-button"]').click();
      await waitForScaleToast(debugPage, "success-toast");
      await debugPage.goto("/debug-sessions");
      await debugPage.waitForLoadState("networkidle");
      const activeCard = debugPage
        .locator('[data-testid^="debug-session-card-"]')
        .filter({ hasText: /Active/ })
        .first();
      await expect(activeCard).toBeVisible({ timeout: 90_000 });
      await showExplainer(
        debugPage,
        "Step 4 - Active",
        "The DebugSession pod is active and ready for controlled diagnostics.",
      );
      const terminateButton = activeCard.locator('[data-testid="terminate-button"]');
      if (await terminateButton.isVisible().catch(() => false)) {
        await terminateButton.click();
        await waitForScaleToast(debugPage, "success-toast");
        await showExplainer(
          debugPage,
          "Step 4 - Terminated",
          "Termination revokes the DebugSession and cleans up its controlled workload.",
        );
      } else {
        await cleanupOwnDebugSessions(debugPage);
      }
      await closeSegment(debugContext, debugPage, "debug-session");
      debugContext = undefined;
      debugPage = undefined;
    } finally {
      if (requesterPage) await cleanupOwnBreakglassSessions(requesterPage).catch(() => undefined);
      if (finalRequesterPage) await cleanupOwnBreakglassSessions(finalRequesterPage).catch(() => undefined);
      if (debugPage) await cleanupOwnDebugSessions(debugPage).catch(() => undefined);
      await requesterContext?.close();
      await approverContext?.close();
      await finalRequesterContext?.close();
      await debugContext?.close();
    }
  });
});

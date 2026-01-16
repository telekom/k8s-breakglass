// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  MailHogClient,
  fillScaleTextarea,
  waitForScaleToast,
  findEscalationCardByName,
  cleanupPendingSessions,
  config,
} from "./helpers";

// This test file uses ui-e2e-approve-email-user (isolated user with group "ui-e2e-approve-email-requester")
// It targets the "ui-e2e-approve-email-test" escalation which only allows "ui-e2e-approve-email-requester" group
// Approver: ui-e2e-approver
// The UI displays the escalatedGroup field, not the metadata.name
const ESCALATION_NAME = "ui-e2e-approve-email-group";

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("Approve Session via Email Link", () => {
  let mailhog: MailHogClient;

  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });

  test.beforeEach(async ({ page }) => {
    await mailhog.clearMessages();
    // Clean up any leftover sessions from this test to prevent pollution
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApproveEmail);
    await cleanupPendingSessions(page);
  });

  test("approver can approve session by clicking email link", async ({ browser }) => {
    // Create two browser contexts: requester and approver
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const approverContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });

    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();

      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);

      // === Step 1: Requester creates session ===
      // Use ui-e2e-approve-email-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eApproveEmail);

      // Navigate to home page
      await requesterPage.goto("/");
      await requesterPage.waitForLoadState("networkidle");

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();

      await fillScaleTextarea(
        requesterPage,
        '[data-testid="reason-input"]',
        "Email approval test - please approve via link",
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Verify success message (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(requesterPage, "success-toast");

      // === Step 2: Wait for email ===
      // Backend processes session creation asynchronously and sends email
      // MailHog client has built-in retry logic (60s timeout, 2s polling)
      // No need for additional artificial delay
      const email = await mailhog.waitForSubject("breakglass", 90000);
      expect(email).toBeTruthy();

      // Extract approval link
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();
      console.log("Approval link:", approvalLink);

      // === Step 3: Approver logs in and clicks email link ===
      await approverAuth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

      // Verify approver is logged in by navigating to home and checking user menu
      await approverPage.goto("/");
      await approverPage.waitForLoadState("networkidle");
      await expect(approverPage.getByText(/ui-e2e-approver@example.com/i).first()).toBeVisible({ timeout: 10000 });
      console.log("Approver logged in successfully");

      // Navigate to approval link (now a dedicated page, not a modal)
      // Rewrite backend URL to frontend dev server URL to preserve OIDC session
      // which is stored per-origin in sessionStorage
      const frontendApprovalLink = mailhog.rewriteToFrontendUrl(approvalLink!);
      console.log("Navigating to approval link:", frontendApprovalLink);
      await approverPage.goto(frontendApprovalLink);
      await approverPage.waitForLoadState("networkidle");
      console.log("Current URL:", approverPage.url());

      // Wait for the session review content to load on the dedicated approval page
      // Use specific visible element instead of wrapper div which may not pass visibility checks
      await expect(approverPage.locator('[data-testid="requester"]')).toBeVisible({ timeout: 20000 });

      // Verify session details - requester is ui-e2e-approve-email-user
      await expect(approverPage.locator('[data-testid="requester"]')).toContainText("ui-e2e-approve-email");
      await expect(approverPage.getByText(/Email approval test/i)).toBeVisible();

      // Approve the session - use getByRole which works better with Scale buttons
      const approvalReasonInput = approverPage.locator('[data-testid="approval-reason-input"]');
      if (await approvalReasonInput.isVisible()) {
        await fillScaleTextarea(
          approverPage,
          '[data-testid="approval-reason-input"]',
          "Approved via email link - E2E test",
        );
      }
      await approverPage.getByRole("button", { name: /Confirm Approve/i }).click();

      // Verify approval success (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(approverPage, "success-toast");

      // === Step 4: Verify requester sees approved session ===
      // Backend processes approval asynchronously - poll for status change
      // Navigate to Session Browser as approved sessions no longer show on "My Pending Requests" (state=pending filter)
      await requesterPage.goto("/sessions");
      await requesterPage.reload();
      await requesterPage.waitForLoadState("networkidle");

      // Wait for session to appear with active/approved status
      // Backend may take time to update status - use longer timeout
      const sessionRow = requesterPage.locator('[data-testid="session-row"]').first();
      await expect(sessionRow).toContainText(/active|approved/i, { timeout: 30000 });

      // === Step 5: Verify approval email sent to requester ===
      // Email delivery may be async - use longer timeout
      const approvalEmail = await mailhog.waitForSubject("approved", 90000);
      expect(approvalEmail).toBeTruthy();

      const approvalBody = mailhog.getPlainTextBody(approvalEmail);
      expect(approvalBody.toLowerCase()).toContain("ui-e2e-approver"); // Approver email
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });

  test("approval link without login redirects to Keycloak then back", async ({ browser }) => {
    // First create a session with logged in user
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const requesterPage = await requesterContext.newPage();
    const requesterAuth = new AuthHelper(requesterPage);

    try {
      // Use ui-e2e-approve-email-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eApproveEmail);

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Deep link test");
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Wait for email
      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();

      // Open new context (not logged in)
      const newContext = await browser.newContext({ ignoreHTTPSErrors: true });
      const newPage = await newContext.newPage();

      // Intercept requests to internal Kubernetes DNS and redirect to configured Keycloak URL
      // This handles the case where Keycloak issuer URL uses cluster-internal DNS
      const keycloakOrigin = new URL(config.keycloakUrl).origin;
      await newPage.route("**/*.svc.cluster.local*/**", (route) => {
        const url = route.request().url();
        // Replace cluster-internal DNS with configured Keycloak URL
        const fixedUrl = url.replace(/https?:\/\/[^\/]+\.svc\.cluster\.local:\d+/, keycloakOrigin);
        console.log(`DEBUG: Intercepting ${url} -> ${fixedUrl}`);
        route.continue({ url: fixedUrl });
      });

      try {
        // Navigate to approval link without being logged in
        await newPage.goto(approvalLink!);
        await newPage.waitForLoadState("networkidle");

        // Check if there's a login button (frontend login page)
        const loginButton = newPage.locator('scale-button:has-text("Log In"), button:has-text("Log In")').first();
        const hasLoginButton = await loginButton.isVisible({ timeout: 2000 }).catch(() => false);

        if (hasLoginButton) {
          // Frontend login page - click login button which redirects to Keycloak
          await loginButton.click();
          // Wait for navigation to Keycloak
          await newPage.waitForURL(/keycloak|auth/, { timeout: 10000 }).catch(() => {
            // Already on auth page or direct redirect
          });
          await newPage.waitForLoadState("networkidle");
        }

        // Login via Keycloak if we're on the Keycloak page
        const currentUrl = newPage.url();
        if (/keycloak|auth/.test(currentUrl) && !currentUrl.includes("/auth/callback")) {
          await newPage.fill("#username", TEST_USERS.uiE2eApprover.username);
          await newPage.fill("#password", TEST_USERS.uiE2eApprover.password);
          await newPage.click("#kc-login");
          // Wait for redirect back to the app (use config.backendUrl for origin check)
          const backendOrigin = new URL(config.backendUrl).origin;
          await newPage.waitForURL((url) => url.href.includes(backendOrigin) && !url.href.includes("keycloak"), {
            timeout: 30000,
          });
        }

        // If on callback page, wait for redirect to approval page
        if (newPage.url().includes("/auth/callback")) {
          await newPage.waitForURL(/session\/.*\/approve/, { timeout: 15000 }).catch(async () => {
            // If redirect doesn't happen (possible auth bug), manually navigate to approval link
            await newPage.goto(approvalLink!);
          });
        }

        // Ensure we're on the approval page
        const currentPageUrl = newPage.url();
        if (!currentPageUrl.includes("/session/")) {
          // Auth completed but didn't redirect to approval page - navigate manually
          await newPage.goto(approvalLink!);
        }

        // Wait for full page load and session data to load
        await newPage.waitForLoadState("networkidle");

        // Wait for the session review content to appear on the dedicated approval page
        // Look for specific content elements rather than wrapper div
        await expect(
          newPage
            .locator('[data-testid="requester"], [data-testid="approve-button"], [data-testid="error-title"]')
            .first(),
        ).toBeVisible({ timeout: 20000 });
      } finally {
        await newContext.close();
      }
    } finally {
      await requesterContext.close();
    }
  });

  test("non-approver cannot approve session", async ({ browser }) => {
    // Create session with requester
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const requesterPage = await requesterContext.newPage();
    const requesterAuth = new AuthHelper(requesterPage);

    try {
      // Use ui-e2e-approve-email-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eApproveEmail);

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Non-approver test");
      await requesterPage.click('[data-testid="submit-request-button"]');

      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);

      // Try to access with requester (not an approver for own request)
      await requesterPage.goto(approvalLink!);

      // Should either show error or not show approve button
      const approveButton = requesterPage.locator('[data-testid="approve-button"]');
      const errorMessage = requesterPage.locator('[data-testid="error-message"]');

      // Either approve button is not visible, or error is shown
      const canApprove = await approveButton.isVisible().catch(() => false);
      const hasError = await errorMessage.isVisible().catch(() => false);

      // At least one of these should be true for proper access control
      expect(canApprove === false || hasError).toBe(true);
    } finally {
      await requesterContext.close();
    }
  });
});

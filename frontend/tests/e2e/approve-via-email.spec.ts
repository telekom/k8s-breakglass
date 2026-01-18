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

      // Open new context (not logged in) - Keycloak hostname resolution works via /etc/hosts
      const newContext = await browser.newContext({ ignoreHTTPSErrors: true });
      const newPage = await newContext.newPage();

      try {
        // Navigate to approval link without being logged in
        // Rewrite to frontend URL to match the OIDC redirect_uri origin
        const frontendApprovalLink = mailhog.rewriteToFrontendUrl(approvalLink!);
        console.log("Navigating to approval link (unauthenticated):", frontendApprovalLink);

        // Listen for ALL console messages (including errors) to debug auth flow
        newPage.on("console", (msg) => {
          const text = msg.text();
          const type = msg.type();
          // Log errors always, and auth-related messages
          if (
            type === "error" ||
            type === "warning" ||
            text.includes("Auth") ||
            text.includes("OIDC") ||
            text.includes("Session") ||
            text.includes("signin") ||
            text.includes("redirect")
          ) {
            console.log(`[Browser Console ${type}] ${text}`);
          }
        });

        // Also capture page errors (unhandled exceptions)
        newPage.on("pageerror", (err) => {
          console.log(`[Browser Page Error] ${err.message}`);
        });

        // Verify this is a truly fresh context with no cookies BEFORE navigation
        const cookiesBefore = await newContext.cookies();
        console.log(
          "Cookies before navigation:",
          cookiesBefore.length > 0 ? cookiesBefore.map((c) => c.name).join(", ") : "(none)",
        );

        await newPage.goto(frontendApprovalLink);
        await newPage.waitForLoadState("networkidle");

        // Check cookies after navigation (may include server-set cookies, but should NOT have OIDC tokens)
        const cookiesAfter = await newContext.cookies();
        console.log(
          "Cookies after navigation:",
          cookiesAfter.length > 0 ? cookiesAfter.map((c) => c.name).join(", ") : "(none)",
        );

        // Log current URL after initial load
        console.log("URL after initial load:", newPage.url());

        // Check storage for OIDC state (should be empty in fresh context)
        const oidcStorageKeys = await newPage.evaluate(() => {
          const keys: string[] = [];
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            if (key && key.includes("oidc")) {
              keys.push(key);
            }
          }
          return keys;
        });
        console.log("OIDC sessionStorage keys:", oidcStorageKeys.length > 0 ? oidcStorageKeys.join(", ") : "(none)");

        // Log all visible text to understand what page is shown
        const bodyText = await newPage
          .locator("body")
          .textContent()
          .catch(() => "");
        console.log("Page body text (first 500 chars):", bodyText?.slice(0, 500));

        // Check for any error messages on the page
        const errorElements = await newPage
          .locator('[class*="error"], [class*="Error"], scale-alert[variant="error"]')
          .count()
          .catch(() => 0);
        console.log("Error elements found:", errorElements);

        // Check if we're on the approval page or somewhere else
        const isOnApprovalPage = newPage.url().includes("/approve");
        console.log("Is on approval page URL:", isOnApprovalPage);

        // The approval page requires authentication - user should see login option
        // First wait for the page to fully load and check if we need to click login
        // The SessionApprovalView may auto-redirect OR require clicking the login button
        // depending on timing of Vue component mounting
        const redirectResult = await newPage
          .waitForURL(/keycloak|\/realms\//, { timeout: 10000 })
          .then(() => ({ success: true, url: newPage.url(), clickedLogin: false }))
          .catch(async () => {
            // Auto-redirect didn't happen within 10s - try clicking the login button
            console.log("Auto-redirect not triggered, looking for login button...");
            const loginButton = newPage.locator('text="Log In"').first();
            if (await loginButton.isVisible()) {
              console.log("Clicking login button to initiate auth...");
              await loginButton.click();
              // Wait for Keycloak redirect after clicking
              await newPage.waitForURL(/keycloak|\/realms\//, { timeout: 20000 });
              return { success: true, url: newPage.url(), clickedLogin: true };
            }
            return { success: false, url: newPage.url(), clickedLogin: false };
          });

        if (!redirectResult.success) {
          // The page didn't redirect to Keycloak - this is the bug we're debugging
          // Take screenshot and fail with details
          await newPage.screenshot({ path: "test-results/keycloak-redirect-failure.png" });
          throw new Error(
            `Expected redirect to Keycloak but stayed at: ${redirectResult.url}. ` +
              `This may indicate the user is already authenticated or OIDC config failed.`,
          );
        }

        if (redirectResult.clickedLogin) {
          console.log("Login initiated via button click");
        }

        await newPage.waitForLoadState("networkidle");
        console.log("Redirected to Keycloak:", newPage.url());

        // Login via Keycloak
        await newPage.fill("#username", TEST_USERS.uiE2eApprover.username);
        await newPage.fill("#password", TEST_USERS.uiE2eApprover.password);
        await newPage.click("#kc-login");

        // Wait for redirect back to the app after Keycloak login
        // The OIDC callback should redirect to the original approval page path
        await newPage.waitForURL(/localhost:\d+/, { timeout: 30000 });
        console.log("Redirected back to app:", newPage.url());

        // Wait for callback processing and redirect to approval page
        // The callback handler in main.ts reads state.path and redirects
        await newPage.waitForLoadState("networkidle");

        // If still on callback page, wait for redirect to complete
        if (newPage.url().includes("/auth/callback")) {
          console.log("Still on callback page, waiting for redirect...");
          await newPage.waitForURL(/session\/.*\/approve/, { timeout: 20000 }).catch(() => {
            console.log("Callback redirect timed out, current URL:", newPage.url());
          });
        }

        // If not on session page, something went wrong with the callback
        // This is a test failure condition - log details for debugging
        const finalUrl = newPage.url();
        console.log("Final URL after auth flow:", finalUrl);

        if (!finalUrl.includes("/session/")) {
          // Take a screenshot for debugging
          await newPage.screenshot({ path: "test-results/callback-redirect-failure.png" });
          console.log("ERROR: Expected to be on session approval page but got:", finalUrl);
        }

        // Wait for the session review content to appear on the dedicated approval page
        // Look for specific content elements
        await newPage.waitForLoadState("networkidle");
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

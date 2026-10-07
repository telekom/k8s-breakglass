// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  cleanupPendingSessions,
  fillScaleTextField,
  fillScaleTextarea,
  findEscalationCardByName,
  waitForScaleModal,
  waitForScaleToast,
} from "./helpers";

const RESOURCE_NAME = "breakglass-ui-e2e-display-name-test";
const DISPLAY_NAME = "Production Admin Display Name E2E";
const GROUP = "ui-e2e-display-name-group";
const FALLBACK_NAME = "breakglass-ui-e2e-display-fallback-test";

test.describe.serial("Escalation display names", () => {
  test.beforeEach(async ({ page }) => {
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eReqSession);
    await cleanupPendingSessions(page);
    await page.goto("/");
  });

  test.afterEach(async ({ page }) => {
    await cleanupPendingSessions(page);
  });

  test("displayName is shown, searchable by both identities, and preserves real access requests", async ({ page }) => {
    const card = page.locator(`[data-escalation-name="${RESOURCE_NAME}"]`);
    await expect(card.locator('[data-testid="summary-card-title"]')).toHaveText(DISPLAY_NAME);
    await expect(card.locator('[data-testid="escalation-name"]')).toHaveText(GROUP);

    for (const identity of [DISPLAY_NAME, RESOURCE_NAME]) {
      await fillScaleTextField(page, '[data-testid="escalation-search"]', identity);
      await expect(page.locator('[data-testid="escalation-card"]')).toHaveCount(1);
      await expect(card).toBeVisible();
    }

    const availableCard = await findEscalationCardByName(page, GROUP, { requireAvailable: true });
    expect(availableCard).not.toBeNull();
    if (!availableCard) throw new Error("Display-name fixture must be available for requests");
    await availableCard.locator('[data-testid="request-access-button"]').click();
    await waitForScaleModal(page, '[data-testid="request-modal"]');
    const reason = "E2E display name request preserves cluster and granted group";
    await fillScaleTextarea(page, '[data-testid="reason-input"]', reason);

    const responsePromise = page.waitForResponse(
      (response) => response.request().method() === "POST" && response.url().endsWith("/api/breakglassSessions"),
    );
    await page.locator('[data-testid="submit-request-button"]').click();
    const response = await responsePromise;
    expect(response.ok()).toBe(true);
    expect(response.request().postDataJSON()).toMatchObject({ cluster: "breakglass-hub", group: GROUP });
    await waitForScaleToast(page, "success-toast");
    await page.goto("/requests/mine");
    const pendingCard = page.locator('[data-testid-generic="pending-request-card"]').filter({ hasText: GROUP });
    await expect(pendingCard).toBeVisible({ timeout: 30000 });
    await expect(pendingCard).toContainText(reason);
    await expect(pendingCard).toContainText(/pending/i);
  });

  test("an escalation without displayName shows and searches metadata.name", async ({ page }) => {
    const card = page.locator(`[data-escalation-name="${FALLBACK_NAME}"]`);
    await expect(card.locator('[data-testid="summary-card-title"]')).toHaveText(FALLBACK_NAME);
    await expect(card).toHaveAttribute("data-escalation-identities", JSON.stringify([FALLBACK_NAME]));
    await fillScaleTextField(page, '[data-testid="escalation-search"]', FALLBACK_NAME);
    await expect(page.locator('[data-testid="escalation-card"]')).toHaveCount(1);
    await expect(card).toBeVisible();
  });
});

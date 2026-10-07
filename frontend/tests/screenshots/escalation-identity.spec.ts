// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { findEscalationCardByName, waitForScaleModal } from "../e2e/helpers/scale-components";
import { performMockLogin } from "./helpers";

for (const displayName of ["Production administrators", undefined]) {
  test(`escalation identity remains discoverable with displayName ${displayName ?? "omitted"}`, async ({ page }) => {
    const escalations = [
      { name: "admin-a1b2c3d4", displayName },
      { name: "admin-e5f6a7b8", displayName: "Secondary administrators" },
    ].map(({ name, displayName }) => ({
      metadata: { name },
      spec: {
        displayName,
        escalatedGroup: "admin-group",
        allowed: { clusters: ["prod"], groups: ["dev"] },
        approvers: { groups: ["approvers"] },
        maxValidFor: "1h",
      },
    }));
    await page.route("**/api/breakglassEscalations*", (route) =>
      route.fulfill({ json: { items: escalations, total: escalations.length } }),
    );
    await page.route("**/api/breakglassSessions*", (route) => route.fulfill({ json: { items: [], total: 0 } }));
    await performMockLogin(page);
    await expect(page.getByTestId("escalation-card")).toHaveCount(1);

    // Use the unchanged real-backend E2E helper: lookup remains by granted group.
    const card = await findEscalationCardByName(page, "admin-group", { requireAvailable: true });
    expect(card).not.toBeNull();
    if (!card) throw new Error("Escalation is not discoverable with the existing E2E helper");
    await expect(card.getByTestId("summary-card-title")).toHaveText(displayName || "admin-a1b2c3d4");
    await expect(card.getByTestId("escalation-name")).toHaveText("admin-group");
    await expect(card).toHaveAttribute("data-escalation-name", "admin-a1b2c3d4");
    expect(JSON.parse((await card.getAttribute("data-escalation-identities"))!)).toEqual(
      ["admin-a1b2c3d4", displayName || "admin-a1b2c3d4", "admin-e5f6a7b8", "Secondary administrators"].filter(
        (identity, index, identities) => identities.indexOf(identity) === index,
      ),
    );

    await page.getByRole("searchbox", { name: "Search escalations" }).fill("admin-e5f6a7b8");
    await expect(card).toBeVisible();
    await expect(card.getByTestId("request-access-button")).toBeVisible();
    await card.getByTestId("request-access-button").click();
    await waitForScaleModal(page, '[data-testid="request-modal"]');
    await expect(page.getByRole("button", { name: "Confirm Request", exact: true })).toBeVisible();
  });
}

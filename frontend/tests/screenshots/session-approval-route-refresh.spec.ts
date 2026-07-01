import { test, expect, Page } from "@playwright/test";
import { navigateWithRouter, performMockLogin } from "./helpers";

function approvalPayload(name: string, requester: string) {
  return {
    session: {
      metadata: { name },
      spec: {
        user: requester,
        cluster: "prod-eu",
        grantedGroup: "cluster-admin",
        requestReason: `Route refresh check for ${name}`,
      },
      status: {
        state: "Pending",
        approverGroups: ["platform-oncall"],
      },
    },
    approvalMeta: {
      canApprove: true,
      canReject: true,
      isRequester: false,
      isApprover: true,
      sessionState: "Pending",
    },
  };
}

async function exerciseApprovalRouteRefresh(page: Page) {
  const fetchedSessions: string[] = [];

  await page.route(/\/api\/breakglassSessions\/session-[ab]$/, async (route) => {
    const name = route.request().url().endsWith("session-a") ? "session-a" : "session-b";
    fetchedSessions.push(name);
    const requester = name === "session-a" ? "requester-a@example.com" : "requester-b@example.com";
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(approvalPayload(name, requester)),
    });
  });

  await performMockLogin(page);
  await navigateWithRouter(page, "/session/session-a/approve");
  await expect(page.getByTestId("requester")).toContainText("requester-a@example.com");

  await navigateWithRouter(page, "/session/session-b/approve");

  await expect(page).toHaveURL(/\/session\/session-b\/approve$/);
  await expect(page.getByTestId("requester")).toContainText("requester-b@example.com");
  await expect(page.getByTestId("requester")).not.toContainText("requester-a@example.com");
  expect(fetchedSessions).toEqual(["session-a", "session-b"]);
}

test.describe("Session approval route refresh", () => {
  test("desktop route reuse refreshes the displayed session", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 720 });
    await exerciseApprovalRouteRefresh(page);
    await expect(page).toHaveScreenshot("session-approval-route-refresh-desktop.png", { fullPage: true });
  });

  test("mobile route reuse refreshes the displayed session", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await exerciseApprovalRouteRefresh(page);
    await expect(page).toHaveScreenshot("session-approval-route-refresh-mobile.png", { fullPage: true });
  });
});

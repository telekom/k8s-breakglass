// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Locator, type Page } from "@playwright/test";
import {
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  expectDisabledWithReason,
  expectFocusOnPageHeading,
  expectModalDialog,
  expectTabOrderFollowsReadingOrder,
  expectToastAnnounced,
  focusedStop,
  mockDebugSessions,
  mockLogin,
  mockNavigate,
} from "./helpers";

/**
 * Screen-reader-equivalent checks on the mock dev server, read from
 * Playwright's accessibility tree (which includes Scale's shadow DOM):
 *  - every dialog is a modal dialog named by its heading, with the expected
 *    roles, names and states; disabled actions carry their reason as the
 *    accessible description,
 *  - focus moves into a dialog, stays trapped, and returns to the opener on
 *    Escape, the close button and Cancel,
 *  - the Tab order of key pages has named stops in reading order,
 *  - route changes move focus to the page h1,
 *  - toasts are rendered into a live region that exists before they appear.
 * ui-screen-reader.spec.ts repeats the core checks on the deployed bundle.
 */

type DialogCase = {
  name: string;
  route: string;
  opener: string;
  modal: string;
  tree: string;
  disabled?: Array<{ button: string; reason: string }>;
};

const DIALOGS: DialogCase[] = [
  {
    name: "Request breakglass",
    route: "/",
    opener: '[data-testid="request-access-button"]',
    modal: '[data-testid="request-modal"]',
    tree: `
      - dialog "Request breakglass":
        - heading "Request breakglass" [level=2]
        - button "Close"
        - textbox "Duration"
        - button "Show common durations"
        - button "Schedule for future date (optional)"
        - textbox "Reason" [invalid]
        - paragraph: Reason is required.
        - button "Confirm Request" [disabled]
        - button "Cancel"
    `,
    disabled: [{ button: "Confirm Request", reason: "Enter a reason to submit the request." }],
  },
  {
    name: "Review Session",
    route: "/approvals/pending",
    opener: '.approval-card-shell:has(scale-tag:has-text("Note required")) [data-testid="review-button"]',
    modal: '[data-testid="approval-modal"]',
    tree: `
      - dialog "Review Session":
        - heading "Review Session" [level=2]
        - button "Close"
        - textbox "Approver Note" [invalid]
        - alert: This field is required.
        - button "Cancel"
        - button "Reject" [disabled]
        - button "Confirm Approve" [disabled]
    `,
    disabled: [
      { button: "Reject", reason: "Enter the required note before approving or rejecting." },
      { button: "Confirm Approve", reason: "Enter the required note before approving or rejecting." },
    ],
  },
  {
    name: "Withdraw Request",
    route: "/requests/mine",
    opener: '[data-testid="withdraw-button"]',
    modal: '[data-testid="withdraw-confirm-modal"]',
    tree: `
      - dialog "Withdraw Request":
        - heading "Withdraw Request" [level=2]
        - button "Close"
        - paragraph: Are you sure you want to withdraw this request? This action cannot be undone.
        - button "Cancel"
        - button "Withdraw"
    `,
  },
  {
    name: "Renew Debug Session",
    route: "/debug-sessions",
    opener: `[data-testid="debug-session-card-${DEBUG_ACTIVE}"] [data-testid="renew-button"]`,
    modal: `[data-testid="debug-session-card-${DEBUG_ACTIVE}"] [data-testid="renew-modal"]`,
    tree: `
      - dialog "Renew Debug Session":
        - heading "Renew Debug Session" [level=2]
        - button "Close"
        - combobox "Extend By"
        - button "Cancel"
        - button "Renew"
    `,
  },
  {
    name: "Reject Debug Session",
    route: "/debug-sessions",
    opener: `[data-testid="debug-session-card-${DEBUG_PENDING}"] [data-testid="reject-button"]`,
    modal: `[data-testid="debug-session-card-${DEBUG_PENDING}"] [data-testid="reject-modal"]`,
    tree: `
      - dialog "Reject Debug Session":
        - heading "Reject Debug Session" [level=2]
        - button "Close"
        - textbox "Rejection Reason"
        - button "Cancel"
        - button "Reject" [disabled]
    `,
    disabled: [{ button: "Reject", reason: "Enter a reason to reject the session." }],
  },
  {
    name: "Reject Session",
    route: `/debug-sessions/${DEBUG_PENDING}`,
    opener: '[data-testid="reject-session-button"]',
    modal: '[data-testid="reject-session-modal"]',
    tree: `
      - dialog "Reject Session":
        - heading "Reject Session" [level=2]
        - button "Close"
        - textbox "Rejection Reason"
        - button "Cancel"
        - button "Reject"
    `,
  },
  {
    name: "Renew Session",
    route: `/debug-sessions/${DEBUG_ACTIVE}`,
    opener: '[data-testid="renew-session-button"]',
    modal: '[data-testid="renew-session-modal"]',
    tree: `
      - dialog "Renew Session":
        - heading "Renew Session" [level=2]
        - button "Close"
        - combobox "Duration"
        - button "Cancel"
        - button "Renew"
    `,
  },
];

const OPEN_TRANSITION_MS = 500;

/** True when keyboard focus is on the host or inside it (including its shadow root). */
function focusIsWithin(host: Locator): Promise<boolean> {
  return host.evaluate(
    (el) => !!document.activeElement && (el === document.activeElement || el.contains(document.activeElement)),
  );
}

async function openWithKeyboard(page: Page, opener: Locator, modal: Locator, name: string) {
  await opener.locator("button").first().focus();
  const openerStop = await focusedStop(page);
  await page.keyboard.press("Enter");
  const dialog = await expectModalDialog(modal, name);
  await page.waitForTimeout(OPEN_TRANSITION_MS);
  expect(await focusIsWithin(modal), `focus should stay in "${name}" after its open transition`).toBe(true);
  return { dialog, openerStop };
}

/** Tab and Shift+Tab never leave the dialog and wrap back to the starting control. */
async function expectFocusTrapped(page: Page, modal: Locator, name: string) {
  for (const key of ["Tab", "Shift+Tab"]) {
    const start = (await focusedStop(page))?.aria;
    const visited: string[] = [];
    for (let i = 0; i < 30; i++) {
      await page.keyboard.press(key);
      const stop = await focusedStop(page);
      expect(await focusIsWithin(modal), `${name}: ${key} #${i + 1} left the dialog (focus on ${stop?.aria})`).toBe(
        true,
      );
      visited.push(stop?.aria ?? "");
      if (stop?.aria === start) break;
    }
    expect(visited.at(-1), `${name}: ${key} should wrap back to ${start}: ${visited.join(" | ")}`).toBe(start);
  }
}

async function expectFocusBackOnOpener(page: Page, opener: Locator, expected: string | undefined, how: string) {
  await expect
    .poll(async () => ((await focusIsWithin(opener)) ? (await focusedStop(page))?.aria : "elsewhere"), {
      message: `${how} should return focus to the opener`,
    })
    .toBe(expected);
}

test.describe("Screen reader semantics (mock)", () => {
  test.beforeEach(async ({ page }) => {
    await mockDebugSessions(page, "mock.user@breakglass.dev");
    await mockLogin(page);
  });

  for (const dialogCase of DIALOGS) {
    test(`${dialogCase.name} dialog: modal semantics, focus trap and focus restore`, async ({ page }) => {
      await mockNavigate(page, dialogCase.route);
      const opener = page.locator(dialogCase.opener).filter({ visible: true }).first();
      const modal = page.locator(dialogCase.modal).first();
      await expect(opener).toBeVisible();

      const { dialog, openerStop } = await openWithKeyboard(page, opener, modal, dialogCase.name);
      expect(openerStop?.aria).toMatch(/^button "\S/);
      await expect(dialog).toMatchAriaSnapshot(dialogCase.tree);
      for (const { button, reason } of dialogCase.disabled ?? []) {
        // Slotted controls are light-DOM children of the modal host, not of its shadow dialog element.
        await expectDisabledWithReason(modal, button, reason);
      }
      await expectFocusTrapped(page, modal, dialogCase.name);

      await page.keyboard.press("Escape");
      await expect(dialog).toBeHidden();
      await expectFocusBackOnOpener(page, opener, openerStop?.aria, "Escape");

      for (const button of ["Close", "Cancel"]) {
        await page.keyboard.press("Enter");
        await expectModalDialog(modal, dialogCase.name);
        await page.waitForTimeout(OPEN_TRANSITION_MS);
        await modal.getByRole("button", { name: button, exact: true }).focus();
        await page.keyboard.press("Enter");
        await expect(dialog).toBeHidden();
        await expectFocusBackOnOpener(page, opener, openerStop?.aria, `${button} button`);
      }
    });
  }

  test("Tab order on key pages has named stops in reading order", async ({ page }) => {
    // Start away from "/" (the page after login): only real navigations move focus.
    const routes = [
      "/requests/mine",
      "/approvals/pending",
      "/sessions",
      "/debug-sessions",
      "/debug-sessions/create",
      `/debug-sessions/${DEBUG_ACTIVE}`,
      "/",
    ];
    for (const route of routes) {
      await mockNavigate(page, route);
      await expectFocusOnPageHeading(page, route);
      const stops = await expectTabOrderFollowsReadingOrder(page, route, { maxStops: 25 });
      expect(stops.length, `${route}: too few Tab stops: ${stops.join(" | ")}`).toBeGreaterThan(1);
    }
  });

  test("route changes move focus to the page h1", async ({ page }) => {
    // Activate the main navigation links from the keyboard, as a screen reader user would.
    for (const [link, heading] of [
      ["Approvals", "Pending Approvals"],
      ["Request", "Request access"],
    ]) {
      const item = page.getByRole("link", { name: link, exact: true }).filter({ visible: true }).first();
      await item.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(heading);
      await expectFocusOnPageHeading(page, `${link} link`);
    }
  });

  test("toasts are announced through a live region", async ({ page }) => {
    // The region must exist before the toast is inserted, or screen readers ignore it.
    const region = page.locator('.toast-region[aria-live="polite"]');
    await expect(region).toHaveCount(1);
    await expect(region.locator("scale-notification-toast")).toHaveCount(0);

    // Keep the shared mock server state intact so the withdraw dialog test stays repeatable.
    await page.route("**/api/breakglassSessions/*/withdraw", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: '{"message":"session withdrawn"}' }),
    );
    await mockNavigate(page, "/requests/mine");
    await page.locator('[data-testid="withdraw-button"]').filter({ visible: true }).first().click();
    const modal = page.locator('[data-testid="withdraw-confirm-modal"]').first();
    await expectModalDialog(modal, "Withdraw Request");
    await modal.getByRole("button", { name: "Withdraw", exact: true }).click();
    await expectToastAnnounced(page, "success-toast", /Withdrew request/);

    await page.route("**/api/breakglassEscalations**", (route) =>
      route.fulfill({ status: 500, contentType: "application/json", body: '{"error":"boom"}' }),
    );
    await mockNavigate(page, "/");
    await expectToastAnnounced(page, "error-toast", /./);
  });
});

test.describe("Tab order audit", () => {
  // Positive tabindex values reverse the Tab sequence without changing the reading order.
  // Each case gets a fresh page: the sequential focus starting point survives setContent.
  // The trailing button ends the walk; Firefox otherwise wraps Tab back into main.
  const withExit = (main: string) => `${main}<button>After main</button>`;
  const cases = [
    {
      name: "prefix-sharing button names",
      html: (a: number, b: number) =>
        withExit(
          `<main id="main"><button tabindex="${a}">Select template</button><button tabindex="${b}">Select</button></main>`,
        ),
      stops: ['button "Select template"', 'button "Select"'],
    },
    {
      name: "focusable text flattened into one line",
      html: (a: number, b: number) =>
        withExit(
          `<main id="main"><p><span tabindex="${a}">alpha</span> and <span tabindex="${b}">beta</span></p></main>`,
        ),
      stops: ["text: alpha", "text: beta"],
    },
  ];

  for (const { name, html, stops } of cases) {
    test(`accepts Tab stops in reading order: ${name}`, async ({ page }) => {
      await page.setContent(html(0, 0));
      expect(await expectTabOrderFollowsReadingOrder(page, name)).toEqual(stops);
    });

    test(`rejects reversed Tab stops: ${name}`, async ({ page }) => {
      await page.setContent(html(2, 1));
      await expect(expectTabOrderFollowsReadingOrder(page, name)).rejects.toThrow(
        `Tab stop #2 (${stops[0]}) comes before`,
      );
    });
  }
});

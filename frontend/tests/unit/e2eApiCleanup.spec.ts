/**
 * Tests for Playwright API cleanup helpers.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Page } from "@playwright/test";
import { APICleanupHelper } from "../e2e/helpers/api-cleanup";

describe("APICleanupHelper", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("withdraws sessions without sending a request body", async () => {
    const helper = new APICleanupHelper(createPage());

    await expect(helper.withdrawSession("session/name")).resolves.toBe(true);

    expect(fetch).toHaveBeenCalledWith("/api/breakglassSessions/session%2Fname/withdraw", {
      method: "POST",
      headers: {
        Authorization: "Bearer test-token",
      },
    });
  });

  it("drops sessions without sending a request body", async () => {
    const helper = new APICleanupHelper(createPage());

    await expect(helper.dropSession("session/name")).resolves.toBe(true);

    expect(fetch).toHaveBeenCalledWith("/api/breakglassSessions/session%2Fname/drop", {
      method: "POST",
      headers: {
        Authorization: "Bearer test-token",
      },
    });
  });
});

function createPage(): Page {
  return {
    evaluate: vi.fn(async (callback: (arg: unknown) => unknown, arg?: unknown) => {
      if (arg === undefined) {
        return "test-token";
      }
      return callback(arg);
    }),
  } as unknown as Page;
}

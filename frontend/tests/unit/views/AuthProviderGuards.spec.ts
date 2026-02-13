/**
 * Auth provider guard tests for views that require injected Auth context
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi } from "vitest";
import { mount } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import BreakglassSessionReview from "@/views/BreakglassSessionReview.vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";

vi.mock("@/services/auth", () => ({
  useUser: vi.fn(() => ref(null)),
}));

describe("View auth provider guards", () => {
  it("throws a clear error when BreakglassSessionReview is mounted without auth provider", async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/review", component: BreakglassSessionReview }],
    });

    await router.push("/review");
    await router.isReady();

    expect(() => {
      mount(BreakglassSessionReview, {
        global: {
          plugins: [router],
          stubs: {
            BreakglassSessionCard: true,
            ApprovalModalContent: true,
            "scale-button": true,
            "scale-switch": true,
            "scale-text-field": true,
            "scale-tag": true,
            "scale-modal": true,
          },
        },
      });
    }).toThrow("BreakglassSessionReview requires an Auth provider");
  });

  it("throws a clear error when PendingApprovalsView is mounted without auth provider", () => {
    expect(() => {
      mount(PendingApprovalsView, {
        global: {
          stubs: {
            PageHeader: true,
            EmptyState: true,
            LoadingState: true,
            StatusTag: true,
            ReasonPanel: true,
            ActionButton: true,
            CountdownTimer: true,
            SessionSummaryCard: true,
            SessionMetaGrid: true,
            ApprovalModalContent: true,
            "scale-dropdown-select": true,
            "scale-dropdown-select-option": true,
            "scale-modal": true,
            "scale-tag": true,
          },
        },
      });
    }).toThrow("PendingApprovalsView requires an Auth provider");
  });
});

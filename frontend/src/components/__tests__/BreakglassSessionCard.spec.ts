// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for BreakglassSessionCard component
 *
 * Covers rendering, computed properties, action buttons, and event emissions
 * for all session states (Pending, Approved, Rejected, Withdrawn, Expired,
 * ApprovalTimeout, WaitingForScheduledTime, IdleExpired).
 *
 */
import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import BreakglassSessionCard from "../BreakglassSessionCard.vue";
import type { SessionMetadata, SessionSpec, SessionStatus } from "@/model/breakglass";

// Minimal stub for SessionSummaryCard to avoid full component tree
const SessionSummaryCardStub = {
  name: "SessionSummaryCard",
  template: `<div class="summary-stub">
    <slot name="status" />
    <slot name="chips" />
    <slot name="body" />
    <slot name="timeline" />
    <slot name="footer" />
  </div>`,
  props: ["eyebrow", "title", "subtitle", "statusTone", "dense"],
};

interface SessionOverrides {
  metadata?: Partial<SessionMetadata>;
  spec?: Partial<SessionSpec>;
  status?: Partial<SessionStatus>;
  [key: string]: unknown;
}

function makeSession(overrides: SessionOverrides = {}) {
  return {
    metadata: {
      name: "test-session-001",
      creationTimestamp: "2026-02-20T10:00:00Z",
      ...overrides.metadata,
    },
    spec: {
      user: "alice@example.com",
      grantedGroup: "cluster-admin",
      cluster: "prod-cluster",
      identityProviderName: "Keycloak",
      requestReason: "Investigating production outage",
      ...overrides.spec,
    },
    status: {
      state: "Approved",
      approvedAt: "2026-02-20T10:05:00Z",
      expiresAt: new Date(Date.now() + 3600000).toISOString(), // 1h in future
      retainedUntil: new Date(Date.now() + 86400000).toISOString(), // 1d in future
      rejectedAt: undefined,
      withdrawnAt: undefined,
      ...overrides.status,
    },
  };
}

function mountCard(sessionOverrides: SessionOverrides = {}, props: Record<string, unknown> = {}) {
  return mount(BreakglassSessionCard, {
    props: {
      breakglass: makeSession(sessionOverrides),
      time: Date.now(),
      currentUserEmail: "alice@example.com",
      ...props,
    },
    global: {
      stubs: {
        SessionSummaryCard: SessionSummaryCardStub,
        "scale-tag": {
          template: '<span class="scale-tag-stub"><slot /></span>',
          props: ["variant", "size"],
        },
        "scale-button": {
          template: '<button class="scale-button-stub" @click="$emit(\'click\')"><slot /></button>',
          props: ["variant"],
        },
      },
    },
  });
}

describe("BreakglassSessionCard", () => {
  describe("rendering", () => {
    it("renders the session card", () => {
      const wrapper = mountCard();
      expect(wrapper.find(".summary-stub").exists()).toBe(true);
    });

    it("displays session state in status tag", () => {
      const wrapper = mountCard();
      const statusTag = wrapper.find("[data-testid='session-status']");
      expect(statusTag.exists()).toBe(true);
      expect(statusTag.text()).toBe("Approved");
    });

    it("displays user and IDP chips", () => {
      const wrapper = mountCard();
      const html = wrapper.html();
      expect(html).toContain("alice@example.com");
      expect(html).toContain("Keycloak");
    });

    it("displays session name chip", () => {
      const wrapper = mountCard();
      const html = wrapper.html();
      expect(html).toContain("test-session-001");
    });

    it("displays request reason when provided", () => {
      const wrapper = mountCard();
      expect(wrapper.text()).toContain("Investigating production outage");
    });

    it("does not display request reason when empty", () => {
      const wrapper = mountCard({ spec: { requestReason: "" } });
      expect(wrapper.find(".session-card__reason").exists()).toBe(false);
    });
  });

  describe("timeline rendering", () => {
    it("shows requested timestamp", () => {
      const wrapper = mountCard();
      const timeline = wrapper.find("[data-testid='timeline-requested']");
      expect(timeline.exists()).toBe(true);
    });

    it("shows approved timestamp for approved sessions", () => {
      const wrapper = mountCard();
      const timeline = wrapper.find("[data-testid='timeline-approved']");
      expect(timeline.exists()).toBe(true);
    });

    it("shows rejected timestamp for rejected sessions", () => {
      const wrapper = mountCard({
        status: {
          state: "Rejected",
          rejectedAt: "2026-02-20T10:10:00Z",
        },
      });
      const timeline = wrapper.find("[data-testid='timeline-rejected']");
      expect(timeline.exists()).toBe(true);
    });

    it("shows withdrawn timestamp for withdrawn sessions", () => {
      const wrapper = mountCard({
        status: {
          state: "Withdrawn",
          withdrawnAt: "2026-02-20T10:10:00Z",
        },
      });
      const timeline = wrapper.find("[data-testid='timeline-withdrawn']");
      expect(timeline.exists()).toBe(true);
    });

    it("shows status line in timeline", () => {
      const wrapper = mountCard();
      const timeline = wrapper.find("[data-testid='timeline-status']");
      expect(timeline.exists()).toBe(true);
    });
  });

  describe("session states", () => {
    it("pending session shows review button", () => {
      const wrapper = mountCard({
        status: {
          state: "Pending",
          approvedAt: undefined,
          expiresAt: undefined,
          retainedUntil: new Date(Date.now() + 86400000).toISOString(),
        },
      });
      const reviewBtn = wrapper.find("[data-testid='review-button']");
      expect(reviewBtn.exists()).toBe(true);
    });

    it("approved session shows drop button for session owner", () => {
      const wrapper = mountCard(
        {
          status: {
            state: "Approved",
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            retainedUntil: new Date(Date.now() + 86400000).toISOString(),
          },
        },
        { currentUserEmail: "alice@example.com" },
      );
      const dropBtn = wrapper.find("[data-testid='drop-button']");
      expect(dropBtn.exists()).toBe(true);
    });

    it("approved session shows cancel button for non-owner", () => {
      const wrapper = mountCard(
        {
          status: {
            state: "Approved",
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            retainedUntil: new Date(Date.now() + 86400000).toISOString(),
          },
        },
        { currentUserEmail: "bob@example.com" },
      );
      const cancelBtn = wrapper.find("[data-testid='cancel-button']");
      expect(cancelBtn.exists()).toBe(true);
    });

    it("rejected session has no action buttons", () => {
      const wrapper = mountCard({
        status: {
          state: "Rejected",
          rejectedAt: "2026-02-20T10:10:00Z",
        },
      });
      expect(wrapper.find("[data-testid='session-actions']").exists()).toBe(false);
    });

    it("expired session has no action buttons", () => {
      const wrapper = mountCard({
        status: {
          state: "Expired",
          expiresAt: "2026-02-20T09:00:00Z",
        },
      });
      expect(wrapper.find("[data-testid='session-actions']").exists()).toBe(false);
    });

    it("withdrawn session has no action buttons", () => {
      const wrapper = mountCard({
        status: {
          state: "Withdrawn",
          withdrawnAt: "2026-02-20T10:10:00Z",
        },
      });
      expect(wrapper.find("[data-testid='session-actions']").exists()).toBe(false);
    });

    it("ApprovalTimeout session has no action buttons", () => {
      const wrapper = mountCard({
        status: {
          state: "ApprovalTimeout",
        },
      });
      expect(wrapper.find("[data-testid='session-actions']").exists()).toBe(false);
    });

    it("WaitingForScheduledTime session shows review button", () => {
      const wrapper = mountCard({
        status: {
          state: "WaitingForScheduledTime",
          approvedAt: undefined,
          expiresAt: undefined,
          retainedUntil: new Date(Date.now() + 86400000).toISOString(),
        },
      });
      const reviewBtn = wrapper.find("[data-testid='review-button']");
      expect(reviewBtn.exists()).toBe(true);
    });
  });

  describe("events", () => {
    it("emits 'review' when review button is clicked", async () => {
      const wrapper = mountCard({
        status: {
          state: "Pending",
          approvedAt: undefined,
          expiresAt: undefined,
          retainedUntil: new Date(Date.now() + 86400000).toISOString(),
        },
      });
      await wrapper.find("[data-testid='review-button']").trigger("click");
      expect(wrapper.emitted("review")).toBeTruthy();
      expect(wrapper.emitted("review")!.length).toBe(1);
    });

    it("emits 'drop' when owner clicks drop button on active session", async () => {
      const wrapper = mountCard(
        {
          status: {
            state: "Approved",
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            retainedUntil: new Date(Date.now() + 86400000).toISOString(),
          },
        },
        { currentUserEmail: "alice@example.com" },
      );
      const dropBtn = wrapper.find("[data-testid='drop-button']");
      await dropBtn.trigger("click");
      expect(wrapper.emitted("drop")).toBeTruthy();
    });

    it("emits 'cancel' when non-owner clicks cancel on active session", async () => {
      const wrapper = mountCard(
        {
          status: {
            state: "Approved",
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            retainedUntil: new Date(Date.now() + 86400000).toISOString(),
          },
        },
        { currentUserEmail: "bob@example.com" },
      );
      const cancelBtn = wrapper.find("[data-testid='cancel-button']");
      await cancelBtn.trigger("click");
      expect(wrapper.emitted("cancel")).toBeTruthy();
    });
  });

  describe("edge cases", () => {
    it("handles missing spec fields gracefully", () => {
      const wrapper = mountCard({
        spec: {
          user: undefined,
          grantedGroup: undefined,
          cluster: undefined,
          identityProviderName: undefined,
        },
      });
      expect(wrapper.exists()).toBe(true);
    });

    it("handles unknown state gracefully", () => {
      const wrapper = mountCard({
        status: { state: "SomeUnknownState" },
      });
      const statusTag = wrapper.find("[data-testid='session-status']");
      expect(statusTag.text()).toBe("SomeUnknownState");
    });

    it("handles null state gracefully", () => {
      const wrapper = mountCard({
        status: { state: undefined },
      });
      const statusTag = wrapper.find("[data-testid='session-status']");
      // Should show "Unknown" as fallback
      expect(statusTag.text()).toContain("Unknown");
    });

    it("renders IdleExpired state correctly", () => {
      const wrapper = mountCard({
        status: { state: "IdleExpired" },
      });
      const statusTag = wrapper.find("[data-testid='session-status']");
      expect(statusTag.text()).toBe("IdleExpired");
    });

    it("renders WaitingForScheduledTime state correctly", () => {
      const wrapper = mountCard({
        status: { state: "WaitingForScheduledTime" },
      });
      const statusTag = wrapper.find("[data-testid='session-status']");
      expect(statusTag.text()).toBe("WaitingForScheduledTime");
    });
  });
});

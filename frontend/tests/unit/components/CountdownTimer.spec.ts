/**
 * Tests for CountdownTimer component
 *
 * Covers:
 * - Countdown display formatting (Xm Ys, Xs)
 * - Expired state rendering
 * - Interval setup/cleanup
 * - Reactive prop changes
 *
 * NOTE: Vue reactive DOM updates are async. After mount() we must
 * await nextTick() so that the template reflects the reactive state
 * set by onMounted().
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { mount, VueWrapper } from "@vue/test-utils";
import { nextTick } from "vue";
import CountdownTimer from "@/components/CountdownTimer.vue";

// Mock dateTime utilities
vi.mock("@/utils/dateTime", () => ({
  format24Hour: vi.fn((iso: string) => {
    const d = new Date(iso);
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  }),
  debugLogDateTime: vi.fn(),
}));

describe("CountdownTimer", () => {
  let wrapper: VueWrapper | null = null;

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.useRealTimers();
  });

  /**
   * Mount the timer with fake clock pinned to `baseTime`.
   * Awaits nextTick so DOM reflects the updated reactive state.
   */
  async function mountAt(baseTime: Date, expiresAt: string | Date): Promise<VueWrapper> {
    vi.useFakeTimers({ now: baseTime });
    wrapper = mount(CountdownTimer, { props: { expiresAt } });
    await nextTick();
    return wrapper;
  }

  describe("when time remains", () => {
    it("displays minutes and seconds when > 60s remain", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 5 * 60_000 + 30_000).toISOString();
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("5m 30s");
    });

    it("displays only seconds when < 60s remain", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 45_000).toISOString();
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("45s");
      expect(w.text()).not.toContain("m");
    });

    it("updates countdown every second", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 60_000).toISOString();
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("1m 0s");

      vi.advanceTimersByTime(10_000);
      await nextTick();
      expect(w.text()).toContain("50s");
    });

    it("does not have expired class", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();
      const w = await mountAt(now, expiresAt);
      const el = w.find("[data-testid='countdown-timer']");
      expect(el.classes()).not.toContain("expired");
    });
  });

  describe("when expired", () => {
    it("displays 'Expired' when past expiry", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() - 10 * 60_000).toISOString();
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("Expired");
    });

    it("has expired class", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() - 10 * 60_000).toISOString();
      const w = await mountAt(now, expiresAt);
      const el = w.find("[data-testid='countdown-timer']");
      expect(el.classes()).toContain("expired");
    });

    it("transitions to expired when timer runs out", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 3_000).toISOString();
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("3s");

      vi.advanceTimersByTime(4_000);
      await nextTick();
      expect(w.text()).toContain("Expired");
    });
  });

  describe("title attribute", () => {
    it("shows full formatted time as title", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();
      const w = await mountAt(now, expiresAt);
      const el = w.find("[data-testid='countdown-timer']");
      expect(el.attributes("title")).toBeTruthy();
    });
  });

  describe("prop reactivity", () => {
    it("recalculates when expiresAt changes", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 60_000).toISOString());
      expect(w.text()).toContain("1m 0s");

      await w.setProps({ expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString() });
      await nextTick();
      expect(w.text()).toContain("5m 0s");
    });

    it("accepts Date objects as props", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const expiresAt = new Date(now.getTime() + 2 * 60_000);
      const w = await mountAt(now, expiresAt);
      expect(w.text()).toContain("2m 0s");
    });
  });

  describe("lifecycle", () => {
    it("clears interval on unmount", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      vi.useFakeTimers({ now });
      const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");
      wrapper = mount(CountdownTimer, {
        props: { expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString() },
      });
      await nextTick();

      wrapper.unmount();
      wrapper = null;
      expect(clearIntervalSpy).toHaveBeenCalled();
      clearIntervalSpy.mockRestore();
    });
  });
});

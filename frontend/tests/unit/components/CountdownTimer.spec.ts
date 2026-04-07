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

  describe("screen-reader announcements", () => {
    it("renders a polite live region", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 90_000).toISOString());
      const liveRegion = w.find('[aria-live="polite"]');

      expect(liveRegion.exists()).toBe(true);
    });

    it("announces one minute remaining at 60 seconds", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 60_000).toISOString());

      expect(w.find(".sr-only").text()).toBe("1 minute remaining");
    });

    it("announces 30 seconds remaining at 30 seconds", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 30_000).toISOString());

      expect(w.find(".sr-only").text()).toBe("30 seconds remaining");
    });

    it("announces each second from 10 seconds remaining to expiry", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 10_000).toISOString());
      const srOnly = () => w.find(".sr-only");

      expect(srOnly().text()).toBe("10 seconds remaining");

      for (let secondsRemaining = 9; secondsRemaining >= 1; secondsRemaining -= 1) {
        vi.advanceTimersByTime(1_000);
        await nextTick();
        expect(srOnly().text()).toBe(`${secondsRemaining} ${secondsRemaining === 1 ? "second" : "seconds"} remaining`);
      }
    });

    it("announces timer expired when the countdown reaches zero", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 1_000).toISOString());

      vi.advanceTimersByTime(1_000);
      await nextTick();

      expect(w.find(".sr-only").text()).toBe("Timer expired");
    });

    it("announces timer expired when expiresAt changes to a past value", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 5 * 60_000).toISOString());

      await w.setProps({ expiresAt: new Date(now.getTime() - 1_000).toISOString() });
      await nextTick();

      expect(w.find(".sr-only").text()).toBe("Timer expired");
    });

    it("announces timer expired on mount when expiresAt is already in the past", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() - 5_000).toISOString());

      expect(w.find(".sr-only").text()).toBe("Timer expired");
    });

    it("clears stale announcement text when expiresAt changes to a new value", async () => {
      const now = new Date("2030-06-15T12:00:00Z");
      const w = await mountAt(now, new Date(now.getTime() + 60_000).toISOString());

      expect(w.find(".sr-only").text()).toBe("1 minute remaining");

      await w.setProps({ expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString() });
      await nextTick();

      expect(w.find(".sr-only").text()).toBe("");
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

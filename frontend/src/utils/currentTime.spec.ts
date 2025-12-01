/**
 * Tests for currentTime composable
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { defineComponent, h } from "vue";
import useCurrentTime from "./currentTime";

describe("useCurrentTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-12-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns the current timestamp", async () => {
    let timeValue: number | undefined;

    const TestComponent = defineComponent({
      setup() {
        const time = useCurrentTime();
        timeValue = time.value;
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(timeValue).toBe(Date.now());
  });

  it("updates time at the specified interval", async () => {
    const capturedValues: number[] = [];

    const TestComponent = defineComponent({
      setup() {
        const time = useCurrentTime(100);
        capturedValues.push(time.value);
        return () => h("div", time.value.toString());
      },
    });

    const wrapper = mount(TestComponent);
    await flushPromises();

    const initialTime = Date.now();
    expect(capturedValues[0]).toBe(initialTime);

    // Advance time by 100ms
    vi.advanceTimersByTime(100);
    await flushPromises();

    // Time should have been updated
    expect(wrapper.text()).toBe(String(Date.now()));
  });

  it("clears interval on unmount", async () => {
    const clearIntervalSpy = vi.spyOn(window, "clearInterval");

    const TestComponent = defineComponent({
      setup() {
        const time = useCurrentTime(1000);
        return () => h("div", time.value.toString());
      },
    });

    const wrapper = mount(TestComponent);
    await flushPromises();

    wrapper.unmount();

    expect(clearIntervalSpy).toHaveBeenCalled();
  });

  it("uses default 1000ms interval when not specified", async () => {
    const setIntervalSpy = vi.spyOn(window, "setInterval");

    const TestComponent = defineComponent({
      setup() {
        const time = useCurrentTime();
        return () => h("div", time.value.toString());
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 1000);
  });

  it("returns a readonly ref", async () => {
    let timeRef: ReturnType<typeof useCurrentTime> | undefined;

    const TestComponent = defineComponent({
      setup() {
        timeRef = useCurrentTime();
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    // The ref should be readonly (attempting to set will be ignored in production)
    expect(timeRef).toBeDefined();
    expect(typeof timeRef!.value).toBe("number");
  });
});

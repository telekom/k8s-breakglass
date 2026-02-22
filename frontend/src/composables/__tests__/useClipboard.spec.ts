// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useClipboard } from "@/composables/useClipboard";

describe("useClipboard", () => {
  let originalClipboard: Clipboard;

  beforeEach(() => {
    vi.useFakeTimers();
    originalClipboard = navigator.clipboard;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    Object.defineProperty(navigator, "clipboard", {
      value: originalClipboard,
      writable: true,
      configurable: true,
    });
  });

  it("copies text using the Clipboard API", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, copied, error } = useClipboard();
    const result = await copy("hello");

    expect(result).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
    expect(copied.value).toBe(true);
    expect(error.value).toBeNull();
  });

  it("resets copied after the default delay", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, copied } = useClipboard();
    await copy("hello");

    expect(copied.value).toBe(true);

    vi.advanceTimersByTime(2000);
    expect(copied.value).toBe(false);
  });

  it("respects custom reset delay", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, copied } = useClipboard(500);
    await copy("hello");

    expect(copied.value).toBe(true);

    vi.advanceTimersByTime(499);
    expect(copied.value).toBe(true);

    vi.advanceTimersByTime(1);
    expect(copied.value).toBe(false);
  });

  it("falls back to textarea copy when Clipboard API is unavailable", async () => {
    // Remove Clipboard API
    Object.defineProperty(navigator, "clipboard", { value: undefined, writable: true, configurable: true });

    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    const appendSpy = vi.spyOn(document.body, "appendChild");
    const removeSpy = vi.spyOn(document.body, "removeChild");

    const { copy, copied } = useClipboard();
    const result = await copy("fallback text");

    expect(result).toBe(true);
    expect(copied.value).toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(appendSpy).toHaveBeenCalled();
    expect(removeSpy).toHaveBeenCalled();
  });

  it("reports error when fallback execCommand fails", async () => {
    Object.defineProperty(navigator, "clipboard", { value: undefined, writable: true, configurable: true });

    const execCommand = vi.fn().mockReturnValue(false);
    document.execCommand = execCommand;

    const { copy, copied, error } = useClipboard();
    const result = await copy("fail fallback");

    expect(result).toBe(false);
    expect(copied.value).toBe(false);
    expect(error.value).toBe("execCommand copy failed");
  });

  it("falls back to textarea when writeText rejects", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("Permission denied"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, copied, error } = useClipboard();
    const result = await copy("fail");

    // writeText rejected, fallback tried, execCommand unavailable in jsdom
    expect(result).toBe(false);
    expect(copied.value).toBe(false);
    expect(error.value).toBe("execCommand copy failed");
  });

  it("falls back to textarea on non-Error writeText rejection", async () => {
    const writeText = vi.fn().mockRejectedValue("string error");
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, error } = useClipboard();
    await copy("fail");

    // writeText rejected, fallback tried, execCommand unavailable in jsdom
    expect(error.value).toBe("execCommand copy failed");
  });

  it("clears previous timer on rapid successive copies", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, writable: true, configurable: true });

    const { copy, copied } = useClipboard(1000);

    await copy("first");
    expect(copied.value).toBe(true);

    vi.advanceTimersByTime(800);
    await copy("second");
    expect(copied.value).toBe(true);

    // The first timer (1000ms from first copy) should NOT trigger reset
    vi.advanceTimersByTime(200);
    expect(copied.value).toBe(true);

    // The second timer fires at 800 + 200 + 800 = 1800ms total (1000ms from second copy)
    vi.advanceTimersByTime(800);
    expect(copied.value).toBe(false);
  });
});

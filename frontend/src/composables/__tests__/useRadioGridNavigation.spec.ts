// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { useRadioGridNavigation } from "../useRadioGridNavigation";

/**
 * Creates a mock radiogroup container with radio items for testing.
 */
function createRadioGroup(count: number): { group: HTMLElement; items: HTMLElement[] } {
  const group = document.createElement("div");
  group.setAttribute("role", "radiogroup");
  const items: HTMLElement[] = [];
  for (let i = 0; i < count; i++) {
    const item = document.createElement("div");
    item.setAttribute("role", "radio");
    item.setAttribute("data-index", String(i));
    item.focus = vi.fn();
    item.click = vi.fn();
    group.appendChild(item);
    items.push(item);
  }
  return { group, items };
}

function createKeyboardEvent(group: HTMLElement, target: HTMLElement): KeyboardEvent {
  const event = new KeyboardEvent("keydown");
  Object.defineProperty(event, "currentTarget", { value: group });
  Object.defineProperty(event, "target", { value: target });
  return event;
}

describe("useRadioGridNavigation", () => {
  it("returns focusNextRadio and focusPrevRadio functions", () => {
    const { focusNextRadio, focusPrevRadio } = useRadioGridNavigation();
    expect(typeof focusNextRadio).toBe("function");
    expect(typeof focusPrevRadio).toBe("function");
  });

  describe("focusNextRadio", () => {
    it("focuses and clicks the next radio item", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const event = createKeyboardEvent(group, items[0]!);

      focusNextRadio(event);

      expect(items[1]!.focus).toHaveBeenCalled();
      expect(items[1]!.click).toHaveBeenCalled();
    });

    it("wraps to the first item when at the last item", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const event = createKeyboardEvent(group, items[2]!);

      focusNextRadio(event);

      expect(items[0]!.focus).toHaveBeenCalled();
      expect(items[0]!.click).toHaveBeenCalled();
    });

    it("does nothing when group has no radio items", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const group = document.createElement("div");
      const target = document.createElement("div");
      group.appendChild(target);
      const event = createKeyboardEvent(group, target);

      // Should not throw
      focusNextRadio(event);
    });

    it("does nothing when target is not inside a radio item", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const outsideTarget = document.createElement("span");
      group.appendChild(outsideTarget);
      const event = createKeyboardEvent(group, outsideTarget);

      focusNextRadio(event);

      // None of the radio items should have been focused
      for (const item of items) {
        expect(item.focus).not.toHaveBeenCalled();
      }
    });

    it("does nothing when currentTarget is null", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const event = new KeyboardEvent("keydown");
      Object.defineProperty(event, "currentTarget", { value: null });

      // Should not throw
      focusNextRadio(event);
    });
  });

  describe("focusPrevRadio", () => {
    it("focuses and clicks the previous radio item", () => {
      const { focusPrevRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const event = createKeyboardEvent(group, items[2]!);

      focusPrevRadio(event);

      expect(items[1]!.focus).toHaveBeenCalled();
      expect(items[1]!.click).toHaveBeenCalled();
    });

    it("wraps to the last item when at the first item", () => {
      const { focusPrevRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const event = createKeyboardEvent(group, items[0]!);

      focusPrevRadio(event);

      expect(items[2]!.focus).toHaveBeenCalled();
      expect(items[2]!.click).toHaveBeenCalled();
    });

    it("does nothing when group has no radio items", () => {
      const { focusPrevRadio } = useRadioGridNavigation();
      const group = document.createElement("div");
      const target = document.createElement("div");
      group.appendChild(target);
      const event = createKeyboardEvent(group, target);

      // Should not throw
      focusPrevRadio(event);
    });

    it("does nothing when target is not inside a radio item", () => {
      const { focusPrevRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(3);
      const outsideTarget = document.createElement("span");
      group.appendChild(outsideTarget);
      const event = createKeyboardEvent(group, outsideTarget);

      focusPrevRadio(event);

      for (const item of items) {
        expect(item.focus).not.toHaveBeenCalled();
      }
    });
  });

  describe("single-item group", () => {
    it("focusNextRadio wraps to itself", () => {
      const { focusNextRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(1);
      const event = createKeyboardEvent(group, items[0]!);

      focusNextRadio(event);

      expect(items[0]!.focus).toHaveBeenCalled();
      expect(items[0]!.click).toHaveBeenCalled();
    });

    it("focusPrevRadio wraps to itself", () => {
      const { focusPrevRadio } = useRadioGridNavigation();
      const { group, items } = createRadioGroup(1);
      const event = createKeyboardEvent(group, items[0]!);

      focusPrevRadio(event);

      expect(items[0]!.focus).toHaveBeenCalled();
      expect(items[0]!.click).toHaveBeenCalled();
    });
  });
});

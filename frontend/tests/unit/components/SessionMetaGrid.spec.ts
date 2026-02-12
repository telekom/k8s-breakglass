/**
 * Tests for SessionMetaGrid component
 *
 * Covers:
 * - Grid rendering with items
 * - Value formatting (null, undefined, empty string → dash)
 * - Mono styling
 * - Hint tooltips
 * - Custom item slot
 * - Accessibility (role=table, role=row, role=rowheader, role=cell)
 * - data-testid attributes
 */

import { describe, it, expect, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import SessionMetaGrid from "@/components/SessionMetaGrid.vue";

// Note: Scale web components (scale-tooltip, scale-icon-action-info)
// are registered globally in tests/setup.ts

type MetaItem = {
  id: string;
  label: string;
  value?: string | number | null;
  mono?: boolean;
  hint?: string;
};

describe("SessionMetaGrid", () => {
  let activeWrapper: ReturnType<typeof mount> | null = null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function mountGrid(items: MetaItem[], slots: any = {}) {
    const wrapper = mount(SessionMetaGrid, { props: { items }, slots });
    activeWrapper = wrapper;
    return wrapper;
  }

  afterEach(() => {
    activeWrapper?.unmount();
    activeWrapper = null;
  });

  const sampleItems: MetaItem[] = [
    { id: "cluster", label: "Cluster", value: "prod-eu-01" },
    { id: "user", label: "User", value: "admin@example.com", mono: true },
    { id: "group", label: "Group", value: "cluster-admin" },
  ];

  describe("rendering", () => {
    it("renders a row for each item", () => {
      const wrapper = mountGrid(sampleItems);
      const rows = wrapper.findAll("[role='row']");
      expect(rows).toHaveLength(3);
    });

    it("displays labels and values", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.text()).toContain("Cluster");
      expect(wrapper.text()).toContain("prod-eu-01");
      expect(wrapper.text()).toContain("User");
      expect(wrapper.text()).toContain("admin@example.com");
    });

    it("has data-testid on the grid", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.find("[data-testid='session-meta-grid']").exists()).toBe(true);
    });

    it("has data-testid on each row", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.find("[data-testid='meta-row-cluster']").exists()).toBe(true);
      expect(wrapper.find("[data-testid='meta-row-user']").exists()).toBe(true);
    });

    it("has data-testid on each value cell", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.find("[data-testid='meta-value-cluster']").exists()).toBe(true);
    });
  });

  describe("value formatting", () => {
    it("shows dash for null values", () => {
      const wrapper = mountGrid([{ id: "test", label: "Test", value: null }]);
      const value = wrapper.find("[data-testid='meta-value-test']");
      expect(value.text()).toBe("—");
    });

    it("shows dash for undefined values", () => {
      const wrapper = mountGrid([{ id: "test", label: "Test" }]);
      const value = wrapper.find("[data-testid='meta-value-test']");
      expect(value.text()).toBe("—");
    });

    it("shows dash for empty string values", () => {
      const wrapper = mountGrid([{ id: "test", label: "Test", value: "" }]);
      const value = wrapper.find("[data-testid='meta-value-test']");
      expect(value.text()).toBe("—");
    });

    it("shows numeric values", () => {
      const wrapper = mountGrid([{ id: "count", label: "Count", value: 42 }]);
      expect(wrapper.text()).toContain("42");
    });
  });

  describe("mono styling", () => {
    it("applies mono class when item.mono is true", () => {
      const wrapper = mountGrid([{ id: "hash", label: "Hash", value: "abc123", mono: true }]);
      const value = wrapper.find("[data-testid='meta-value-hash']");
      expect(value.find(".mono").exists()).toBe(true);
    });

    it("does not apply mono class when mono is false or absent", () => {
      const wrapper = mountGrid([{ id: "name", label: "Name", value: "John" }]);
      const value = wrapper.find("[data-testid='meta-value-name']");
      expect(value.find(".mono").exists()).toBe(false);
    });
  });

  describe("hint tooltips", () => {
    it("renders tooltip when item has a hint", () => {
      const wrapper = mountGrid([{ id: "field", label: "Field", value: "val", hint: "Extra info" }]);
      expect(wrapper.find("scale-tooltip").exists()).toBe(true);
    });

    it("does not render tooltip when item has no hint", () => {
      const wrapper = mountGrid([{ id: "field", label: "Field", value: "val" }]);
      expect(wrapper.find("scale-tooltip").exists()).toBe(false);
    });

    it("hint button has accessible aria-label", () => {
      const wrapper = mountGrid([{ id: "field", label: "My Field", value: "val", hint: "More info" }]);
      const btn = wrapper.find(".meta-label__hint");
      expect(btn.attributes("aria-label")).toBe("More info about My Field");
    });
  });

  describe("accessibility roles", () => {
    it("has role=table on the grid container", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.find("[role='table']").exists()).toBe(true);
    });

    it("has role=rowgroup wrapping rows", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.find("[role='rowgroup']").exists()).toBe(true);
    });

    it("has role=row on each item row", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.findAll("[role='row']")).toHaveLength(3);
    });

    it("has role=rowheader on label cells", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.findAll("[role='rowheader']")).toHaveLength(3);
    });

    it("has role=cell on value cells", () => {
      const wrapper = mountGrid(sampleItems);
      expect(wrapper.findAll("[role='cell']")).toHaveLength(3);
    });
  });

  describe("custom item slot", () => {
    it("renders custom slot content instead of default value", () => {
      const wrapper = mount(SessionMetaGrid, {
        props: {
          items: [{ id: "custom", label: "Custom", value: "original" }],
        },
        slots: {
          item: '<template #item="{ item }"><strong>{{ item.label }}: custom render</strong></template>',
        },
      });
      expect(wrapper.text()).toContain("custom render");
    });
  });
});

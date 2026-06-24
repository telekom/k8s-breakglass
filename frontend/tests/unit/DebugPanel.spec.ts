/**
 * Tests for DebugPanel component utility functions
 *
 * This test suite covers DebugPanel-related utility logic:
 * - Group extraction from JWT claims
 * - Debug information collection
 * - Token summary display
 *
 * @vitest-environment jsdom
 */

import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import DebugPanel from "@/components/DebugPanel.vue";
import { AuthKey } from "@/keys";
import { useUser } from "@/services/auth";

let wrapper: VueWrapper | null = null;

function mountDebugPanel() {
  return mount(DebugPanel, {
    global: {
      provide: {
        [AuthKey as symbol]: {
          getAccessToken: vi.fn().mockResolvedValue(""),
        },
      },
      stubs: {
        "scale-card": { template: "<div><slot /></div>" },
        "scale-button": { template: '<button v-bind="$attrs"><slot /></button>' },
        "scale-icon-action-circle-close": true,
        "scale-icon-action-success": true,
        "scale-icon-service-settings": true,
      },
    },
  });
}

async function flushMutationObserver() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function appendOpenModal() {
  const modal = document.createElement("scale-modal");
  modal.setAttribute("opened", "");
  document.body.appendChild(modal);
  return modal;
}

function appendClosedModal() {
  const modal = document.createElement("scale-modal");
  modal.setAttribute("opened", "false");
  document.body.appendChild(modal);
  return modal;
}

beforeEach(() => {
  document.querySelectorAll("scale-modal").forEach((modal) => modal.remove());
  useUser().value = undefined;
});

afterEach(() => {
  wrapper?.unmount();
  wrapper = null;
  document.querySelectorAll("scale-modal").forEach((modal) => modal.remove());
  useUser().value = undefined;
  vi.restoreAllMocks();
});

describe("DebugPanel Utilities", () => {
  /**
   * Utility function that extracts groups from JWT claims
   * Matches the implementation in DebugPanel.vue
   */
  function extractGroups(claims: Record<string, unknown> | null): string[] {
    if (!claims) return [];
    const groups: Set<string> = new Set();
    if (Array.isArray(claims.groups)) {
      claims.groups.forEach((g: string) => groups.add(g));
    }
    if (claims.group) {
      if (typeof claims.group === "string") groups.add(claims.group);
      if (Array.isArray(claims.group)) claims.group.forEach((g: string) => groups.add(g));
    }
    const realmAccess = claims.realm_access as Record<string, unknown> | undefined;
    if (realmAccess?.roles && Array.isArray(realmAccess.roles)) {
      realmAccess.roles.forEach((r: string) => groups.add(r));
    }
    return Array.from(groups);
  }

  describe("extractGroups()", () => {
    it("returns empty array for null claims", () => {
      expect(extractGroups(null)).toEqual([]);
    });

    it("returns empty array for undefined claims", () => {
      expect(extractGroups(undefined as unknown as Record<string, unknown> | null)).toEqual([]);
    });

    it("extracts groups from groups array", () => {
      const claims = { groups: ["admin", "viewer", "editor"] };
      expect(extractGroups(claims)).toEqual(["admin", "viewer", "editor"]);
    });

    it("extracts single group from group string", () => {
      const claims = { group: "admin" };
      expect(extractGroups(claims)).toEqual(["admin"]);
    });

    it("extracts groups from group array", () => {
      const claims = { group: ["admin", "viewer"] };
      expect(extractGroups(claims)).toEqual(["admin", "viewer"]);
    });

    it("extracts roles from realm_access.roles", () => {
      const claims = {
        realm_access: { roles: ["breakglass-viewer", "breakglass-admin"] },
      };
      expect(extractGroups(claims)).toEqual(["breakglass-viewer", "breakglass-admin"]);
    });

    it("combines groups from multiple sources without duplicates", () => {
      const claims = {
        groups: ["admin", "viewer"],
        group: "admin", // duplicate
        realm_access: { roles: ["viewer", "new-role"] }, // one duplicate
      };
      const groups = extractGroups(claims);
      expect(groups).toHaveLength(3);
      expect(groups).toContain("admin");
      expect(groups).toContain("viewer");
      expect(groups).toContain("new-role");
    });

    it("handles empty groups array", () => {
      const claims = { groups: [] };
      expect(extractGroups(claims)).toEqual([]);
    });

    it("handles missing realm_access.roles gracefully", () => {
      const claims = { realm_access: {} };
      expect(extractGroups(claims)).toEqual([]);
    });

    it("handles missing realm_access gracefully", () => {
      const claims = { sub: "user" };
      expect(extractGroups(claims)).toEqual([]);
    });
  });

  describe("Token Summary Generation", () => {
    /**
     * Generates a summary string from access token claims
     * Matches the tokenSummary computed property in DebugPanel.vue
     */
    function getTokenSummary(claims: Record<string, unknown> | null): string {
      if (!claims) return "No access token";
      return `sub: ${claims.sub}, preferred_username: ${claims.preferred_username}, email: ${claims.email}`;
    }

    it("returns 'No access token' when claims are null", () => {
      expect(getTokenSummary(null)).toBe("No access token");
    });

    it("generates summary from JWT claims", () => {
      const claims = {
        sub: "user-123",
        preferred_username: "testuser",
        email: "test@example.com",
      };
      expect(getTokenSummary(claims)).toBe("sub: user-123, preferred_username: testuser, email: test@example.com");
    });

    it("handles undefined fields in claims", () => {
      const claims = { sub: "user-123" };
      expect(getTokenSummary(claims)).toBe("sub: user-123, preferred_username: undefined, email: undefined");
    });
  });

  describe("Groups Display Formatting", () => {
    /**
     * Formats groups array for display
     * Matches the groupsDisplay computed property in DebugPanel.vue
     */
    function formatGroupsDisplay(groups: string[]): string {
      if (groups.length === 0) {
        return "No groups found";
      }
      return groups.join(", ");
    }

    it("returns 'No groups found' for empty array", () => {
      expect(formatGroupsDisplay([])).toBe("No groups found");
    });

    it("joins groups with comma separator", () => {
      expect(formatGroupsDisplay(["admin", "viewer", "editor"])).toBe("admin, viewer, editor");
    });

    it("returns single group without comma", () => {
      expect(formatGroupsDisplay(["admin"])).toBe("admin");
    });
  });
});

describe("DebugPanel modal guard", () => {
  it("keeps the debug toggle enabled when a closed app modal is mounted", async () => {
    appendClosedModal();

    wrapper = mountDebugPanel();
    await flushPromises();

    const toggle = wrapper.get('[data-testid="debug-toggle-button"]');
    expect(toggle.attributes("disabled")).toBeUndefined();
    expect(toggle.attributes("aria-disabled")).toBe("false");

    await toggle.trigger("click");
    await flushPromises();

    expect(wrapper.find('[data-testid="debug-panel"]').exists()).toBe(true);
  });

  it("disables the debug toggle while an app modal is open", async () => {
    appendOpenModal();

    wrapper = mountDebugPanel();
    await flushPromises();

    const toggle = wrapper.get('[data-testid="debug-toggle-button"]');
    expect(toggle.attributes("disabled")).toBeDefined();
    expect(toggle.attributes("aria-disabled")).toBe("true");

    await toggle.trigger("click");

    expect(wrapper.find('[data-testid="debug-panel"]').exists()).toBe(false);
  });

  it("closes the debug panel when an app modal opens later", async () => {
    wrapper = mountDebugPanel();
    await flushPromises();

    await wrapper.get('[data-testid="debug-toggle-button"]').trigger("click");
    await flushPromises();

    expect(wrapper.find('[data-testid="debug-panel"]').exists()).toBe(true);

    appendOpenModal();
    await flushMutationObserver();

    expect(wrapper.find('[data-testid="debug-panel"]').exists()).toBe(false);
    expect(wrapper.get('[data-testid="debug-toggle-button"]').attributes("disabled")).toBeDefined();
  });
});

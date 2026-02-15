/**
 * Tests for AutoLogoutWarning component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { mount, VueWrapper } from "@vue/test-utils";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
import { AuthKey } from "@/keys";

describe("AutoLogoutWarning", () => {
  let wrapper: VueWrapper | null = null;

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.clearAllTimers();
    vi.restoreAllMocks();
  });
  const createMockAuth = () => ({
    logout: vi.fn(),
    userManager: {
      settings: {
        authority: "https://issuer.example.com",
        client_id: "breakglass-ui",
      },
      signinSilent: vi.fn().mockResolvedValue(undefined),
    },
  });

  it("throws a clear error when mounted without auth provider", () => {
    expect(() => {
      mount(AutoLogoutWarning, {
        global: {
          stubs: {
            transition: false,
            "scale-notification": true,
            "scale-button": true,
          },
        },
      });
    }).toThrow("AutoLogoutWarning requires an Auth provider");
  });

  it("mounts successfully when auth provider is present", () => {
    wrapper = mount(AutoLogoutWarning, {
      global: {
        provide: {
          [AuthKey as symbol]: createMockAuth(),
        },
        stubs: {
          transition: false,
          "scale-notification": true,
          "scale-button": true,
        },
      },
    });

    expect(wrapper.exists()).toBe(true);
  });
});

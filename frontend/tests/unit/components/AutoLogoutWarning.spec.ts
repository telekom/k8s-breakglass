/**
 * Tests for AutoLogoutWarning component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { mount, VueWrapper } from "@vue/test-utils";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
import { AuthKey } from "@/keys";

type MockAuth = {
  login: (state?: { path: string; idpName?: string }) => Promise<void>;
  logout: () => void;
  getIdentityProviderName: () => string | undefined;
  userManager: {
    settings: {
      authority: string;
      client_id: string;
    };
  };
};

type AutoLogoutWarningVm = {
  reauthenticate: () => Promise<void>;
};

describe("AutoLogoutWarning", () => {
  let wrapper: VueWrapper | null = null;

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.clearAllTimers();
    vi.restoreAllMocks();
    vi.useRealTimers();
    sessionStorage.clear();
    localStorage.clear();
    window.history.pushState({}, "", "/");
  });

  const mountWithAuth = (auth: MockAuth) =>
    mount(AutoLogoutWarning, {
      global: {
        provide: {
          [AuthKey as symbol]: auth,
        },
        stubs: {
          transition: false,
          "scale-notification": true,
          "scale-button": true,
        },
      },
    });

  const createMockAuth = (overrides: Partial<MockAuth> = {}): MockAuth => ({
    login: vi.fn().mockResolvedValue(undefined),
    logout: vi.fn(),
    getIdentityProviderName: vi.fn(() => undefined),
    userManager: {
      settings: {
        authority: "https://issuer.example.com",
        client_id: "breakglass-ui",
      },
    },
    ...overrides,
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
    wrapper = mountWithAuth(createMockAuth());

    expect(wrapper.exists()).toBe(true);
  });

  it("preserves the active identity provider when reauthenticating", async () => {
    const auth = createMockAuth({
      getIdentityProviderName: vi.fn(() => "corp"),
    });
    window.history.pushState({}, "", "/sessions?cluster=prod#approval");
    wrapper = mountWithAuth(auth);

    await (wrapper.vm as unknown as AutoLogoutWarningVm).reauthenticate();

    expect(auth.login).toHaveBeenCalledWith({
      path: "/sessions?cluster=prod#approval",
      idpName: "corp",
    });
  });

  it("uses the local persisted identity provider when persistent storage is active", async () => {
    const auth = createMockAuth();
    localStorage.setItem("breakglass_oidc_token_persistence", "persistent");
    localStorage.setItem("breakglass_current_idp_name", "corp");
    window.history.pushState({}, "", "/sessions?cluster=prod#approval");
    wrapper = mountWithAuth(auth);

    await (wrapper.vm as unknown as AutoLogoutWarningVm).reauthenticate();

    expect(auth.login).toHaveBeenCalledWith({
      path: "/sessions?cluster=prod#approval",
      idpName: "corp",
    });
  });

  it("ignores stale local persisted identity provider names by default", async () => {
    const auth = createMockAuth();
    localStorage.setItem("breakglass_current_idp_name", "corp");
    window.history.pushState({}, "", "/sessions?cluster=prod#approval");
    wrapper = mountWithAuth(auth);

    await (wrapper.vm as unknown as AutoLogoutWarningVm).reauthenticate();

    expect(auth.login).toHaveBeenCalledWith({
      path: "/sessions?cluster=prod#approval",
    });
  });

  it("falls back to default reauthentication when session storage is unavailable", async () => {
    const auth = createMockAuth();
    const sessionStorageDescriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() {
        throw new Error("storage blocked");
      },
    });

    try {
      wrapper = mountWithAuth(auth);

      await (wrapper.vm as unknown as AutoLogoutWarningVm).reauthenticate();

      expect(auth.login).toHaveBeenCalledWith({
        path: "/",
      });
    } finally {
      if (sessionStorageDescriptor) {
        Object.defineProperty(window, "sessionStorage", sessionStorageDescriptor);
      }
    }
  });

  it("shows the warning for an expiring IDP-specific OIDC user", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const expiresAt = Math.floor((Date.now() + 10_000) / 1000);
    sessionStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(createMockAuth());

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(true);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);
  });

  it("ignores expiring OIDC users from unrelated authorities", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const expiresAt = Math.floor((Date.now() + 10_000) / 1000);
    sessionStorage.setItem(
      "oidc.user:https://other.example.com:other-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(createMockAuth());

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(false);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("ignores stale localStorage OIDC users unless persistent storage is active", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const expiresAt = Math.floor((Date.now() + 10_000) / 1000);
    localStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(createMockAuth());

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(false);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("uses localStorage OIDC users when non-production persistent storage is active", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const expiresAt = Math.floor((Date.now() + 10_000) / 1000);
    localStorage.setItem("breakglass_oidc_token_persistence", "persistent");
    localStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(createMockAuth());

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(true);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);
  });
});

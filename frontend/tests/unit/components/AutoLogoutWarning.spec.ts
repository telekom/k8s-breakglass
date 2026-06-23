/**
 * Tests for AutoLogoutWarning component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, afterEach } from "vitest";

const loggerMocks = vi.hoisted(() => ({
  warn: vi.fn(),
}));

vi.mock("@/services/logger", () => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: loggerMocks.warn,
  error: vi.fn(),
}));

import { mount, VueWrapper } from "@vue/test-utils";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
import AuthService from "@/services/auth";
import { AuthKey } from "@/keys";

type MockAuth = {
  login: (state?: { path: string; idpName?: string }) => Promise<void>;
  logout: () => void;
  getIdentityProviderName: () => string | undefined;
  getActiveOIDCUserStorageKeys: () => string[];
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
    loggerMocks.warn.mockReset();
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
    getActiveOIDCUserStorageKeys: vi.fn(() => ["oidc.user:https://issuer.example.com:breakglass-ui"]),
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

  it("does not recover stale local persisted identity provider names through AuthService", async () => {
    const auth = new AuthService({
      oidcAuthority: "https://issuer.example.com",
      oidcClientID: "breakglass-ui",
    });
    const loginSpy = vi.spyOn(auth, "login").mockResolvedValue(undefined);
    localStorage.setItem("breakglass_current_idp_name", "corp");
    window.history.pushState({}, "", "/sessions?cluster=prod#approval");
    wrapper = mountWithAuth(auth);

    await (wrapper.vm as unknown as AutoLogoutWarningVm).reauthenticate();

    expect(loginSpy).toHaveBeenCalledWith({
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
    const auth = createMockAuth({
      getActiveOIDCUserStorageKeys: vi.fn(() => ["oidc.user:/api/oidc/authority:corp-ui"]),
    });
    sessionStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(auth);

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
    const auth = createMockAuth({
      getActiveOIDCUserStorageKeys: vi.fn(() => ["oidc.user:/api/oidc/authority:corp-ui"]),
    });
    localStorage.setItem("breakglass_oidc_token_persistence", "persistent");
    localStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: expiresAt,
      }),
    );

    wrapper = mountWithAuth(auth);

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(true);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);
  });

  it("ignores inactive IDP OIDC users when only they are expiring", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const inactiveExpiresAt = Math.floor((Date.now() + 10_000) / 1000);
    const activeExpiresAt = Math.floor((Date.now() + 120_000) / 1000);
    const auth = createMockAuth({
      getIdentityProviderName: vi.fn(() => "corp"),
      getActiveOIDCUserStorageKeys: vi.fn(() => ["oidc.user:/api/oidc/authority:corp-ui"]),
    });
    sessionStorage.setItem(
      "oidc.user:/api/oidc/authority:legacy-ui",
      JSON.stringify({
        expires_at: inactiveExpiresAt,
      }),
    );
    sessionStorage.setItem(
      "oidc.user:/api/oidc/authority:corp-ui",
      JSON.stringify({
        expires_at: activeExpiresAt,
      }),
    );

    wrapper = mountWithAuth(auth);

    await vi.advanceTimersByTimeAsync(5000);
    await wrapper.vm.$nextTick();

    expect((wrapper.vm as unknown as { show: boolean }).show).toBe(false);
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("warns once per storage item when OIDC user storage reads fail repeatedly", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    const originalSessionStorageDescriptor = Object.getOwnPropertyDescriptor(window, "sessionStorage");
    const throwingStorage = {
      get length() {
        return 0;
      },
      clear: vi.fn(),
      getItem: vi.fn(() => {
        throw new Error("storage read blocked");
      }),
      key: vi.fn(() => null),
      removeItem: vi.fn(),
      setItem: vi.fn(),
    } satisfies Storage;

    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      value: throwingStorage,
    });

    try {
      wrapper = mountWithAuth(createMockAuth());

      await vi.advanceTimersByTimeAsync(15_000);

      const readWarnings = loggerMocks.warn.mock.calls.filter(
        ([tag, message]) => tag === "AutoLogoutWarning" && message === "Unable to read browser storage item",
      );
      expect(readWarnings).toHaveLength(1);
    } finally {
      if (originalSessionStorageDescriptor) {
        Object.defineProperty(window, "sessionStorage", originalSessionStorageDescriptor);
      }
    }
  });

  it("warns once per malformed OIDC user value when parsing fails repeatedly", async () => {
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    sessionStorage.setItem("oidc.user:https://issuer.example.com:breakglass-ui", "{not-json");

    wrapper = mountWithAuth(createMockAuth());

    await vi.advanceTimersByTimeAsync(15_000);

    const parseWarnings = loggerMocks.warn.mock.calls.filter(
      ([tag, message]) =>
        tag === "AutoLogoutWarning" && message === "Failed to parse OIDC user data from browser storage",
    );
    expect(parseWarnings).toHaveLength(1);
  });
});

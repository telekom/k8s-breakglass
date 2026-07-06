/**
 * Tests for AutoLogoutWarning component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import { nextTick } from "vue";
import AutoLogoutWarning from "@/components/AutoLogoutWarning.vue";
import { AuthKey } from "@/keys";
import { getOIDCUserStorageKey, getStoredOIDCUser } from "@/services/auth";

const AUTHORITY = "https://issuer.example.com";
const CLIENT_ID = "breakglass-ui";
const OIDC_USER_STORAGE_KEY = getOIDCUserStorageKey(AUTHORITY, CLIENT_ID);

describe("AutoLogoutWarning", () => {
  let wrapper: VueWrapper | null = null;

  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
    sessionStorage.clear();
    localStorage.clear();
  });
  const createMockAuth = () => ({
    logout: vi.fn(),
    userManager: {
      settings: {
        authority: AUTHORITY,
        client_id: CLIENT_ID,
      },
      signinSilent: vi.fn().mockResolvedValue(undefined),
    },
  });

  const mountWithAuth = () =>
    mount(AutoLogoutWarning, {
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

  const runExpiryCheck = async () => {
    await vi.advanceTimersByTimeAsync(5000);
    await nextTick();
  };

  const storeOIDCUser = (storage: Storage, expiresAt: number | undefined) => {
    if (!OIDC_USER_STORAGE_KEY) {
      throw new Error("Expected OIDC user storage key");
    }
    storage.setItem(OIDC_USER_STORAGE_KEY, JSON.stringify({ expires_at: expiresAt }));
  };

  const storeOIDCUserString = (storage: Storage, value: string) => {
    if (!OIDC_USER_STORAGE_KEY) {
      throw new Error("Expected OIDC user storage key");
    }
    storage.setItem(OIDC_USER_STORAGE_KEY, value);
  };

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
    wrapper = mountWithAuth();

    expect(wrapper.exists()).toBe(true);
  });

  it("shows the warning when the sessionStorage OIDC user expires soon", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    storeOIDCUser(sessionStorage, Math.floor(Date.now() / 1000) + 20);

    wrapper = mountWithAuth();
    await runExpiryCheck();

    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);
  });

  it("falls back to localStorage when no sessionStorage OIDC user exists", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    storeOIDCUser(localStorage, Math.floor(Date.now() / 1000) + 20);

    wrapper = mountWithAuth();
    await runExpiryCheck();

    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);
  });

  it("keeps the warning hidden when no OIDC user is stored", async () => {
    vi.useFakeTimers();

    wrapper = mountWithAuth();
    await runExpiryCheck();

    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("keeps the warning hidden for expired and non-expiring stored users", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));

    storeOIDCUser(sessionStorage, Math.floor(Date.now() / 1000) - 1);
    wrapper = mountWithAuth();
    await runExpiryCheck();
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);

    wrapper.unmount();
    sessionStorage.clear();
    storeOIDCUser(sessionStorage, undefined);
    wrapper = mountWithAuth();
    await runExpiryCheck();
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("hides a visible warning when the stored OIDC user disappears", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    storeOIDCUser(sessionStorage, Math.floor(Date.now() / 1000) + 20);

    wrapper = mountWithAuth();
    await runExpiryCheck();
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);

    if (!OIDC_USER_STORAGE_KEY) {
      throw new Error("Expected OIDC user storage key");
    }
    sessionStorage.removeItem(OIDC_USER_STORAGE_KEY);
    await runExpiryCheck();

    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("hides a visible warning when stored OIDC user data becomes invalid", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    storeOIDCUser(sessionStorage, Math.floor(Date.now() / 1000) + 20);

    wrapper = mountWithAuth();
    await runExpiryCheck();
    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(true);

    storeOIDCUserString(sessionStorage, "{not-json");
    await runExpiryCheck();

    expect(wrapper.find('[data-testid="auto-logout-warning"]').exists()).toBe(false);
  });

  it("returns null when browser storage access is blocked", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });

    expect(getStoredOIDCUser(AUTHORITY, CLIENT_ID)).toBeNull();
  });
});

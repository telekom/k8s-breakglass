/**
 * Tests for useMultiIDP composable
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { defineComponent, h } from "vue";
import { useMultiIDP } from "@/composables/useMultiIDP";
import type { MultiIDPConfig, IDPInfo } from "@/model/multiIDP";

// Mock the multiIDP service
const mockGetMultiIDPConfig = vi.fn();
const mockGetAllowedIDPsForEscalation = vi.fn();
const mockIsIDPAllowedForEscalation = vi.fn();

vi.mock("@/services/multiIDP", () => ({
  getMultiIDPConfig: () => mockGetMultiIDPConfig(),
  getAllowedIDPsForEscalation: (escalation: string, config: MultiIDPConfig) =>
    mockGetAllowedIDPsForEscalation(escalation, config),
  isIDPAllowedForEscalation: (idpName: string, escalation: string, config: MultiIDPConfig) =>
    mockIsIDPAllowedForEscalation(idpName, escalation, config),
}));

vi.mock("@/services/logger", () => ({
  error: vi.fn(),
}));

describe("useMultiIDP", () => {
  const mockIDPs: IDPInfo[] = [
    { name: "keycloak", displayName: "Keycloak SSO", issuer: "https://keycloak.example.com", enabled: true },
    { name: "azuread", displayName: "Azure AD", issuer: "https://login.microsoftonline.com", enabled: true },
  ];

  const mockConfig: MultiIDPConfig = {
    identityProviders: mockIDPs,
    escalationIDPMapping: {
      "admin-escalation": ["keycloak", "azuread"],
      "partner-escalation": ["azuread"],
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockGetMultiIDPConfig.mockResolvedValue(mockConfig);
    mockGetAllowedIDPsForEscalation.mockReturnValue(mockIDPs);
    mockIsIDPAllowedForEscalation.mockReturnValue(true);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("initializes with loading state", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("test-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);

    // Initially loading should be true
    expect(capturedResult!.loading.value).toBe(true);

    await flushPromises();

    // After config loads, loading should be false
    expect(capturedResult!.loading.value).toBe(false);
  });

  it("loads multi-IDP configuration on mount", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("test-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(mockGetMultiIDPConfig).toHaveBeenCalled();
    expect(capturedResult!.config.value).toEqual(mockConfig);
  });

  it("computes allowedIDPs for the escalation", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    // The allowedIDPs computed property should be populated based on the config
    expect(capturedResult!.config.value).toEqual(mockConfig);
    expect(capturedResult!.allowedIDPs.value).toEqual(mockIDPs);
  });

  it("detects when multiple IDPs are available", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(capturedResult!.hasMultipleIDPs.value).toBe(true);
  });

  it("allows selecting a valid IDP", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    const success = capturedResult!.selectIDP("keycloak");
    expect(success).toBe(true);
    expect(capturedResult!.selectedIDP.value).toBe("keycloak");
  });

  it("rejects selecting an invalid IDP", async () => {
    mockIsIDPAllowedForEscalation.mockReturnValue(false);

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    const success = capturedResult!.selectIDP("invalid-idp");
    expect(success).toBe(false);
    expect(capturedResult!.selectedIDP.value).toBeUndefined();
    expect(capturedResult!.error.value).toBe("Selected IDP is not allowed for this escalation");
  });

  it("clears selection", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    capturedResult!.selectIDP("keycloak");
    expect(capturedResult!.selectedIDP.value).toBe("keycloak");

    capturedResult!.clearSelection();
    expect(capturedResult!.selectedIDP.value).toBeUndefined();
  });

  it("validates selection correctly", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    mockIsIDPAllowedForEscalation.mockReturnValue(true);
    expect(capturedResult!.validateSelection("keycloak", "admin-escalation")).toBe(true);

    mockIsIDPAllowedForEscalation.mockReturnValue(false);
    expect(capturedResult!.validateSelection("unknown", "admin-escalation")).toBe(false);
  });

  it("returns false for validation when config not loaded", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    mockGetMultiIDPConfig.mockResolvedValue(null);

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    // Config is null, so validation should return false
    expect(capturedResult!.validateSelection("keycloak", "admin-escalation")).toBe(false);
    expect(capturedResult!.error.value).toBe("Configuration not loaded");
  });

  it("calls onSelectionChange callback when IDP is selected", async () => {
    const onSelectionChange = vi.fn();
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation", { onSelectionChange });
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    capturedResult!.selectIDP("keycloak");
    expect(onSelectionChange).toHaveBeenCalledWith("keycloak");

    capturedResult!.clearSelection();
    expect(onSelectionChange).toHaveBeenCalledWith(undefined);
  });

  it("handles config load error gracefully", async () => {
    mockGetMultiIDPConfig.mockRejectedValue(new Error("Network error"));

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(capturedResult!.error.value).toBe("Failed to load identity provider configuration");
    expect(capturedResult!.loading.value).toBe(false);
  });

  it("sets error when config has no identity providers", async () => {
    mockGetMultiIDPConfig.mockResolvedValue({ identityProviders: [] });

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(capturedResult!.error.value).toBe("No identity providers available");
  });

  it("isValid is true when no IDP is required and none selected", async () => {
    mockGetAllowedIDPsForEscalation.mockReturnValue(mockIDPs);

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation", { required: false });
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(capturedResult!.isValid.value).toBe(true);
  });

  it("isValid is false when IDP is required but none selected", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation", { required: true });
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(capturedResult!.isValid.value).toBe(false);
  });

  it("isValid is true when required and valid IDP is selected", async () => {
    mockGetAllowedIDPsForEscalation.mockReturnValue(mockIDPs);

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation", { required: true });
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    capturedResult!.selectIDP("keycloak");
    expect(capturedResult!.isValid.value).toBe(true);
  });

  it("supports dynamic escalation name via getter function", async () => {
    let currentEscalation = "first-escalation";
    const escalationGetter = () => currentEscalation;

    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP(escalationGetter);
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    // The getter function is used internally when computing allowedIDPs
    // We verify configuration was loaded successfully
    expect(capturedResult!.config.value).toEqual(mockConfig);
    expect(mockGetMultiIDPConfig).toHaveBeenCalled();
  });

  it("refreshConfig reloads configuration", async () => {
    let capturedResult: ReturnType<typeof useMultiIDP> | null = null;

    const TestComponent = defineComponent({
      setup() {
        capturedResult = useMultiIDP("admin-escalation");
        return () => h("div");
      },
    });

    mount(TestComponent);
    await flushPromises();

    expect(mockGetMultiIDPConfig).toHaveBeenCalledTimes(1);

    await capturedResult!.refreshConfig();
    expect(mockGetMultiIDPConfig).toHaveBeenCalledTimes(2);
  });
});

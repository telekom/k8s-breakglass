import { vi, type Mock } from "vitest";
import axios from "axios";
import getConfig from "@/services/config";
import { getIdentityProvider, extractOIDCConfig } from "@/services/identityProvider";
import type { IdentityProviderConfig } from "@/services/identityProvider";

vi.mock("axios");
vi.mock("@/services/identityProvider", () => ({
  getIdentityProvider: vi.fn(),
  extractOIDCConfig: vi.fn(),
}));

const mockedAxios = axios as unknown as { get: Mock };
const mockedGetIdentityProvider = getIdentityProvider as Mock<typeof getIdentityProvider>;
const mockedExtractOIDC = extractOIDCConfig as Mock<typeof extractOIDCConfig>;

describe("Config service", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    // Use try-catch to handle jsdom SecurityError
    try {
      window.history.replaceState({}, "", "/");
    } catch {
      // Ignore SecurityError in jsdom
    }
  });

  it("merges runtime uiFlavour when IdentityProvider omits branding fields", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as IdentityProviderConfig);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });

    mockedAxios.get.mockImplementation((url: string) => {
      if (url === "/api/config") {
        return Promise.resolve({
          data: {
            frontend: {
              brandingName: "Breakglass Dev Preview",
              uiFlavour: "telekom",
            },
          },
        });
      }
      throw new Error(`Unexpected axios call to ${url}`);
    });

    const config = await getConfig();

    expect(config.oidcAuthority).toBe("https://keycloak.example.com/realms/schiff");
    expect(config.oidcClientID).toBe("ui");
    expect(config.brandingName).toBe("Breakglass Dev Preview");
    expect(config.uiFlavour).toBe("telekom");
    expect(mockedAxios.get).toHaveBeenCalledWith("/api/config");
  });

  it("honours flavour override via query parameter and stores it for later", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as IdentityProviderConfig);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { brandingName: "Breakglass", uiFlavour: "telekom" } } });

    // Use Object.defineProperty to mock location.search without triggering SecurityError
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "?flavour=oss" },
      writable: true,
    });

    const config = await getConfig();

    expect(config.uiFlavour).toBe("oss");
    expect(window.localStorage.getItem("k8sBreakglassUiFlavourOverride")).toBe("oss");
  });

  it("accepts neutral flavour override", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as IdentityProviderConfig);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { brandingName: "Breakglass", uiFlavour: "telekom" } } });

    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "?flavour=neutral" },
      writable: true,
    });

    const config = await getConfig();

    expect(config.uiFlavour).toBe("neutral");
    expect(window.localStorage.getItem("k8sBreakglassUiFlavourOverride")).toBe("neutral");
  });

  it("falls back to stored override when query parameter is absent", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as IdentityProviderConfig);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { uiFlavour: "telekom" } } });

    Object.defineProperty(window, "location", {
      value: { ...window.location, search: "" },
      writable: true,
    });

    window.localStorage.setItem("k8sBreakglassUiFlavourOverride", "oss");

    const config = await getConfig();

    expect(config.uiFlavour).toBe("oss");
  });

  it.each(["reset", "clear", "default", "auto"])("clears stored override when %s token is provided", async (token) => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as IdentityProviderConfig);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { uiFlavour: "telekom" } } });

    window.localStorage.setItem("k8sBreakglassUiFlavourOverride", "oss");
    // Use Object.defineProperty to mock location.search without triggering SecurityError
    Object.defineProperty(window, "location", {
      value: { ...window.location, search: `?flavour=${token}` },
      writable: true,
    });

    const config = await getConfig();

    expect(config.uiFlavour).toBe("telekom");
    expect(window.localStorage.getItem("k8sBreakglassUiFlavourOverride")).toBeNull();
  });
});

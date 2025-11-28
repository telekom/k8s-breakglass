import axios from "axios";
import getConfig from "@/services/config";
import { getIdentityProvider, extractOIDCConfig } from "@/services/identityProvider";

jest.mock("axios");
jest.mock("@/services/identityProvider", () => ({
  getIdentityProvider: jest.fn(),
  extractOIDCConfig: jest.fn(),
}));

const mockedAxios = axios as jest.Mocked<typeof axios>;
const mockedGetIdentityProvider = getIdentityProvider as jest.MockedFunction<typeof getIdentityProvider>;
const mockedExtractOIDC = extractOIDCConfig as jest.MockedFunction<typeof extractOIDCConfig>;

describe("Config service", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    window.localStorage.clear();
    window.history.replaceState({}, "", "http://localhost/");
  });

  it("merges runtime uiFlavour when IdentityProvider omits branding fields", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as any);
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
    } as any);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { brandingName: "Breakglass", uiFlavour: "telekom" } } });

    window.history.replaceState({}, "", "http://localhost/?flavour=oss");

    const config = await getConfig();

    expect(config.uiFlavour).toBe("oss");
    expect(window.localStorage.getItem("k8sBreakglassUiFlavourOverride")).toBe("oss");
  });

  it("falls back to stored override when query parameter is absent", async () => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as any);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { uiFlavour: "telekom" } } });

    window.localStorage.setItem("k8sBreakglassUiFlavourOverride", "oss");

    const config = await getConfig();

    expect(config.uiFlavour).toBe("oss");
  });

  it.each(["reset", "clear", "default", "auto"])("clears stored override when %s token is provided", async (token) => {
    mockedGetIdentityProvider.mockResolvedValue({
      type: "Keycloak",
      clientID: "ui",
      keycloak: { baseURL: "https://keycloak.example.com", realm: "schiff" },
    } as any);
    mockedExtractOIDC.mockReturnValue({
      oidcAuthority: "https://keycloak.example.com/realms/schiff",
      oidcClientID: "ui",
    });
    mockedAxios.get.mockResolvedValue({ data: { frontend: { uiFlavour: "telekom" } } });

    window.localStorage.setItem("k8sBreakglassUiFlavourOverride", "oss");
    window.history.replaceState({}, "", `http://localhost/?flavour=${token}`);

    const config = await getConfig();

    expect(config.uiFlavour).toBe("telekom");
    expect(window.localStorage.getItem("k8sBreakglassUiFlavourOverride")).toBeNull();
  });
});

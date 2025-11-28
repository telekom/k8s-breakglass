import axios from "axios";
import {
  getMultiIDPConfig,
  getAllowedIDPsForEscalation,
  isIDPAllowedForEscalation,
  type MultiIDPConfig,
} from "./multiIDP";
import { error as logError } from "@/services/logger";

jest.mock("axios", () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
  },
}));

jest.mock("@/services/logger", () => ({
  __esModule: true,
  error: jest.fn(),
}));

const mockedAxios = axios as unknown as { get: jest.Mock };
const mockedLogError = logError as jest.MockedFunction<typeof logError>;

describe("multiIDP service", () => {
  beforeEach(() => {
    mockedAxios.get.mockReset();
    mockedLogError.mockReset();
  });

  it("fetches multi-IDP config from the API", async () => {
    const config: MultiIDPConfig = {
      identityProviders: [{ name: "corp", displayName: "Corporate", issuer: "https://idp", enabled: true }],
      escalationIDPMapping: { admin: ["corp"] },
    };
    mockedAxios.get.mockResolvedValueOnce({ data: config });

    const result = await getMultiIDPConfig();

    expect(mockedAxios.get).toHaveBeenCalledWith("/api/config/idps");
    expect(result).toEqual(config);
  });

  it("returns empty defaults and logs errors when fetching fails", async () => {
    mockedAxios.get.mockRejectedValueOnce(new Error("boom"));

    const result = await getMultiIDPConfig();

    expect(result).toEqual({ identityProviders: [], escalationIDPMapping: {} });
    expect(mockedLogError).toHaveBeenCalledWith(
      "MultiIDPService",
      "Failed to fetch multi-IDP configuration",
      expect.any(Error),
    );
  });

  it("filters allowed IDPs for a restricted escalation", () => {
    const config: MultiIDPConfig = {
      identityProviders: [
        { name: "corp", displayName: "Corporate", issuer: "https://corp", enabled: true },
        { name: "contractor", displayName: "Contractor", issuer: "https://contractor", enabled: true },
      ],
      escalationIDPMapping: {
        prod: ["corp"],
      },
    };

    const allowed = getAllowedIDPsForEscalation("prod", config);
    expect(allowed.map((idp) => idp.name)).toEqual(["corp"]);

    const unrestricted = getAllowedIDPsForEscalation("unknown", config);
    expect(unrestricted).toHaveLength(2);
  });

  it("validates IDP selection against the mapping", () => {
    const config: MultiIDPConfig = {
      identityProviders: [],
      escalationIDPMapping: {
        prod: ["corp"],
        unrestricted: [],
      },
    };

    expect(isIDPAllowedForEscalation("corp", "prod", config)).toBe(true);
    expect(isIDPAllowedForEscalation("contractor", "prod", config)).toBe(false);
    expect(isIDPAllowedForEscalation("corp", "unrestricted", config)).toBe(true);
    expect(isIDPAllowedForEscalation("corp", "unknown", config)).toBe(true);
  });
});

/**
 * Tests for BreakglassService error handling
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock dependencies before importing the service
const mockGet = vi.fn();
const mockPost = vi.fn();

vi.mock("@/services/httpClient", () => ({
  createAuthenticatedApiClient: () => ({
    get: mockGet,
    post: mockPost,
  }),
}));

vi.mock("@/services/logger", () => ({
  handleAxiosError: vi.fn(),
  debug: vi.fn(),
}));

import BreakglassService from "@/services/breakglass";

describe("BreakglassService", () => {
  let service: BreakglassService;

  const mockAuth = {
    user: { email: "test@example.com" },
    getAccessToken: vi.fn().mockResolvedValue("test-token"),
    getUserEmail: vi.fn().mockResolvedValue("test@example.com"),
  } as unknown as ConstructorParameters<typeof BreakglassService>[0];

  beforeEach(() => {
    vi.clearAllMocks();
    service = new BreakglassService(mockAuth);
  });

  describe("fetchAvailableEscalations (via getBreakglasses)", () => {
    it.each([["Production admin"], [""], [undefined]])(
      "preserves escalation identity and resolves displayName %s for every cluster",
      async (displayName) => {
        mockGet.mockImplementation((url: string) =>
          Promise.resolve({
            data:
              url === "/breakglassEscalations"
                ? {
                    items: [
                      {
                        metadata: { name: "admin-a1b2c3d4" },
                        spec: {
                          displayName,
                          escalatedGroup: "admin",
                          allowed: { clusters: ["prod", "staging"], groups: ["dev"] },
                        },
                      },
                    ],
                  }
                : [],
          }),
        );
        const result = await service.getBreakglasses();
        expect(result).toEqual([
          expect.objectContaining({
            escalationName: "admin-a1b2c3d4",
            displayName: displayName || "admin-a1b2c3d4",
            to: "admin",
            cluster: "prod",
          }),
          expect.objectContaining({
            escalationName: "admin-a1b2c3d4",
            displayName: displayName || "admin-a1b2c3d4",
            to: "admin",
            cluster: "staging",
          }),
        ]);
      },
    );

    it("rethrows when escalations API fails", async () => {
      // fetchAvailableEscalations is private, but it's called by getBreakglasses
      // Simulate a network error on the escalations endpoint
      mockGet.mockImplementation((url: string) => {
        if (url === "/breakglassEscalations") {
          return Promise.reject(new Error("Network error"));
        }
        // Other endpoints return empty
        return Promise.resolve({ data: [] });
      });

      await expect(service.getBreakglasses()).rejects.toThrow("Network error");
    });

    it("handles non-array response data gracefully", async () => {
      mockGet.mockImplementation((url: string) => {
        if (url === "/breakglassEscalations") {
          return Promise.resolve({ data: null });
        }
        return Promise.resolve({ data: [] });
      });

      const result = await service.getBreakglasses();
      expect(Array.isArray(result)).toBe(true);
    });

    it("logs error when escalations fetch fails", async () => {
      const { handleAxiosError } = await import("@/services/logger");
      mockGet.mockImplementation((url: string) => {
        if (url === "/breakglassEscalations") {
          return Promise.reject(new Error("Server error"));
        }
        return Promise.resolve({ data: [] });
      });

      await expect(service.getBreakglasses()).rejects.toThrow("Server error");

      expect(handleAxiosError).toHaveBeenCalledWith(
        expect.stringContaining("fetchAvailableEscalations"),
        expect.any(Error),
        expect.any(String),
      );
    });
  });

  describe("fetchMyOutstandingRequests", () => {
    it("re-throws error after logging", async () => {
      mockGet.mockRejectedValueOnce(new Error("Request failed"));

      await expect(service.fetchMyOutstandingRequests()).rejects.toThrow("Request failed");
    });

    it("requests only cluster/group even when the card aggregates escalation identities", async () => {
      mockPost.mockResolvedValueOnce({ status: 201 });
      const transition = {
        cluster: "prod",
        to: "admin",
        escalationName: "first-id",
        displayName: "First admin",
        escalationIdentities: ["first-id", "First admin", "second-id", "Second admin"],
        from: "ops",
        duration: 3600,
        selfApproval: false,
        approvalGroups: ["approvers"],
        group: "admin",
        expiry: 0,
        state: "Available",
      };
      await service.requestBreakglass(transition, "Incident repair", 3600);
      expect(mockPost).toHaveBeenCalledWith("/breakglassSessions", {
        cluster: "prod",
        group: "admin",
        user: "test@example.com",
        reason: "Incident repair",
        duration: 3600,
      });
    });

    it("returns empty array for non-array response", async () => {
      mockGet.mockResolvedValueOnce({ data: "not an array" });

      const result = await service.fetchMyOutstandingRequests();
      expect(result).toEqual([]);
    });
  });

  describe("fetchActiveSessions", () => {
    it("returns empty array on error", async () => {
      mockGet.mockRejectedValueOnce(new Error("Timeout"));

      const result = await service.fetchActiveSessions();
      expect(result).toEqual([]);
    });

    it("handles non-array session data", async () => {
      mockGet.mockResolvedValueOnce({ data: null });

      const result = await service.fetchActiveSessions();
      expect(result).toEqual([]);
    });
  });
});

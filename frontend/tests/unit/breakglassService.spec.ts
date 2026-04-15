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
  } as unknown as ConstructorParameters<typeof BreakglassService>[0];

  beforeEach(() => {
    vi.clearAllMocks();
    service = new BreakglassService(mockAuth);
  });

  describe("fetchAvailableEscalations (via getBreakglasses)", () => {
    it("returns empty array when escalations API fails", async () => {
      // fetchAvailableEscalations is private, but it's called by getBreakglasses
      // Simulate a network error on the escalations endpoint
      mockGet.mockImplementation((url: string) => {
        if (url === "/breakglassEscalations") {
          return Promise.reject(new Error("Network error"));
        }
        // Other endpoints return empty
        return Promise.resolve({ data: [] });
      });

      // getBreakglasses calls fetchAvailableEscalations internally
      // The error should be caught and an empty array returned
      const result = await service.getBreakglasses();
      expect(Array.isArray(result)).toBe(true);
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

      await service.getBreakglasses();

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

  describe("pagination", () => {
    it("fetchMyOutstandingRequests walks all pages", async () => {
      const page1 = { metadata: { name: "s1" }, spec: { grantedGroup: "g", cluster: "c" }, status: {} };
      const page2 = { metadata: { name: "s2" }, spec: { grantedGroup: "g", cluster: "c" }, status: {} };
      mockGet
        .mockResolvedValueOnce({ data: { items: [page1], metadata: { continue: "tok1" } } })
        .mockResolvedValueOnce({ data: { items: [page2], metadata: { continue: "" } } });

      const result = await service.fetchMyOutstandingRequests();
      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({ metadata: { name: "s1" } });
      expect(result[1]).toMatchObject({ metadata: { name: "s2" } });
      expect(mockGet).toHaveBeenCalledTimes(2);
    });

    it("fetchActiveSessions walks all pages", async () => {
      const page1 = { metadata: { name: "a1" }, spec: { grantedGroup: "grp", cluster: "cl" }, status: { state: "Approved" } };
      const page2 = { metadata: { name: "a2" }, spec: { grantedGroup: "grp", cluster: "cl" }, status: { state: "Approved" } };
      mockGet
        .mockResolvedValueOnce({ data: { items: [page1], metadata: { continue: "next" } } })
        .mockResolvedValueOnce({ data: { items: [page2], metadata: { continue: "" } } });

      const result = await service.fetchActiveSessions();
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("a1");
      expect(result[1].name).toBe("a2");
      expect(mockGet).toHaveBeenCalledTimes(2);
    });

    it("searchSessions walks all pages", async () => {
      const s1 = { metadata: { name: "q1" }, spec: {}, status: {} };
      const s2 = { metadata: { name: "q2" }, spec: {}, status: {} };
      mockGet
        .mockResolvedValueOnce({ data: { items: [s1], metadata: { continue: "c1" } } })
        .mockResolvedValueOnce({ data: { items: [s2], metadata: { continue: "" } } });

      const result = await service.searchSessions({ state: "pending" });
      expect(result).toHaveLength(2);
      expect(mockGet).toHaveBeenCalledTimes(2);
    });

    it("fetchHistoricalSessions walks all pages", async () => {
      const h1 = { metadata: { name: "h1" }, spec: { grantedGroup: "g", cluster: "c" }, status: { state: "Rejected" } };
      const h2 = { metadata: { name: "h2" }, spec: { grantedGroup: "g", cluster: "c" }, status: { state: "Withdrawn" } };
      mockGet
        .mockResolvedValueOnce({ data: { items: [h1], metadata: { continue: "p2" } } })
        .mockResolvedValueOnce({ data: { items: [h2], metadata: { continue: "" } } });

      const result = await service.fetchHistoricalSessions();
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe("h1");
      expect(result[1].name).toBe("h2");
      expect(mockGet).toHaveBeenCalledTimes(2);
    });

    it("fetchSessionsIApproved walks all pages", async () => {
      const a1 = { metadata: { name: "ia1" }, spec: { grantedGroup: "g", cluster: "c" }, status: { state: "Approved" } };
      const a2 = { metadata: { name: "ia2" }, spec: { grantedGroup: "g", cluster: "c" }, status: { state: "Timeout" } };
      mockGet
        .mockResolvedValueOnce({ data: { items: [a1], metadata: { continue: "tok" } } })
        .mockResolvedValueOnce({ data: { items: [a2], metadata: { continue: "" } } });

      const result = await service.fetchSessionsIApproved();
      expect(result).toHaveLength(2);
      expect(mockGet).toHaveBeenCalledTimes(2);
    });
  });
});

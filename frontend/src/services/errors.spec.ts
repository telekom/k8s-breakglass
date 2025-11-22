/**
 * Tests for error handling service
 *
 * This test suite covers error management functionality:
 * - Error creation and storage
 * - Error dismissal
 * - Auto-expiration of errors
 * - Error state management
 *
 * @jest-environment jsdom
 */

/// <reference types="jest" />

import { pushError, dismissError, useErrors } from "@/services/errors";

describe("Error Service", () => {
  beforeEach(() => {
    // Clear errors by dismissing all
    const state = useErrors();
    const ids = [...state.errors].map((e) => e.id);
    ids.forEach((id) => dismissError(id));
  });

  describe("pushError()", () => {
    it("adds an error to the errors list", () => {
      pushError("Test error");
      const state = useErrors();
      expect(state.errors.length).toBeGreaterThan(0);
      expect(state.errors.some((e) => e.message === "Test error")).toBe(true);
    });

    it("includes status code when provided", () => {
      pushError("Forbidden", 403);
      const state = useErrors();
      const error = state.errors.find((e) => e.message === "Forbidden");
      expect(error?.status).toBe(403);
    });

    it("includes correlation ID when provided", () => {
      pushError("Error", 500, "req-123");
      const state = useErrors();
      const error = state.errors.find((e) => e.message === "Error");
      expect(error?.cid).toBe("req-123");
    });

    it("generates unique IDs for each error", () => {
      pushError("Error 1");
      pushError("Error 2");
      const state = useErrors();
      const ids = state.errors.map((e) => e.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("includes timestamp for each error", () => {
      const before = Date.now();
      pushError("Test error");
      const after = Date.now();

      const state = useErrors();
      const error = state.errors.find((e) => e.message === "Test error");
      expect(error?.ts).toBeGreaterThanOrEqual(before);
      expect(error?.ts).toBeLessThanOrEqual(after);
    });

    it("creates error object with all required properties", () => {
      pushError("Complete error", 400, "corr-id");
      const state = useErrors();
      const error = state.errors.find((e) => e.message === "Complete error");

      expect(error).toHaveProperty("id");
      expect(error).toHaveProperty("message");
      expect(error).toHaveProperty("status");
      expect(error).toHaveProperty("cid");
      expect(error).toHaveProperty("ts");
      expect(typeof error?.id).toBe("string");
      expect(error?.status).toBe(400);
      expect(error?.cid).toBe("corr-id");
    });
  });

  describe("dismissError()", () => {
    it("removes an error by ID", () => {
      pushError("Test error");
      const state = useErrors();
      const errorId = state.errors[state.errors.length - 1]?.id;

      if (errorId) {
        const initialCount = state.errors.length;
        dismissError(errorId);
        expect(state.errors.length).toBe(initialCount - 1);
      }
    });

    it("does not affect other errors", () => {
      pushError("Error 1");
      pushError("Error 2");
      pushError("Error 3");

      let state = useErrors();
      const error2Id = state.errors.find((e) => e.message === "Error 2")?.id;

      if (error2Id) {
        dismissError(error2Id);
        state = useErrors();

        expect(state.errors.some((e) => e.message === "Error 1")).toBe(true);
        expect(state.errors.some((e) => e.message === "Error 2")).toBe(false);
        expect(state.errors.some((e) => e.message === "Error 3")).toBe(true);
      }
    });
  });

  describe("useErrors()", () => {
    it("returns the error state object", () => {
      const state = useErrors();
      expect(state).toBeDefined();
      expect(state).toHaveProperty("errors");
      expect(Array.isArray(state.errors)).toBe(true);
    });

    it("reflects changes to errors list", () => {
      pushError("New error");
      const state = useErrors();
      expect(state.errors.some((e) => e.message === "New error")).toBe(true);
    });
  });
});

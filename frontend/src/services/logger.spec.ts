/**
 * Tests for logger service
 *
 * This test suite covers logging functionality:
 * - Info, warn, and error logging
 * - Timestamp and tag formatting
 * - Axios error handling
 * - Error message extraction and sanitization
 *
 * @jest-environment jsdom
 */

/// <reference types="jest" />

import { info, warn, error, handleAxiosError } from "@/services/logger";

describe("Logger Service", () => {
  beforeEach(() => {
    // Save original console methods
    jest.spyOn(console, "info").mockImplementation();
    jest.spyOn(console, "warn").mockImplementation();
    jest.spyOn(console, "error").mockImplementation();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("info() - info logging", () => {
    it("logs info message with tag", () => {
      info("TestTag", "test message");

      expect(console.info).toHaveBeenCalled();
      const args = (console.info as jest.Mock).mock.calls[0];
      expect(args[0]).toMatch(/^\d{4}-\d{2}-\d{2}T/); // timestamp
      expect(args[1]).toBe("[TestTag]");
      expect(args[2]).toBe("test message");
    });

    it("logs multiple arguments", () => {
      info("Tag", "msg1", "msg2", { key: "value" });

      expect(console.info).toHaveBeenCalled();
      const args = (console.info as jest.Mock).mock.calls[0];
      expect(args.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe("warn() - warning logging", () => {
    it("logs warning message with tag", () => {
      warn("TestTag", "warning message");

      expect(console.warn).toHaveBeenCalled();
      const args = (console.warn as jest.Mock).mock.calls[0];
      expect(args[1]).toBe("[TestTag]");
      expect(args[2]).toBe("warning message");
    });

    it("includes timestamp", () => {
      warn("Service", "Warning occurred");

      const args = (console.warn as jest.Mock).mock.calls[0];
      expect(args[0]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe("error() - error logging", () => {
    it("logs error message with tag", () => {
      error("TestTag", "error message");

      expect(console.error).toHaveBeenCalled();
      const args = (console.error as jest.Mock).mock.calls[0];
      expect(args[1]).toBe("[TestTag]");
      expect(args[2]).toBe("error message");
    });

    it("includes timestamp", () => {
      error("Service", "Error occurred");

      const args = (console.error as jest.Mock).mock.calls[0];
      expect(args[0]).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe("handleAxiosError() - axios error handling", () => {
    it("extracts error message from response data", () => {
      const err = {
        response: {
          status: 400,
          data: { error: "Invalid input" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Invalid input");
    });

    it("extracts string response as error message", () => {
      const err = {
        response: {
          status: 500,
          data: "Server error occurred",
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Server error occurred");
    });

    it("falls back to error message property", () => {
      const err = {
        message: "Network timeout",
        response: { status: 0 },
      };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Network timeout");
    });

    it("uses user message as last resort", () => {
      const err = { response: {} };

      const result = handleAxiosError("API", err, "Custom user message");
      expect(result.message).toBe("Custom user message");
    });

    it("uses default message if nothing provided", () => {
      const err = {};

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Request failed");
    });

    it("extracts status code from response", () => {
      const err = {
        response: {
          status: 403,
          data: { error: "Forbidden" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.status).toBe(403);
    });

    it("extracts correlation ID from response data", () => {
      const err = {
        response: {
          data: { cid: "corr-123" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.cid).toBe("corr-123");
    });

    it("extracts correlation ID from response headers (x-request-id)", () => {
      const err = {
        response: {
          headers: { "x-request-id": "req-456" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.cid).toBe("req-456");
    });

    it("extracts correlation ID from response headers (X-Request-ID)", () => {
      const err = {
        response: {
          headers: { "X-Request-ID": "req-789" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.cid).toBe("req-789");
    });

    it("prioritizes data cid over header cid", () => {
      const err = {
        response: {
          data: { cid: "data-cid" },
          headers: { "x-request-id": "header-cid" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.cid).toBe("data-cid");
    });

    it("logs error to console", () => {
      const err = {
        response: { status: 400, data: { error: "Bad request" } },
      };

      handleAxiosError("API", err);
      expect(console.error).toHaveBeenCalled();
    });

    it("handles missing response gracefully", () => {
      const err = { message: "Network error" };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Network error");
      expect(result.status).toBeUndefined();
    });

    it("handles null/undefined response gracefully", () => {
      const err = { response: null };

      const result = handleAxiosError("API", err);
      expect(result).toBeDefined();
      expect(result.message).toBeDefined();
    });

    it("converts message to string", () => {
      const err = {
        response: {
          data: { error: 123 }, // non-string error
        },
      };

      const result = handleAxiosError("API", err);
      expect(typeof result.message).toBe("string");
    });
  });

  describe("Error message priority", () => {
    it("prefers response.data.error over other sources", () => {
      const err = {
        message: "Generic error",
        response: {
          data: { error: "Specific error" },
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Specific error");
    });

    it("prefers response.data string over message", () => {
      const err = {
        message: "Generic error",
        response: {
          data: "Response error",
        },
      };

      const result = handleAxiosError("API", err);
      expect(result.message).toBe("Response error");
    });
  });
});

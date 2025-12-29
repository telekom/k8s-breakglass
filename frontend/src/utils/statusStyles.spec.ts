/**
 * Tests for statusStyles utility
 */
import { describe, it, expect } from "vitest";
import { statusToneFor } from "./statusStyles";

describe("statusStyles", () => {
  describe("statusToneFor", () => {
    it("returns 'neutral' for null or undefined state", () => {
      expect(statusToneFor(null)).toBe("neutral");
      expect(statusToneFor(undefined)).toBe("neutral");
      expect(statusToneFor("")).toBe("neutral");
    });

    it("maps success states correctly", () => {
      expect(statusToneFor("active")).toBe("success");
      expect(statusToneFor("approved")).toBe("success");
      expect(statusToneFor("running")).toBe("success");
      // Case insensitive
      expect(statusToneFor("Active")).toBe("success");
      expect(statusToneFor("APPROVED")).toBe("success");
    });

    it("maps warning states correctly", () => {
      expect(statusToneFor("pending")).toBe("warning");
      expect(statusToneFor("pendingrequest")).toBe("warning");
      expect(statusToneFor("waitingforscheduledtime")).toBe("warning");
      // Case insensitive
      expect(statusToneFor("Pending")).toBe("warning");
      expect(statusToneFor("WaitingForScheduledTime")).toBe("warning");
    });

    it("maps info states correctly", () => {
      expect(statusToneFor("available")).toBe("info");
      expect(statusToneFor("scheduled")).toBe("info");
      expect(statusToneFor("queued")).toBe("info");
    });

    it("maps danger states correctly", () => {
      expect(statusToneFor("rejected")).toBe("danger");
      expect(statusToneFor("withdraw")).toBe("danger");
      expect(statusToneFor("withdrawn")).toBe("danger");
      expect(statusToneFor("dropped")).toBe("danger");
      expect(statusToneFor("cancelled")).toBe("danger");
      expect(statusToneFor("canceled")).toBe("danger");
      expect(statusToneFor("timeout")).toBe("danger");
      expect(statusToneFor("approvaltimeout")).toBe("danger");
    });

    it("maps muted states correctly", () => {
      expect(statusToneFor("expired")).toBe("muted");
      expect(statusToneFor("completed")).toBe("muted");
      expect(statusToneFor("ended")).toBe("muted");
    });

    it("maps unknown states to neutral", () => {
      expect(statusToneFor("unknown")).toBe("neutral");
      expect(statusToneFor("default")).toBe("neutral");
      expect(statusToneFor("somethingelse")).toBe("neutral");
    });

    it("normalizes whitespace in state strings", () => {
      expect(statusToneFor("waiting for scheduled time")).toBe("warning");
      expect(statusToneFor("approval timeout")).toBe("danger");
      expect(statusToneFor("pending request")).toBe("warning");
    });

    it("handles mixed case and whitespace", () => {
      expect(statusToneFor("Waiting For Scheduled Time")).toBe("warning");
      expect(statusToneFor("APPROVAL TIMEOUT")).toBe("danger");
    });
  });
});

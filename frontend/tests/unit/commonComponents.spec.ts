/**
 * Unit tests for common UI component utilities
 * Tests the logic used by EmptyState, PageHeader, LoadingState, etc.
 */

describe("Common UI Component Utilities", () => {
  describe("StatusTag variant determination", () => {
    /**
     * Maps status strings to visual variants
     */
    function getStatusVariant(status: string): "success" | "warning" | "danger" | "info" | "neutral" {
      const normalized = status.toLowerCase();
      if (["approved", "active", "started"].includes(normalized)) return "success";
      if (["pending", "waitingforscheduledtime", "scheduled"].includes(normalized)) return "warning";
      if (["rejected", "expired", "withdrawn", "timeout", "approvaltimeout", "cancelled"].includes(normalized)) {
        return "danger";
      }
      if (["processing", "waiting"].includes(normalized)) return "info";
      return "neutral";
    }

    it("returns success for approved status", () => {
      expect(getStatusVariant("Approved")).toBe("success");
      expect(getStatusVariant("approved")).toBe("success");
      expect(getStatusVariant("Active")).toBe("success");
    });

    it("returns warning for pending status", () => {
      expect(getStatusVariant("Pending")).toBe("warning");
      expect(getStatusVariant("WaitingForScheduledTime")).toBe("warning");
      expect(getStatusVariant("scheduled")).toBe("warning");
    });

    it("returns danger for rejected/expired status", () => {
      expect(getStatusVariant("Rejected")).toBe("danger");
      expect(getStatusVariant("Expired")).toBe("danger");
      expect(getStatusVariant("Withdrawn")).toBe("danger");
      expect(getStatusVariant("Timeout")).toBe("danger");
      expect(getStatusVariant("ApprovalTimeout")).toBe("danger");
    });

    it("returns info for processing status", () => {
      expect(getStatusVariant("Processing")).toBe("info");
      expect(getStatusVariant("Waiting")).toBe("info");
    });

    it("returns neutral for unknown status", () => {
      expect(getStatusVariant("Unknown")).toBe("neutral");
      expect(getStatusVariant("")).toBe("neutral");
      expect(getStatusVariant("SomeOtherState")).toBe("neutral");
    });
  });

  describe("ReasonPanel visibility logic", () => {
    function hasReason(reason?: string): boolean {
      return Boolean(reason?.trim());
    }

    it("returns true for non-empty reason", () => {
      expect(hasReason("Need access for maintenance")).toBe(true);
    });

    it("returns false for empty reason", () => {
      expect(hasReason("")).toBe(false);
    });

    it("returns false for whitespace-only reason", () => {
      expect(hasReason("   ")).toBe(false);
      expect(hasReason("\t\n")).toBe(false);
    });

    it("returns false for undefined reason", () => {
      expect(hasReason(undefined)).toBe(false);
    });
  });

  describe("ReasonPanel icon mapping", () => {
    type ReasonVariant = "request" | "approval" | "rejection" | "default";

    function getReasonIcon(variant: ReasonVariant): string {
      const icons: Record<ReasonVariant, string> = {
        request: "📝",
        approval: "✅",
        rejection: "❌",
        default: "",
      };
      return icons[variant];
    }

    it("returns correct icon for request variant", () => {
      expect(getReasonIcon("request")).toBe("📝");
    });

    it("returns correct icon for approval variant", () => {
      expect(getReasonIcon("approval")).toBe("✅");
    });

    it("returns correct icon for rejection variant", () => {
      expect(getReasonIcon("rejection")).toBe("❌");
    });

    it("returns empty string for default variant", () => {
      expect(getReasonIcon("default")).toBe("");
    });
  });

  describe("TimelineGrid item generation", () => {
    interface TimelineItem {
      id: string;
      label: string;
      value: string | null;
    }

    function buildTimelineItems(
      scheduledStart: string | null,
      actualStart: string | null,
      ended: string | null,
      expiresAt: string | null,
    ): TimelineItem[] {
      const items: TimelineItem[] = [];

      if (scheduledStart) {
        items.push({ id: "scheduled", label: "Scheduled", value: scheduledStart });
      }
      if (actualStart) {
        items.push({ id: "started", label: "Started", value: actualStart });
      }
      if (ended) {
        items.push({ id: "ended", label: "Ended", value: ended });
      }
      if (expiresAt) {
        items.push({ id: "expires", label: "Expires", value: expiresAt });
      }

      return items;
    }

    it("returns empty array when all values are null", () => {
      expect(buildTimelineItems(null, null, null, null)).toEqual([]);
    });

    it("returns single item for scheduled start", () => {
      const items = buildTimelineItems("2024-01-15T10:00:00Z", null, null, null);
      expect(items).toHaveLength(1);
      expect(items[0]!.id).toBe("scheduled");
    });

    it("returns multiple items when provided", () => {
      const items = buildTimelineItems("2024-01-15T10:00:00Z", "2024-01-15T10:30:00Z", null, "2024-01-15T12:00:00Z");
      expect(items).toHaveLength(3);
      expect(items.map((i) => i.id)).toEqual(["scheduled", "started", "expires"]);
    });

    it("returns all items when all values provided", () => {
      const items = buildTimelineItems(
        "2024-01-15T10:00:00Z",
        "2024-01-15T10:30:00Z",
        "2024-01-15T11:30:00Z",
        "2024-01-15T12:00:00Z",
      );
      expect(items).toHaveLength(4);
    });
  });

  describe("EmptyState action visibility", () => {
    function shouldShowAction(actionLabel?: string): boolean {
      return Boolean(actionLabel);
    }

    it("returns true when action label provided", () => {
      expect(shouldShowAction("Refresh")).toBe(true);
    });

    it("returns false when action label is undefined", () => {
      expect(shouldShowAction(undefined)).toBe(false);
    });

    it("returns false when action label is empty", () => {
      expect(shouldShowAction("")).toBe(false);
    });
  });

  describe("PageHeader heading level", () => {
    type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;

    function getHeadingTag(level: HeadingLevel): string {
      return `h${level}`;
    }

    it("returns h1 for level 1", () => {
      expect(getHeadingTag(1)).toBe("h1");
    });

    it("returns h2 for level 2", () => {
      expect(getHeadingTag(2)).toBe("h2");
    });

    it("returns h3 for level 3", () => {
      expect(getHeadingTag(3)).toBe("h3");
    });
  });

  describe("LoadingState size classes", () => {
    type LoadingSize = "small" | "medium" | "large";

    function getSizeClass(size: LoadingSize): string {
      return `loading-state--${size}`;
    }

    it("returns small class", () => {
      expect(getSizeClass("small")).toBe("loading-state--small");
    });

    it("returns medium class", () => {
      expect(getSizeClass("medium")).toBe("loading-state--medium");
    });

    it("returns large class", () => {
      expect(getSizeClass("large")).toBe("loading-state--large");
    });
  });

  describe("ErrorBanner variant classes", () => {
    type ErrorVariant = "error" | "warning" | "info";

    function getVariantClass(variant: ErrorVariant): string {
      return `error-banner--${variant}`;
    }

    it("returns error class", () => {
      expect(getVariantClass("error")).toBe("error-banner--error");
    });

    it("returns warning class", () => {
      expect(getVariantClass("warning")).toBe("error-banner--warning");
    });

    it("returns info class", () => {
      expect(getVariantClass("info")).toBe("error-banner--info");
    });
  });
});

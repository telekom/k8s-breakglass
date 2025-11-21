/**
 * Tests for BreakglassSessionCard component utility functions
 *
 * This test suite covers session card-related utility logic:
 * - Session state detection
 * - User role validation
 * - Action availability based on session state and user permissions
 *
 * @jest-environment jsdom
 */

/// <reference types="jest" />

describe("BreakglassSessionCard Utilities", () => {
  /**
   * Helper functions for session state and user role detection
   */

  function isSessionOwner(session: any, userEmail: string): boolean {
    return session?.spec?.user === userEmail;
  }

  function canDropSession(session: any, userEmail: string): boolean {
    // Can drop if:
    // 1. User is the owner AND
    // 2. Session is in Approved state
    return isSessionOwner(session, userEmail) && session?.status?.state === "Approved";
  }

  function canRejectSession(session: any, userEmail: string): boolean {
    // Can reject if user is NOT the owner but session still exists
    return !isSessionOwner(session, userEmail) && session?.status?.state === "Approved";
  }

  function getSessionExpiry(session: any): Date | null {
    if (!session?.status?.expiresAt) return null;
    return new Date(session.status.expiresAt);
  }

  describe("isSessionOwner()", () => {
    it("returns true when user email matches session owner", () => {
      const session = {
        spec: { user: "owner@example.com" },
      };
      expect(isSessionOwner(session, "owner@example.com")).toBe(true);
    });

    it("returns false when user email does not match session owner", () => {
      const session = {
        spec: { user: "owner@example.com" },
      };
      expect(isSessionOwner(session, "other@example.com")).toBe(false);
    });

    it("returns false for undefined session", () => {
      expect(isSessionOwner(undefined, "user@example.com")).toBe(false);
    });
  });

  describe("canDropSession()", () => {
    const baseSession = {
      spec: { user: "me@example.com", grantedGroup: "g", cluster: "c" },
      status: { state: "Approved", expiresAt: new Date(Date.now() + 3600000).toISOString() },
      metadata: { name: "s1" },
    };

    it("returns true when current user is owner and session is Approved", () => {
      expect(canDropSession(baseSession, "me@example.com")).toBe(true);
    });

    it("returns false when current user is not owner", () => {
      expect(canDropSession(baseSession, "other@example.com")).toBe(false);
    });

    it("returns false when session is not Approved", () => {
      const session = { ...baseSession, status: { ...baseSession.status, state: "Pending" } };
      expect(canDropSession(session, "me@example.com")).toBe(false);
    });
  });

  describe("canRejectSession()", () => {
    const baseSession = {
      spec: { user: "owner@example.com", grantedGroup: "g", cluster: "c" },
      status: { state: "Approved", expiresAt: new Date(Date.now() + 3600000).toISOString() },
      metadata: { name: "s1" },
    };

    it("returns true when current user is NOT owner and session is Approved", () => {
      expect(canRejectSession(baseSession, "other@example.com")).toBe(true);
    });

    it("returns false when current user is the owner", () => {
      expect(canRejectSession(baseSession, "owner@example.com")).toBe(false);
    });

    it("returns false when session is not Approved", () => {
      const session = { ...baseSession, status: { ...baseSession.status, state: "Pending" } };
      expect(canRejectSession(session, "other@example.com")).toBe(false);
    });
  });

  describe("getSessionExpiry()", () => {
    it("returns Date object when expiresAt is present", () => {
      const expiryTime = new Date(Date.now() + 3600000).toISOString();
      const session = {
        status: { expiresAt: expiryTime },
      };
      const expiry = getSessionExpiry(session);
      expect(expiry).toBeInstanceOf(Date);
      expect(expiry?.toISOString()).toBe(expiryTime);
    });

    it("returns null when expiresAt is not present", () => {
      const session = { status: {} };
      expect(getSessionExpiry(session)).toBeNull();
    });

    it("returns null for undefined session", () => {
      expect(getSessionExpiry(undefined)).toBeNull();
    });
  });
});

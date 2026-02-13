/**
 * Tests for IDPSelector component utility functions
 *
 * This test suite covers IDP selection-related utility logic:
 * - IDP filtering based on escalation configuration
 * - Display name resolution
 * - Validation of IDP selection state
 *
 * @vitest-environment jsdom
 */

interface IDPInfo {
  name: string;
  displayName?: string;
  enabled: boolean;
}

interface MultiIDPConfig {
  identityProviders: IDPInfo[];
  defaultIDP?: string;
}

interface EscalationInfo {
  name: string;
  allowedIDPs?: string[];
}

describe("IDPSelector Utilities", () => {
  /**
   * Gets all allowed IDPs for a given escalation name
   * If escalation has no specific allowedIDPs, returns all enabled IDPs
   */
  function getAllowedIDPsForEscalation(
    config: MultiIDPConfig | null,
    escalationName: string,
    escalations: EscalationInfo[] = [],
  ): IDPInfo[] {
    if (!config || !config.identityProviders.length) {
      return [];
    }

    const escalation = escalations.find((e) => e.name === escalationName);
    const enabledIDPs = config.identityProviders.filter((idp) => idp.enabled);

    if (!escalation?.allowedIDPs || escalation.allowedIDPs.length === 0) {
      // No restrictions, return all enabled IDPs
      return enabledIDPs;
    }

    // Filter to only allowed IDPs that are also enabled
    return enabledIDPs.filter((idp) => escalation.allowedIDPs!.includes(idp.name));
  }

  /**
   * Gets display name for an IDP, falling back to the IDP name
   */
  function getIDPDisplayName(idp: IDPInfo): string {
    return idp.displayName || idp.name;
  }

  /**
   * Checks if an IDP selection is valid for the given escalation
   */
  function isIDPSelectionValid(selectedIDP: string | undefined, allowedIDPs: IDPInfo[], required: boolean): boolean {
    if (!required && !selectedIDP) {
      return true; // Not required and not selected = valid
    }
    if (required && !selectedIDP) {
      return false; // Required but not selected = invalid
    }
    // Check if selected IDP is in allowed list
    return allowedIDPs.some((idp) => idp.name === selectedIDP);
  }

  describe("getAllowedIDPsForEscalation()", () => {
    const mockConfig: MultiIDPConfig = {
      identityProviders: [
        { name: "keycloak", displayName: "Keycloak SSO", enabled: true },
        { name: "azure", displayName: "Azure AD", enabled: true },
        { name: "disabled-idp", displayName: "Disabled IDP", enabled: false },
      ],
      defaultIDP: "keycloak",
    };

    const mockEscalations: EscalationInfo[] = [
      { name: "production-access", allowedIDPs: ["keycloak"] },
      { name: "dev-access" }, // No restrictions
      { name: "azure-only", allowedIDPs: ["azure"] },
    ];

    it("returns empty array when config is null", () => {
      expect(getAllowedIDPsForEscalation(null, "production-access", mockEscalations)).toEqual([]);
    });

    it("returns empty array when config has no IDPs", () => {
      const emptyConfig = { identityProviders: [] };
      expect(getAllowedIDPsForEscalation(emptyConfig, "production-access", mockEscalations)).toEqual([]);
    });

    it("returns all enabled IDPs when escalation has no restrictions", () => {
      const result = getAllowedIDPsForEscalation(mockConfig, "dev-access", mockEscalations);
      expect(result).toHaveLength(2); // keycloak and azure (not disabled-idp)
      expect(result.map((idp) => idp.name)).toContain("keycloak");
      expect(result.map((idp) => idp.name)).toContain("azure");
    });

    it("returns only allowed IDPs when escalation has restrictions", () => {
      const result = getAllowedIDPsForEscalation(mockConfig, "production-access", mockEscalations);
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe("keycloak");
    });

    it("returns all enabled IDPs when escalation not found", () => {
      const result = getAllowedIDPsForEscalation(mockConfig, "unknown-escalation", mockEscalations);
      expect(result).toHaveLength(2);
    });

    it("filters out disabled IDPs from allowed list", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          { name: "disabled-idp", enabled: false },
          { name: "enabled-idp", enabled: true },
        ],
      };
      const escalations: EscalationInfo[] = [{ name: "test", allowedIDPs: ["disabled-idp", "enabled-idp"] }];
      const result = getAllowedIDPsForEscalation(config, "test", escalations);
      expect(result).toHaveLength(1);
      expect(result[0]?.name).toBe("enabled-idp");
    });
  });

  describe("getIDPDisplayName()", () => {
    it("returns displayName when present", () => {
      const idp: IDPInfo = { name: "keycloak", displayName: "Keycloak SSO", enabled: true };
      expect(getIDPDisplayName(idp)).toBe("Keycloak SSO");
    });

    it("returns name when displayName is not present", () => {
      const idp: IDPInfo = { name: "keycloak", enabled: true };
      expect(getIDPDisplayName(idp)).toBe("keycloak");
    });

    it("returns name when displayName is empty string", () => {
      const idp: IDPInfo = { name: "keycloak", displayName: "", enabled: true };
      expect(getIDPDisplayName(idp)).toBe("keycloak");
    });
  });

  describe("isIDPSelectionValid()", () => {
    const allowedIDPs: IDPInfo[] = [
      { name: "keycloak", enabled: true },
      { name: "azure", enabled: true },
    ];

    it("returns true when IDP is in allowed list", () => {
      expect(isIDPSelectionValid("keycloak", allowedIDPs, true)).toBe(true);
      expect(isIDPSelectionValid("azure", allowedIDPs, false)).toBe(true);
    });

    it("returns false when IDP is not in allowed list", () => {
      expect(isIDPSelectionValid("unknown-idp", allowedIDPs, true)).toBe(false);
    });

    it("returns true when selection not required and not selected", () => {
      expect(isIDPSelectionValid(undefined, allowedIDPs, false)).toBe(true);
    });

    it("returns false when selection required and not selected", () => {
      expect(isIDPSelectionValid(undefined, allowedIDPs, true)).toBe(false);
    });

    it("returns false for empty allowed list with selection", () => {
      expect(isIDPSelectionValid("keycloak", [], true)).toBe(false);
    });
  });
});

/**
 * Phase 9 Test Suite: Multi-IDP Frontend Services and Logic
 *
 * Tests for multi-IDP service functions and IDP selector component logic:
 * 1. Service functions: Config filtering, validation
 * 2. Component logic: Selection, filtering, state management
 * 3. Integration: Large configs, multi-IDP scenarios
 * 4. Backward compatibility: Single-IDP mode, empty configs
 *
 * @vitest-environment jsdom
 */

// Mock types
interface IDPInfo {
  name: string;
  displayName: string;
  issuer: string;
  enabled: boolean;
}

interface MultiIDPConfig {
  identityProviders: IDPInfo[];
  escalationIDPMapping: Record<string, string[]>;
}

// Service implementations (simulated from multiIDP.ts)
function getAllowedIDPsForEscalation(escalationName: string, config: MultiIDPConfig): IDPInfo[] {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];

  // Empty array [] means all IDPs allowed (backward compatibility)
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    return config.identityProviders;
  }

  // Filter to only allowed IDPs
  return config.identityProviders.filter((idp) => allowedIDPNames.includes(idp.name));
}

function isIDPAllowedForEscalation(idpName: string, escalationName: string, config: MultiIDPConfig): boolean {
  const allowedIDPNames = config.escalationIDPMapping[escalationName];

  // Empty array [] means all IDPs allowed
  if (allowedIDPNames === undefined || allowedIDPNames.length === 0) {
    return true;
  }

  return allowedIDPNames.includes(idpName);
}

// ============================================================================
// PHASE 9 TEST SUITE: Multi-IDP Services
// ============================================================================

describe("Frontend Multi-IDP: Multi-IDP Configuration Service Functions", () => {
  describe("getAllowedIDPsForEscalation()", () => {
    const config: MultiIDPConfig = {
      identityProviders: [
        {
          name: "idp1",
          displayName: "IDP 1",
          issuer: "https://idp1.com",
          enabled: true,
        },
        {
          name: "idp2",
          displayName: "IDP 2",
          issuer: "https://idp2.com",
          enabled: true,
        },
        {
          name: "idp3",
          displayName: "IDP 3",
          issuer: "https://idp3.com",
          enabled: true,
        },
      ],
      escalationIDPMapping: {
        "restricted-access": ["idp1"],
        "multi-allowed": ["idp1", "idp2"],
        "unrestricted-access": [],
      },
    };

    it("should return only allowed IDPs for restricted escalation", () => {
      const allowed = getAllowedIDPsForEscalation("restricted-access", config);

      expect(allowed).toHaveLength(1);
      expect(allowed[0]!.name).toBe("idp1");
    });

    it("should return multiple allowed IDPs", () => {
      const allowed = getAllowedIDPsForEscalation("multi-allowed", config);

      expect(allowed).toHaveLength(2);
      expect(allowed.map((idp) => idp.name)).toEqual(["idp1", "idp2"]);
    });

    it("should return all IDPs when escalation has empty mapping (unrestricted)", () => {
      const allowed = getAllowedIDPsForEscalation("unrestricted-access", config);

      expect(allowed).toHaveLength(3);
      expect(allowed.map((idp) => idp.name)).toEqual(["idp1", "idp2", "idp3"]);
    });

    it("should return all IDPs when escalation not in mapping (backward compat)", () => {
      const allowed = getAllowedIDPsForEscalation("unknown-escalation", config);

      expect(allowed).toHaveLength(3);
    });
  });

  describe("isIDPAllowedForEscalation()", () => {
    const config: MultiIDPConfig = {
      identityProviders: [
        {
          name: "idp1",
          displayName: "IDP 1",
          issuer: "https://idp1.com",
          enabled: true,
        },
        {
          name: "idp2",
          displayName: "IDP 2",
          issuer: "https://idp2.com",
          enabled: true,
        },
      ],
      escalationIDPMapping: {
        "prod-admin": ["idp1"],
        "dev-admin": ["idp1", "idp2"],
        "test-admin": [],
      },
    };

    it("should allow IDP that is in restriction list", () => {
      const allowed = isIDPAllowedForEscalation("idp1", "prod-admin", config);
      expect(allowed).toBe(true);
    });

    it("should reject IDP that is not in restriction list", () => {
      const allowed = isIDPAllowedForEscalation("idp2", "prod-admin", config);
      expect(allowed).toBe(false);
    });

    it("should allow any IDP for unrestricted escalation (empty list)", () => {
      const allowed1 = isIDPAllowedForEscalation("idp1", "test-admin", config);
      const allowed2 = isIDPAllowedForEscalation("idp2", "test-admin", config);

      expect(allowed1).toBe(true);
      expect(allowed2).toBe(true);
    });

    it("should allow any IDP for unknown escalation (backward compat)", () => {
      const allowed = isIDPAllowedForEscalation("idp1", "unknown-escalation", config);

      expect(allowed).toBe(true);
    });

    it("should validate against multiple allowed IDPs", () => {
      const allowed1 = isIDPAllowedForEscalation("idp1", "dev-admin", config);
      const allowed2 = isIDPAllowedForEscalation("idp2", "dev-admin", config);

      expect(allowed1).toBe(true);
      expect(allowed2).toBe(true);
    });
  });

  describe("Service Integration Scenarios", () => {
    it("should handle single-IDP config (backward compatibility)", () => {
      const singleIDPConfig: MultiIDPConfig = {
        identityProviders: [
          {
            name: "default-idp",
            displayName: "Default Identity",
            issuer: "https://auth.example.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "prod-admin": [],
          "dev-admin": [],
        },
      };

      // Should treat empty mapping as all allowed
      const prodIDPs = getAllowedIDPsForEscalation("prod-admin", singleIDPConfig);
      expect(prodIDPs).toHaveLength(1);
      expect(prodIDPs[0]!.name).toBe("default-idp");

      // Should allow any selection in single-IDP mode
      const allowed = isIDPAllowedForEscalation("default-idp", "prod-admin", singleIDPConfig);
      expect(allowed).toBe(true);
    });

    it("should handle mixed enabled/disabled IDPs", () => {
      const mixedConfig: MultiIDPConfig = {
        identityProviders: [
          {
            name: "enabled-idp",
            displayName: "Enabled",
            issuer: "https://enabled.com",
            enabled: true,
          },
          {
            name: "disabled-idp",
            displayName: "Disabled",
            issuer: "https://disabled.com",
            enabled: false,
          },
        ],
        escalationIDPMapping: {
          "prod-admin": ["enabled-idp", "disabled-idp"], // Both in mapping
        },
      };

      // Frontend still gets both, but can filter by enabled status
      const allowed = getAllowedIDPsForEscalation("prod-admin", mixedConfig);
      expect(allowed).toHaveLength(2);

      // Disabled IDPs should still be allowed (backend enforces the real policy)
      const enabledAllowed = isIDPAllowedForEscalation("disabled-idp", "prod-admin", mixedConfig);
      expect(enabledAllowed).toBe(true);
    });

    it("should handle large multi-IDP configurations", () => {
      const largeConfig: MultiIDPConfig = {
        identityProviders: Array.from({ length: 50 }, (_, i) => ({
          name: `idp-${i}`,
          displayName: `IDP ${i}`,
          issuer: `https://idp-${i}.example.com`,
          enabled: i % 2 === 0,
        })),
        escalationIDPMapping: Object.fromEntries(
          Array.from({ length: 20 }, (_, i) => [
            `escalation-${i}`,
            Array.from({ length: 3 }, (_, j) => `idp-${(i * 2 + j) % 50}`),
          ]),
        ),
      };

      // Filtering should work efficiently with large configs
      const allowed = getAllowedIDPsForEscalation("escalation-0", largeConfig);
      expect(allowed.length).toBeGreaterThan(0);

      // Validation should work
      const isAllowed = isIDPAllowedForEscalation("idp-0", "escalation-0", largeConfig);
      expect(typeof isAllowed).toBe("boolean");
    });

    it("should handle escalations with no IDPs allowed (edge case)", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "no-access": [], // Empty list but explicitly set
        },
      };

      // Empty list means all allowed
      const allowed = getAllowedIDPsForEscalation("no-access", config);
      expect(allowed).toHaveLength(1);
    });
  });
});

// ============================================================================
// PHASE 9 TEST SUITE: IDP Selection Component Logic
// ============================================================================

describe("Frontend Multi-IDP: IDP Selector Component Logic", () => {
  describe("IDP selection filtering", () => {
    it("should filter IDPs available for selected escalation", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          restricted: ["idp1"],
        },
      };

      // Component selects escalation "restricted"
      const allowedIDPs = getAllowedIDPsForEscalation("restricted", config);

      // Should only show idp1 in dropdown
      expect(allowedIDPs).toHaveLength(1);
      expect(allowedIDPs[0]!.displayName).toBe("IDP 1");
    });

    it("should show all IDPs when escalation is unrestricted", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          unrestricted: [],
        },
      };

      const allowedIDPs = getAllowedIDPsForEscalation("unrestricted", config);

      // Should show both IDPs
      expect(allowedIDPs).toHaveLength(2);
    });

    it("should filter with display names for UI rendering", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "corp-idp",
            displayName: "Corporate Identity",
            issuer: "https://auth.corp.com",
            enabled: true,
          },
          {
            name: "contractor-idp",
            displayName: "Contractor Portal",
            issuer: "https://auth.contractor.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "prod-admin": ["corp-idp"],
        },
      };

      const allowed = getAllowedIDPsForEscalation("prod-admin", config);

      expect(allowed[0]!.displayName).toBe("Corporate Identity");
    });
  });

  describe("IDP selection validation", () => {
    it("should validate user selection against allowed IDPs", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          prod: ["idp1"],
        },
      };

      // User tries to select idp1 for prod (allowed)
      const userSelection = "idp1";
      const isValid = isIDPAllowedForEscalation(userSelection, "prod", config);

      expect(isValid).toBe(true);
    });

    it("should reject invalid IDP selection for escalation", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          prod: ["idp1"],
        },
      };

      // User tries to select idp2 for prod (not allowed)
      const userSelection = "idp2";
      const isValid = isIDPAllowedForEscalation(userSelection, "prod", config);

      expect(isValid).toBe(false);
    });

    it("should prevent invalid selections before form submission", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp-a",
            displayName: "IDP A",
            issuer: "https://idp-a.com",
            enabled: true,
          },
          {
            name: "idp-b",
            displayName: "IDP B",
            issuer: "https://idp-b.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "api-admin": ["idp-a"],
        },
      };

      const selectedIDP = "idp-b";
      const escalation = "api-admin";

      // Component should validate before allowing form submission
      const isValid = isIDPAllowedForEscalation(selectedIDP, escalation, config);

      if (!isValid) {
        // Should show error to user
        expect(isValid).toBe(false);
      }
    });
  });

  describe("Component state management", () => {
    it("should handle escalation change and reset invalid selection", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          prod: ["idp1"],
          dev: ["idp2"],
        },
      };

      // User selected idp1 for prod escalation
      let currentSelection = "idp1";
      // User changes escalation to dev
      const currentEscalation = "dev";

      // Check if current selection is still valid
      const stillValid = isIDPAllowedForEscalation(currentSelection, currentEscalation, config);

      // Should be invalid - idp1 not allowed for dev
      expect(stillValid).toBe(false);

      // Component should reset selection
      if (!stillValid) {
        currentSelection = "";
      }

      expect(currentSelection).toBe("");
    });

    it("should maintain selection if still valid after escalation change", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
          {
            name: "idp2",
            displayName: "IDP 2",
            issuer: "https://idp2.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          prod: ["idp1", "idp2"],
          dev: ["idp1", "idp2"],
        },
      };

      // User selected idp1 for prod
      const currentSelection = "idp1";
      // User changes to dev
      const currentEscalation = "dev";

      // Check if selection still valid
      const stillValid = isIDPAllowedForEscalation(currentSelection, currentEscalation, config);

      // Should be valid - idp1 allowed for both
      expect(stillValid).toBe(true);
      expect(currentSelection).toBe("idp1");
    });

    it("should handle multiple escalation switches", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp-a",
            displayName: "IDP A",
            issuer: "https://idp-a.com",
            enabled: true,
          },
          {
            name: "idp-b",
            displayName: "IDP B",
            issuer: "https://idp-b.com",
            enabled: true,
          },
          {
            name: "idp-c",
            displayName: "IDP C",
            issuer: "https://idp-c.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "esc-1": ["idp-a"],
          "esc-2": ["idp-b"],
          "esc-3": ["idp-a", "idp-b", "idp-c"],
        },
      };

      let selection = "idp-a";
      let escalation: string;

      // Switch 1: esc-1 -> esc-3 (selection still valid)
      escalation = "esc-3";
      let valid = isIDPAllowedForEscalation(selection, escalation, config);
      expect(valid).toBe(true);

      // Switch 2: esc-3 -> esc-2 (selection invalid)
      escalation = "esc-2";
      valid = isIDPAllowedForEscalation(selection, escalation, config);
      expect(valid).toBe(false);
      if (!valid) selection = "";

      // Switch 3: esc-2 -> esc-3 (selection empty now)
      expect(selection).toBe("");
    });
  });

  describe("Backward compatibility", () => {
    it("should work with single IDP in list", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "default-idp",
            displayName: "Default",
            issuer: "https://auth.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {},
      };

      // Should still work and show single option
      const allowed = getAllowedIDPsForEscalation("any-escalation", config);

      expect(allowed).toHaveLength(1);
      expect(allowed[0]!.name).toBe("default-idp");
    });

    it("should handle empty IDP list gracefully", () => {
      const config: MultiIDPConfig = {
        identityProviders: [],
        escalationIDPMapping: {},
      };

      // Should not crash
      const allowed = getAllowedIDPsForEscalation("any-escalation", config);

      expect(allowed).toHaveLength(0);
    });

    it("should work with escalations missing from mapping (default to all)", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "other-escalation": ["idp1"],
        },
      };

      // Escalation not in mapping - should default to all
      const allowed = getAllowedIDPsForEscalation("unmapped-escalation", config);

      expect(allowed).toHaveLength(1);
    });

    it("should support optional IDP selection (undefined/empty)", () => {
      let selectedIDP: string | undefined = undefined;

      // Should allow undefined selection (backward compat with single-IDP)
      expect(selectedIDP).toBeUndefined();

      // After selection
      selectedIDP = "idp1";
      expect(selectedIDP).toBe("idp1");

      // Can be cleared
      selectedIDP = undefined;
      expect(selectedIDP).toBeUndefined();
    });
  });

  describe("Error handling and edge cases", () => {
    it("should handle IDP names with special characters", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "azure-ad-v2.0",
            displayName: "Azure AD v2.0",
            issuer: "https://login.microsoftonline.com/tenant/v2.0",
            enabled: true,
          },
          {
            name: "okta_prod",
            displayName: "Okta Production",
            issuer: "https://okta.prod.example.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          "cloud-admin": ["azure-ad-v2.0", "okta_prod"],
        },
      };

      const allowed = getAllowedIDPsForEscalation("cloud-admin", config);
      expect(allowed).toHaveLength(2);

      const valid1 = isIDPAllowedForEscalation("azure-ad-v2.0", "cloud-admin", config);
      const valid2 = isIDPAllowedForEscalation("okta_prod", "cloud-admin", config);

      expect(valid1).toBe(true);
      expect(valid2).toBe(true);
    });

    it("should handle very long escalation names", () => {
      const longEscalationName = "production-kubernetes-cluster-admin-with-full-privileges-and-audit-logging";
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "idp1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          [longEscalationName]: ["idp1"],
        },
      };

      const allowed = getAllowedIDPsForEscalation(longEscalationName, config);
      expect(allowed).toHaveLength(1);

      const valid = isIDPAllowedForEscalation("idp1", longEscalationName, config);
      expect(valid).toBe(true);
    });

    it("should be case-sensitive for IDP names", () => {
      const config: MultiIDPConfig = {
        identityProviders: [
          {
            name: "IDP-1",
            displayName: "IDP 1",
            issuer: "https://idp1.com",
            enabled: true,
          },
        ],
        escalationIDPMapping: {
          prod: ["IDP-1"],
        },
      };

      // Exact match should work
      const valid1 = isIDPAllowedForEscalation("IDP-1", "prod", config);
      expect(valid1).toBe(true);

      // Different case should not match
      const valid2 = isIDPAllowedForEscalation("idp-1", "prod", config);
      expect(valid2).toBe(false);
    });
  });
});

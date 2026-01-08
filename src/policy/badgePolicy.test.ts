// src/policy/badgePolicy.test.ts
// Unit tests for badge policy

import { describe, it, expect } from "vitest";
import { BadgeTier, deriveBadge, formatBadgeLabel } from "./badgePolicy.js";
import type { ScanResult } from "../core/types.js";
import { getIsoTimestamp } from "../utils/time.js";

function createMockScanResult(
  kind: "coin" | "fa" | "wallet",
  level: number,
  verdict: "pass" | "warn" | "fail",
  riskScore: number,
  severityCounts: { critical: number; high: number; medium: number; low: number; info: number },
  monitoringEnabled: boolean = false
): ScanResult {
  return {
    request_id: "test-id",
    target: {
      address: kind === "wallet" ? "0x123" : "0x456",
      module_name: kind === "wallet" ? "" : "test",
      module_id: kind === "wallet" ? "0x123" : "0x456::test",
      kind,
      chain: "supra",
    } as any,
    scan_level: level === 1 ? "quick" : level === 2 ? "standard" : level === 3 ? "full" : "monitor",
    timestamp_iso: getIsoTimestamp(),
    engine: {
      name: "ssa-scanner",
      version: "0.1.0",
    },
    artifact: {
      artifactOrigin: {
        kind: "supra_rpc_v3",
        path: "test",
      },
    },
    summary: {
      verdict,
      risk_score: riskScore,
      severity_counts: severityCounts,
      badge_eligibility: {
        scanned: true,
        no_critical: severityCounts.critical === 0,
        security_verified: false,
        continuously_monitored: false,
        reasons: [],
        expires_at_iso: undefined,
      },
      capabilities: {
        viewOnly: false,
        hasAbi: false,
        hasBytecodeOrSource: false,
        queue: false,
        userViews: false,
      },
    },
    findings: [],
    meta: {
      scan_options: {},
      rpc_url: "https://rpc.supra.com",
      duration_ms: 0,
      monitoring_enabled: monitoringEnabled,
    } as any,
    scan_level_num: level,
  } as any;
}

describe("BadgePolicy", () => {
  describe("formatBadgeLabel", () => {
    it("should format CONTINUOUSLY_MONITORED correctly", () => {
      expect(formatBadgeLabel(BadgeTier.CONTINUOUSLY_MONITORED)).toBe("SSA · Continuously Monitored");
    });

    it("should format SECURITY_VERIFIED correctly", () => {
      expect(formatBadgeLabel(BadgeTier.SECURITY_VERIFIED)).toBe("SSA · Security Verified");
    });

    it("should format SURFACE_VERIFIED correctly", () => {
      expect(formatBadgeLabel(BadgeTier.SURFACE_VERIFIED)).toBe("SSA · Surface Verified");
    });

    it("should format WALLET_VERIFIED correctly", () => {
      expect(formatBadgeLabel(BadgeTier.WALLET_VERIFIED)).toBe("SSA · Wallet Verified");
    });

    it("should format NONE correctly", () => {
      expect(formatBadgeLabel(BadgeTier.NONE)).toBe("No Badge");
    });
  });

  describe("deriveBadge", () => {
    describe("Coin/FA badges", () => {
      it("should award SURFACE_VERIFIED for level 4 pass with no critical/high findings", () => {
        const result = createMockScanResult("coin", 4, "pass", 15, {
          critical: 0,
          high: 0,
          medium: 2,
          low: 1,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.SURFACE_VERIFIED);
        expect(badge.label).toBe("SSA · Surface Verified");
        expect(badge.expires_at_iso).toBeTruthy();
        expect(badge.continuously_monitored).toBe(false);
      });

      it("should award SECURITY_VERIFIED for level 4 pass with low risk score", () => {
        const result = createMockScanResult("coin", 4, "pass", 8, {
          critical: 0,
          high: 0,
          medium: 1,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.SECURITY_VERIFIED);
        expect(badge.label).toBe("SSA · Security Verified");
        expect(badge.expires_at_iso).toBeTruthy();
        expect(badge.continuously_monitored).toBe(false);
      });

      it("should award CONTINUOUSLY_MONITORED for level 5 pass with monitoring enabled", () => {
        const result = createMockScanResult("fa", 5, "pass", 5, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 1,
          info: 0,
        }, true);

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.CONTINUOUSLY_MONITORED);
        expect(badge.label).toBe("SSA · Continuously Monitored");
        expect(badge.expires_at_iso).toBe(null); // Rolling expiry
        expect(badge.continuously_monitored).toBe(true);
      });

      it("should prioritize CONTINUOUSLY_MONITORED over SECURITY_VERIFIED", () => {
        const result = createMockScanResult("coin", 5, "pass", 5, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        }, true);

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.CONTINUOUSLY_MONITORED);
        expect(badge.continuously_monitored).toBe(true);
      });

      it("should return SURFACE_VERIFIED with warning for level 4 with high finding (Security Verified blocked)", () => {
        const result = createMockScanResult("coin", 4, "pass", 5, {
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        // High findings block Security Verified but allow Surface Verified with warning
        expect(badge.tier).toBe(BadgeTier.SURFACE_VERIFIED);
        expect(badge.reason).toContain("High risk findings detected");
        expect(badge.reason).toContain("Security Verified badge is blocked");
      });

      it("should return NONE for level 4 with critical finding (all badges blocked)", () => {
        const result = createMockScanResult("fa", 4, "pass", 5, {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("Critical risk detected");
        expect(badge.reason).toContain("All verification badges are blocked");
        expect(badge.reason).toContain("Risk states are separate from badges");
      });

      it("should return NONE for fail verdict", () => {
        const result = createMockScanResult("coin", 4, "fail", 60, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("verdict is fail");
      });

      it("should return NONE for level < 4", () => {
        const result = createMockScanResult("coin", 3, "pass", 5, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("below minimum level 4");
      });
    });

    describe("Wallet badges", () => {
      it("should award WALLET_VERIFIED for wallet level 3 pass", () => {
        const result = createMockScanResult("wallet", 3, "pass", 0, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.WALLET_VERIFIED);
        expect(badge.label).toBe("SSA · Wallet Verified");
        expect(badge.expires_at_iso).toBeTruthy();
        expect(badge.continuously_monitored).toBe(false);
      });

      it("should award WALLET_VERIFIED for creator level 2 pass", () => {
        const result = createMockScanResult("wallet", 2, "pass", 0, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });
        (result.target as any).kind = "creator";

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.WALLET_VERIFIED);
      });

      it("should return NONE for wallet with fail verdict", () => {
        const result = createMockScanResult("wallet", 3, "fail", 50, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("requires 'pass'");
      });

      it("should return NONE for wallet with critical finding (Wallet Verified blocked)", () => {
        const result = createMockScanResult("wallet", 3, "pass", 0, {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("Critical risk detected");
        expect(badge.reason).toContain("Wallet Verified badge is blocked");
      });

      it("should return NONE for wallet level > 3", () => {
        const result = createMockScanResult("wallet", 4, "pass", 0, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        const badge = deriveBadge(result);
        expect(badge.tier).toBe(BadgeTier.NONE);
        expect(badge.reason).toContain("levels 1-3 only");
      });
    });

    describe("Configuration", () => {
      it("should respect custom securityVerifiedRiskThreshold", () => {
        const result = createMockScanResult("coin", 4, "pass", 15, {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        });

        // Default threshold (10) - should be SURFACE_VERIFIED
        const badge1 = deriveBadge(result);
        expect(badge1.tier).toBe(BadgeTier.SURFACE_VERIFIED);

        // Custom threshold (20) - should be SECURITY_VERIFIED
        const badge2 = deriveBadge(result, { securityVerifiedRiskThreshold: 20 });
        expect(badge2.tier).toBe(BadgeTier.SECURITY_VERIFIED);
      });
    });
  });
});

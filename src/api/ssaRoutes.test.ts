// src/api/ssaRoutes.test.ts
// Unit tests for SSA API routes

import { describe, it, expect } from "vitest";
import { validateScanRequest, deriveBadgeEligibility } from "./ssaRoutes.js";
import type { ScanResult } from "../core/types.js";
import { getIsoTimestamp } from "../utils/time.js";

describe("SSA Routes", () => {
  describe("validateScanRequest", () => {
    it("should validate coin scan request with valid level", () => {
      const req = {
        targetType: "coin" as const,
        target: "0x123::MODULE::COIN",
        level: 3,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(true);
    });

    it("should reject coin scan with level > 5", () => {
      const req = {
        targetType: "coin" as const,
        target: "0x123::MODULE::COIN",
        level: 6,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("levels 1–5 only");
    });

    it("should reject coin scan with level < 1", () => {
      const req = {
        targetType: "coin" as const,
        target: "0x123::MODULE::COIN",
        level: 0,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("levels 1–5 only");
    });

    it("should validate FA scan request with valid level", () => {
      const req = {
        targetType: "fa" as const,
        target: "0x1234567890abcdef",
        level: 4,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(true);
    });

    it("should reject FA scan with level > 5", () => {
      const req = {
        targetType: "fa" as const,
        target: "0x1234567890abcdef",
        level: 6,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("levels 1–5 only");
    });

    it("should validate wallet scan request with valid level (1-3)", () => {
      const req = {
        targetType: "wallet" as const,
        target: "0x1234567890abcdef",
        level: 2,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(true);
    });

    it("should reject wallet scan with level > 3", () => {
      const req = {
        targetType: "wallet" as const,
        target: "0x1234567890abcdef",
        level: 4,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Wallet scans support levels 1–3 only.");
    });

    it("should reject wallet scan with level < 1", () => {
      const req = {
        targetType: "wallet" as const,
        target: "0x1234567890abcdef",
        level: 0,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Wallet scans support levels 1–3 only.");
    });

    it("should reject invalid targetType", () => {
      const req = {
        targetType: "invalid" as any,
        target: "0x123",
        level: 1,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("targetType must be");
    });

    it("should reject empty target", () => {
      const req = {
        targetType: "coin" as const,
        target: "",
        level: 1,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("target is required");
    });

    it("should reject missing target", () => {
      const req = {
        targetType: "coin" as const,
        target: undefined as any,
        level: 1,
      };
      const result = validateScanRequest(req);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("target is required");
    });
  });

  describe("deriveBadgeEligibility", () => {
    const createMockScanResult = (verdict: string, riskScore: number): ScanResult => ({
      request_id: "test-id",
      target: {
        address: "0x123",
        module_name: "test",
        module_id: "0x123::test",
      },
      scan_level: "quick",
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
        verdict: verdict as any,
        risk_score: riskScore,
        severity_counts: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        },
        badge_eligibility: {
          scanned: true,
          no_critical: true,
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
      },
    });

    it("should set security_verified=true for pass verdict with low risk", () => {
      const scanResult = createMockScanResult("pass", 25);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.security_verified).toBe(true);
      expect(badge.expiresAt).toBeDefined();
    });

    it("should set security_verified=false for pass verdict with high risk", () => {
      const scanResult = createMockScanResult("pass", 35);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.security_verified).toBe(false);
    });

    it("should set security_verified=false for warn verdict", () => {
      const scanResult = createMockScanResult("warn", 25);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.security_verified).toBe(false);
    });

    it("should set security_verified=false for fail verdict", () => {
      const scanResult = createMockScanResult("fail", 25);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.security_verified).toBe(false);
    });

    it("should set continuously_monitored=false by default", () => {
      const scanResult = createMockScanResult("pass", 25);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.continuously_monitored).toBe(false);
    });

    it("should set continuously_monitored=true when explicitly requested", () => {
      const scanResult = createMockScanResult("pass", 25);
      const badge = deriveBadgeEligibility(scanResult, true);
      expect(badge.continuously_monitored).toBe(true);
    });

    it("should include expiresAt in badge eligibility", () => {
      const scanResult = createMockScanResult("pass", 25);
      const badge = deriveBadgeEligibility(scanResult);
      expect(badge.expiresAt).toBeDefined();
      expect(typeof badge.expiresAt).toBe("string");
    });
  });
});

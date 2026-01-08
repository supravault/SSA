import { describe, it, expect } from "vitest";
import {
  calculateRiskScore,
  calculateSeverityCounts,
  determineVerdict,
  calculateBadgeEligibility,
} from "./scoring.js";
import type { Finding, SeverityCounts } from "./types.js";

describe("scoring", () => {
  describe("calculateRiskScore", () => {
    it("should calculate risk score correctly", () => {
      const findings: Finding[] = [
        {
          id: "TEST-001",
          title: "Critical issue",
          severity: "critical",
          confidence: 1.0,
          description: "Test",
          recommendation: "Fix it",
          evidence: { kind: "heuristic", matched: [] },
        },
        {
          id: "TEST-002",
          title: "High issue",
          severity: "high",
          confidence: 1.0,
          description: "Test",
          recommendation: "Fix it",
          evidence: { kind: "heuristic", matched: [] },
        },
        {
          id: "TEST-003",
          title: "Medium issue",
          severity: "medium",
          confidence: 0.5,
          description: "Test",
          recommendation: "Fix it",
          evidence: { kind: "heuristic", matched: [] },
        },
      ];

      // critical=30, high=15, medium=7*0.5=3.5
      // Total = 30 + 15 + 3.5 = 48.5 -> 49
      const score = calculateRiskScore(findings);
      expect(score).toBe(49);
    });

    it("should cap risk score at 100", () => {
      const findings: Finding[] = Array(10).fill(null).map((_, i) => ({
        id: `TEST-${i}`,
        title: "Critical issue",
        severity: "critical" as const,
        confidence: 1.0,
        description: "Test",
        recommendation: "Fix it",
        evidence: { kind: "heuristic" as const, matched: [] },
      }));

      // 10 critical * 30 = 300, should cap at 100
      const score = calculateRiskScore(findings);
      expect(score).toBe(100);
    });

    it("should return 0 for empty findings", () => {
      const score = calculateRiskScore([]);
      expect(score).toBe(0);
    });
  });

  describe("calculateSeverityCounts", () => {
    it("should count severities correctly", () => {
      const findings: Finding[] = [
        { id: "1", title: "C1", severity: "critical", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
        { id: "2", title: "C2", severity: "critical", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
        { id: "3", title: "H1", severity: "high", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
        { id: "4", title: "M1", severity: "medium", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
        { id: "5", title: "L1", severity: "low", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
        { id: "6", title: "I1", severity: "info", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
      ];

      const counts = calculateSeverityCounts(findings);
      expect(counts.critical).toBe(2);
      expect(counts.high).toBe(1);
      expect(counts.medium).toBe(1);
      expect(counts.low).toBe(1);
      expect(counts.info).toBe(1);
    });
  });

  describe("determineVerdict", () => {
    it("should return 'fail' for critical findings", () => {
      const findings: Finding[] = [
        { id: "1", title: "Critical", severity: "critical", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
      ];
      const verdict = determineVerdict(findings, 10);
      expect(verdict).toBe("fail");
    });

    it("should return 'fail' for risk score >= 60", () => {
      const findings: Finding[] = [];
      const verdict = determineVerdict(findings, 60);
      expect(verdict).toBe("fail");
    });

    it("should return 'warn' for high findings", () => {
      const findings: Finding[] = [
        { id: "1", title: "High", severity: "high", confidence: 1, description: "", recommendation: "", evidence: { kind: "heuristic", matched: [] } },
      ];
      const verdict = determineVerdict(findings, 20);
      expect(verdict).toBe("warn");
    });

    it("should return 'warn' for risk score 25-59", () => {
      const findings: Finding[] = [];
      const verdict = determineVerdict(findings, 30);
      expect(verdict).toBe("warn");
    });

    it("should return 'pass' for low risk", () => {
      const findings: Finding[] = [];
      const verdict = determineVerdict(findings, 10);
      expect(verdict).toBe("pass");
    });
  });

  describe("calculateBadgeEligibility", () => {
    it("should calculate eligibility correctly for quick scan", () => {
      const timestamp = "2024-01-01T00:00:00.000Z";
      const severityCounts: SeverityCounts = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 1,
        info: 0,
      };

      const eligibility = calculateBadgeEligibility("quick", "abc123", severityCounts, timestamp, false);

      expect(eligibility.scanned).toBe(true);
      expect(eligibility.no_critical).toBe(true);
      expect(eligibility.security_verified).toBe(false); // No bytecode/source
      expect(eligibility.continuously_monitored).toBe(false);
      expect(eligibility.reasons).toContain("Security Verified badge requires bytecode or source code analysis");
      expect(eligibility.expires_at_iso).toBeDefined();
    });

    it("should mark as ineligible if critical findings exist", () => {
      const timestamp = "2024-01-01T00:00:00.000Z";
      const severityCounts: SeverityCounts = {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const eligibility = calculateBadgeEligibility("quick", "abc123", severityCounts, timestamp, false);

      expect(eligibility.no_critical).toBe(false);
      expect(eligibility.reasons).toContain("Found 1 critical severity finding(s)");
    });

    it("should mark as ineligible if no artifact hash", () => {
      const timestamp = "2024-01-01T00:00:00.000Z";
      const severityCounts: SeverityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const eligibility = calculateBadgeEligibility("quick", null, severityCounts, timestamp, false);

      expect(eligibility.scanned).toBe(false);
      expect(eligibility.reasons).toContain("Scan did not complete successfully or artifact hash unavailable");
    });
  });
});


import type { Finding, SeverityCounts, Verdict, BadgeEligibility } from "./types.js";
import { getIsoTimestamp, addDays } from "../utils/time.js";

/**
 * Calculate risk score from findings
 * Base risk_score = sum weights by severity:
 * critical=30, high=15, medium=7, low=1, info=0
 * Each finding contributes: weight * confidence
 * Round to nearest int and cap at 100.
 */
export function calculateRiskScore(findings: Finding[]): number {
  const weights: Record<string, number> = {
    critical: 30,
    high: 15,
    medium: 7,
    low: 1,
    info: 0,
  };

  let totalScore = 0;

  for (const finding of findings) {
    const weight = weights[finding.severity] || 0;
    totalScore += weight * finding.confidence;
  }

  return Math.min(100, Math.round(totalScore));
}

/**
 * Calculate severity counts
 */
export function calculateSeverityCounts(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}

/**
 * Determine verdict from findings and risk score
 * Verdict logic:
 * - If any critical finding exists => "fail"
 * - Else if riskScore >= 60 => "fail"
 * - Else if any high finding exists => "warn"
 * - Else if riskScore between 25-59 => "warn"
 * - Else => "pass"
 * 
 * Note: "inconclusive" is only returned when findings.length === 0 AND evidence is insufficient
 * (handled by caller, not this function)
 */
export function determineVerdict(findings: Finding[], riskScore: number): Verdict {
  // Check for any critical findings
  const hasCritical = findings.some((f) => f.severity === "critical");
  if (hasCritical) {
    return "fail";
  }

  // Check risk score threshold
  if (riskScore >= 60) {
    return "fail";
  }

  // Check for any high findings
  const hasHigh = findings.some((f) => f.severity === "high");
  if (hasHigh) {
    return "warn";
  }

  // Check risk score range for warn
  if (riskScore >= 25 && riskScore < 60) {
    return "warn";
  }

  // Default to pass
  return "pass";
}

/**
 * Calculate badge eligibility
 * Security Verified requirements:
 * - hasBytecodeOrSource: true (bytecode or source code must be available)
 * - no high/critical findings: severityCounts.high === 0 && severityCounts.critical === 0
 * - scanned: true (artifact hash exists)
 * 
 * Metadata-only scans (view-only) can never achieve Security Verified status
 */
export function calculateBadgeEligibility(
  scanLevel: string,
  artifactHash: string | null,
  severityCounts: SeverityCounts,
  timestamp: string,
  hasBytecodeOrSource: boolean = false
): BadgeEligibility {
  const scanned = !!artifactHash;
  const noCritical = severityCounts.critical === 0;
  const noHigh = severityCounts.high === 0;
  
  // Security Verified requires bytecode/source AND no high/critical findings
  const securityVerified = hasBytecodeOrSource && noCritical && noHigh && scanned;
  const continuouslyMonitored = false; // Always false for quick scans

  const reasons: string[] = [];
  const expires: { [key: string]: string } = {};

  if (!scanned) {
    reasons.push("Scan did not complete successfully or artifact hash unavailable");
  } else {
    expires.scanned = addDays(timestamp, 30);
  }

  if (!noCritical) {
    reasons.push(`Found ${severityCounts.critical} critical severity finding(s)`);
  } else {
    expires.no_critical = addDays(timestamp, 14);
  }

  if (!securityVerified) {
    if (!hasBytecodeOrSource) {
      reasons.push("Security Verified badge requires bytecode or source code analysis");
    } else if (!noHigh) {
      reasons.push(`Found ${severityCounts.high} high severity finding(s)`);
    } else if (!noCritical) {
      reasons.push(`Found ${severityCounts.critical} critical severity finding(s)`);
    } else {
      reasons.push("Full scan required for security verification badge");
    }
  } else {
    expires.security_verified = addDays(timestamp, 14);
  }

  if (!continuouslyMonitored) {
    reasons.push("Continuous monitoring not enabled");
  }

  // If all conditions met, set expiry to earliest
  let expiresAt: string | undefined;
  if (scanned && noCritical && securityVerified && continuouslyMonitored) {
    expiresAt = expires.security_verified || expires.no_critical || expires.scanned;
  } else if (scanned && noCritical) {
    expiresAt = expires.no_critical;
  } else if (scanned) {
    expiresAt = expires.scanned;
  }

  return {
    scanned,
    no_critical: noCritical,
    security_verified: securityVerified,
    continuously_monitored: continuouslyMonitored,
    reasons,
    expires_at_iso: expiresAt,
  };
}


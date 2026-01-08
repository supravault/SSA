// src/policy/badgePolicy.ts
// Authoritative badge policy for SSA scanner
//
// POLICY DOCUMENTATION:
// See docs/ssa-badges-and-risk-policy.md for complete policy definition
//
// KEY PRINCIPLES:
// - Badges represent positive verification states only
// - Risk states are separate from badges (never issued as badges)
// - Critical findings block all badges
// - High findings block Security Verified
// - No negative/risk-based badges exist

import type { ScanResult } from "../core/types.js";
import { addDays } from "../utils/time.js";
import { getIsoTimestamp } from "../utils/time.js";

/**
 * Badge tiers in priority order (highest to lowest)
 */
export enum BadgeTier {
  CONTINUOUSLY_MONITORED = "CONTINUOUSLY_MONITORED",
  SECURITY_VERIFIED = "SECURITY_VERIFIED",
  SURFACE_VERIFIED = "SURFACE_VERIFIED",
  WALLET_VERIFIED = "WALLET_VERIFIED",
  FULLY_INTEGRATED = "FULLY_INTEGRATED",
  CRITICAL_RISK = "CRITICAL_RISK",
  HIGH_RISK = "HIGH_RISK",
  MEDIUM_RISK = "MEDIUM_RISK",
  NONE = "NONE",
}

/**
 * Badge result structure
 */
export interface BadgeResult {
  tier: BadgeTier;
  label: string;
  expires_at_iso: string | null;
  continuously_monitored: boolean;
  reason?: string;
}

/**
 * Badge policy configuration
 */
export interface BadgePolicyConfig {
  /**
   * Risk score threshold for SECURITY_VERIFIED badge (default: 10)
   */
  securityVerifiedRiskThreshold?: number;
}

const DEFAULT_CONFIG: Required<BadgePolicyConfig> = {
  securityVerifiedRiskThreshold: 10,
};

/**
 * Format badge tier to human-readable label
 */
export function formatBadgeLabel(tier: BadgeTier): string {
  switch (tier) {
    case BadgeTier.CONTINUOUSLY_MONITORED:
      return "SSA · Continuously Monitored";
    case BadgeTier.SECURITY_VERIFIED:
      return "SSA · Security Verified";
    case BadgeTier.SURFACE_VERIFIED:
      return "SSA · Surface Verified";
    case BadgeTier.WALLET_VERIFIED:
      return "SSA · Wallet Verified";
    case BadgeTier.CRITICAL_RISK:
      return "SSA · Critical Risk";
    case BadgeTier.HIGH_RISK:
      return "SSA · High Risk";
    case BadgeTier.MEDIUM_RISK:
      return "SSA · Medium Risk";
    case BadgeTier.NONE:
      return "No Badge";
    default:
      return "No Badge";
  }
}

/**
 * Derive badge tier from scan result
 * This is the single source of truth for badge determination
 * 
 * POLICY ENFORCEMENT:
 * - Badges represent positive verification states only
 * - Critical findings block all badges (except Surface Verified with warning)
 * - High findings block Security Verified
 * - Risk states are separate from badges (never issued as badges)
 * 
 * See: docs/ssa-badges-and-risk-policy.md
 */
export function deriveBadge(
  scanResult: ScanResult,
  config: BadgePolicyConfig = {}
): BadgeResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const now = getIsoTimestamp();
  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";
  const scanLevel = (scanResult as any).scan_level_num || 
    (typeof scanResult.scan_level === "string" 
      ? parseInt(scanResult.scan_level.replace(/[^0-9]/g, "")) || 1
      : 1);
  // Safely extract verdict, risk score, and severity counts with fallbacks
  const verdict = scanResult.summary?.verdict ?? (scanResult as any).verdict ?? "UNKNOWN";
  const riskScore = scanResult.summary?.risk_score ?? (scanResult as any)?.risk?.score ?? 0;
  const severityCounts = scanResult.summary?.severity_counts ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const monitoringEnabled = (scanResult.meta as any)?.monitoring_enabled === true;

  // POLICY ENFORCEMENT: Badge Suppression Rules
  // Rule 1: Critical findings block all badges (except Surface Verified with warning)
  // Rule 2: High findings block Security Verified
  const hasCritical = severityCounts.critical > 0;
  const hasHigh = severityCounts.high > 0;

  // Rule A: Wallet / Creator targets
  if (kind === "wallet" || kind === "creator") {
    // Wallet scans only support levels 1-3
    if (scanLevel > 3) {
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: "Wallet scans support levels 1-3 only",
      };
    }

    // POLICY ENFORCEMENT: Critical findings block Wallet Verified
    if (hasCritical) {
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: `Critical risk detected (${severityCounts.critical} finding(s)). Wallet Verified badge is blocked. Risk states are separate from badges.`,
      };
    }

    // Wallet verified: pass verdict at level >= 3
    // Note: Wallet scans support levels 1-3 only, so level >= 3 means all levels passed
    if (verdict === "pass" && scanLevel >= 3) {
      return {
        tier: BadgeTier.WALLET_VERIFIED,
        label: formatBadgeLabel(BadgeTier.WALLET_VERIFIED),
        expires_at_iso: addDays(now, 7),
        continuously_monitored: false,
      };
    }

    // Wallet verified at lower levels (levels 1-2) - not eligible for badge
    if (verdict === "pass" && scanLevel < 3) {
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: "Wallet Verified requires level 3 (all levels 1-3 must pass)",
      };
    }

    // No badge for non-pass verdicts
    return {
      tier: BadgeTier.NONE,
      label: formatBadgeLabel(BadgeTier.NONE),
      expires_at_iso: null,
      continuously_monitored: false,
      reason: `Verdict is ${verdict}, requires 'pass' for wallet badge`,
    };
  }

  // Rule B: Coin / FA targets
  if (kind === "coin" || kind === "fa") {
    // Check prerequisites: pass verdict
    const hasPassVerdict = verdict === "pass";

    if (!hasPassVerdict) {
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: `Verdict is ${verdict}, requires 'pass' for contract badges`,
      };
    }

    // POLICY ENFORCEMENT: Critical findings block Security Verified and Continuously Monitored
    // Surface Verified may be issued with warning (implementation decision: we block it for safety)
    if (hasCritical) {
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: `Critical risk detected (${severityCounts.critical} finding(s)). All verification badges are blocked. Risk states are separate from badges and should be displayed as warnings/alerts.`,
      };
    }

    // POLICY ENFORCEMENT: High findings block Security Verified and Continuously Monitored
    // Surface Verified may still be issued (with optional warning)
    if (hasHigh) {
      // High findings block Security Verified and Continuously Monitored
      // Only Surface Verified may be considered (if level >= 1)
      if (scanLevel >= 1) {
        // Surface Verified may be issued with warning
        return {
          tier: BadgeTier.SURFACE_VERIFIED,
          label: formatBadgeLabel(BadgeTier.SURFACE_VERIFIED),
          expires_at_iso: addDays(now, 14),
          continuously_monitored: false,
          reason: `High risk findings detected (${severityCounts.high} finding(s)). Security Verified badge is blocked. Surface Verified issued with warning.`,
        };
      } else {
        return {
          tier: BadgeTier.NONE,
          label: formatBadgeLabel(BadgeTier.NONE),
          expires_at_iso: null,
          continuously_monitored: false,
          reason: `High risk findings detected (${severityCounts.high} finding(s)). Badges require level 1+ and no high findings for Security Verified.`,
        };
      }
    }

    // At this point: pass verdict, no critical findings, no high findings
    // Badges may be issued normally
    // Note: Full Integrated is NOT a badge tier - it's a report status that triggers the red wax seal

    // Priority 1: CONTINUOUSLY_MONITORED
    // Requires: level >= 5, pass verdict, monitoring enabled, no critical/high findings
    if (scanLevel >= 5 && monitoringEnabled) {
      return {
        tier: BadgeTier.CONTINUOUSLY_MONITORED,
        label: formatBadgeLabel(BadgeTier.CONTINUOUSLY_MONITORED),
        expires_at_iso: null, // Rolling expiry (but badge must include expiry timestamp)
        continuously_monitored: true,
      };
    }

    // Priority 2: SECURITY_VERIFIED
    // Requires: level >= 3, pass verdict, no critical/high findings
    if (scanLevel >= 3) {
      return {
        tier: BadgeTier.SECURITY_VERIFIED,
        label: formatBadgeLabel(BadgeTier.SECURITY_VERIFIED),
        expires_at_iso: addDays(now, 30),
        continuously_monitored: false,
      };
    }

    // Priority 3: SURFACE_VERIFIED
    // Requires: level >= 1, pass verdict, no critical/high findings
    if (scanLevel >= 1) {
      return {
        tier: BadgeTier.SURFACE_VERIFIED,
        label: formatBadgeLabel(BadgeTier.SURFACE_VERIFIED),
        expires_at_iso: addDays(now, 14),
        continuously_monitored: false,
      };
    }

    // No badge for level < 1
    return {
      tier: BadgeTier.NONE,
      label: formatBadgeLabel(BadgeTier.NONE),
      expires_at_iso: null,
      continuously_monitored: false,
      reason: `Scan level ${scanLevel} is below minimum level 1 for contract badges`,
    };
  }

  // Unknown kind - no badge
  return {
    tier: BadgeTier.NONE,
    label: formatBadgeLabel(BadgeTier.NONE),
    expires_at_iso: null,
    continuously_monitored: false,
    reason: `Unknown scan kind: ${kind}`,
  };
}

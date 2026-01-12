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
export function deriveBadge(scanResult: ScanResult, config: BadgePolicyConfig = {}): BadgeResult {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const now = getIsoTimestamp();
  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";

  const scanLevel =
    (scanResult as any).scan_level_num ||
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

  // ✅ Monitoring gate (customer-defensible):
  // - meta.monitoring_enabled is the canonical boolean for issuance
  // - meta.monitoring.monitoring_active is accepted as a compatible alias
  const metaAny = (scanResult.meta as any) || {};
  const monitoringEnabled =
    metaAny.monitoring_enabled === true || metaAny?.monitoring?.monitoring_active === true;

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
    if (hasHigh) {
      if (scanLevel >= 1) {
        return {
          tier: BadgeTier.SURFACE_VERIFIED,
          label: formatBadgeLabel(BadgeTier.SURFACE_VERIFIED),
          expires_at_iso: addDays(now, 14),
          continuously_monitored: false,
          reason: `High risk findings detected (${severityCounts.high} finding(s)). Security Verified badge is blocked. Surface Verified issued with warning.`,
        };
      }
      return {
        tier: BadgeTier.NONE,
        label: formatBadgeLabel(BadgeTier.NONE),
        expires_at_iso: null,
        continuously_monitored: false,
        reason: `High risk findings detected (${severityCounts.high} finding(s)). Badges require level 1+ and no high findings for Security Verified.`,
      };
    }

    // Priority 1: CONTINUOUSLY_MONITORED
    // Requires: level >= 5, pass verdict, monitoring enabled, no critical/high findings
    if (scanLevel >= 5 && monitoringEnabled) {
      return {
        tier: BadgeTier.CONTINUOUSLY_MONITORED,
        label: formatBadgeLabel(BadgeTier.CONTINUOUSLY_MONITORED),
        // ✅ rolling expiry (customer-defensible); can later be tied to cadence if desired
        expires_at_iso: addDays(now, 7),
        continuously_monitored: true,
      };
    }

    // Optional: if level >= 5 but monitoring not enabled, be explicit (helps support tickets)
    if (scanLevel >= 5 && !monitoringEnabled) {
      // fall through to Security Verified, but include a reason only if you want to surface it
      // (we keep normal badge behavior: Security Verified for L5 pass)
    }

    // Priority 2: SECURITY_VERIFIED
    if (scanLevel >= 3) {
      return {
        tier: BadgeTier.SECURITY_VERIFIED,
        label: formatBadgeLabel(BadgeTier.SECURITY_VERIFIED),
        expires_at_iso: addDays(now, 30),
        continuously_monitored: false,
      };
    }

    // Priority 3: SURFACE_VERIFIED
    if (scanLevel >= 1) {
      return {
        tier: BadgeTier.SURFACE_VERIFIED,
        label: formatBadgeLabel(BadgeTier.SURFACE_VERIFIED),
        expires_at_iso: addDays(now, 14),
        continuously_monitored: false,
      };
    }

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



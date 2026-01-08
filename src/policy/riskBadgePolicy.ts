// src/policy/riskBadgePolicy.ts
// Risk badge policy (separate from positive badges)

import type { ScanResult } from "../core/types.js";
import { BadgeTier, formatBadgeLabel, type BadgeResult } from "./badgePolicy.js";

/**
 * Derive risk badge from scan result
 * Risk badges indicate security concerns, not positive verification
 */
export function deriveRiskBadge(scanResult: ScanResult): BadgeResult | null {
  // Safely extract severity counts with fallbacks
  const severityCounts = scanResult.summary?.severity_counts ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";

  // Critical Risk badge
  if (severityCounts.critical > 0) {
    return {
      tier: BadgeTier.CRITICAL_RISK,
      label: formatBadgeLabel(BadgeTier.CRITICAL_RISK),
      expires_at_iso: null,
      continuously_monitored: false,
      reason: `${severityCounts.critical} critical finding(s) detected`,
    };
  }

  // High Risk badge
  if (severityCounts.high > 0) {
    return {
      tier: BadgeTier.HIGH_RISK,
      label: formatBadgeLabel(BadgeTier.HIGH_RISK),
      expires_at_iso: null,
      continuously_monitored: false,
      reason: `${severityCounts.high} high finding(s) detected`,
    };
  }

  // Medium Risk badge (optional)
  if (severityCounts.medium > 0 && severityCounts.critical === 0 && severityCounts.high === 0) {
    return {
      tier: BadgeTier.MEDIUM_RISK,
      label: formatBadgeLabel(BadgeTier.MEDIUM_RISK),
      expires_at_iso: null,
      continuously_monitored: false,
      reason: `${severityCounts.medium} medium finding(s) detected`,
    };
  }

  return null;
}

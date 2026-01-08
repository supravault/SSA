// src/policy/riskStates.ts
// Risk state definitions (separate from badges)
//
// POLICY DOCUMENTATION:
// See docs/ssa-badges-and-risk-policy.md for complete policy definition
//
// KEY PRINCIPLES:
// - Risk states are NOT badges
// - Risk states represent security findings/warnings
// - Risk states use alert/banner visuals (not shield badges)
// - Risk states are never cryptographically signed as badges

/**
 * Risk state severity levels
 * These are NOT badges - they represent security findings/warnings
 */
export enum RiskState {
  INFO = "INFO",
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

/**
 * Risk state display information
 */
export interface RiskStateInfo {
  state: RiskState;
  label: string;
  icon: string;
  color: string;
  description: string;
}

/**
 * Get risk state information for display
 */
export function getRiskStateInfo(state: RiskState): RiskStateInfo {
  switch (state) {
    case RiskState.INFO:
      return {
        state: RiskState.INFO,
        label: "Info",
        icon: "ℹ️",
        color: "blue",
        description: "Informational findings, no immediate security concern",
      };
    case RiskState.LOW:
      return {
        state: RiskState.LOW,
        label: "Low Risk",
        icon: "⚠️",
        color: "yellow",
        description: "Minor security concerns, best practices not followed",
      };
    case RiskState.MEDIUM:
      return {
        state: RiskState.MEDIUM,
        label: "Medium Risk",
        icon: "⚠️",
        color: "orange",
        description: "Moderate security concerns, potential vulnerabilities",
      };
    case RiskState.HIGH:
      return {
        state: RiskState.HIGH,
        label: "High Risk",
        icon: "⚠️",
        color: "red",
        description: "Significant security concerns, active vulnerabilities",
      };
    case RiskState.CRITICAL:
      return {
        state: RiskState.CRITICAL,
        label: "Critical Risk",
        icon: "⛔",
        color: "darkred",
        description: "Severe security concerns, immediate threats",
      };
    default:
      return {
        state: RiskState.INFO,
        label: "Unknown",
        icon: "❓",
        color: "gray",
        description: "Unknown risk state",
      };
  }
}

/**
 * Determine overall risk state from severity counts
 * Returns the highest severity level present
 */
export function determineOverallRiskState(severityCounts: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}): RiskState {
  if (severityCounts.critical > 0) {
    return RiskState.CRITICAL;
  }
  if (severityCounts.high > 0) {
    return RiskState.HIGH;
  }
  if (severityCounts.medium > 0) {
    return RiskState.MEDIUM;
  }
  if (severityCounts.low > 0) {
    return RiskState.LOW;
  }
  if (severityCounts.info > 0) {
    return RiskState.INFO;
  }
  return RiskState.INFO; // Default to info if no findings
}

/**
 * Check if risk state should block badges
 * Returns true if risk state is high enough to block badge issuance
 */
export function shouldBlockBadges(riskState: RiskState): boolean {
  return riskState === RiskState.CRITICAL || riskState === RiskState.HIGH;
}

/**
 * Get suppression reason for badge blocking
 */
export function getSuppressionReason(severityCounts: {
  critical: number;
  high: number;
}): string | null {
  if (severityCounts.critical > 0) {
    return `Critical risk detected (${severityCounts.critical} finding(s)). Verification badges are blocked. Risk states are separate from badges and should be displayed as warnings/alerts.`;
  }
  if (severityCounts.high > 0) {
    return `High risk detected (${severityCounts.high} finding(s)). Security Verified badge is blocked.`;
  }
  return null;
}

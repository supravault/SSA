// src/analyzers/shared/invariants.ts

export type InvariantStatus = "ok" | "warning" | "violation" | "unknown";

export interface InvariantItem {
  id: string;
  status: InvariantStatus;
  title: string;
  detail: string;
  evidence?: any;
}

export interface InvariantReport {
  items: InvariantItem[];
  overall: InvariantStatus;
}

/**
 * COIN invariant IDs
 */
export const COIN_INVARIANTS = {
  SUPPLY_KNOWN: "COIN_SUPPLY_KNOWN",
  MINT_CAP_PRESENT: "COIN_MINT_CAP_PRESENT",
  MINT_REACHABLE_WITH_CAP: "COIN_MINT_REACHABLE_WITH_CAP",
  FREEZE_REACHABLE: "COIN_FREEZE_REACHABLE",
} as const;

/**
 * FA invariant IDs
 */
export const FA_INVARIANTS = {
  OWNER_KNOWN: "FA_OWNER_KNOWN",
  OWNER_STABILITY_SIGNAL: "FA_OWNER_STABILITY_SIGNAL",
  HAS_WITHDRAW_HOOK: "FA_HAS_WITHDRAW_HOOK",
  UNKNOWN_HOOK_MODULE: "FA_UNKNOWN_HOOK_MODULE",
  MAX_SUPPLY_PRESENT: "FA_MAX_SUPPLY_PRESENT",
  MAX_SUPPLY_EXCEEDED: "FA_MAX_SUPPLY_EXCEEDED",
} as const;

/**
 * Calculate overall invariant status from items
 */
export function calculateOverallInvariantStatus(items: InvariantItem[]): InvariantStatus {
  if (items.length === 0) {
    return "unknown";
  }

  const hasViolation = items.some((item) => item.status === "violation");
  if (hasViolation) {
    return "violation";
  }

  const hasWarning = items.some((item) => item.status === "warning");
  if (hasWarning) {
    return "warning";
  }

  const allOk = items.every((item) => item.status === "ok");
  if (allOk) {
    return "ok";
  }

  return "unknown";
}

/**
 * Create an empty invariant report
 */
export function createEmptyInvariantReport(): InvariantReport {
  return {
    items: [],
    overall: "unknown",
  };
}


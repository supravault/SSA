// src/agent/risk.ts
// Level 3 Risk Synthesis: Convert evidence into agent-grade signals and verdict

import type { BehaviorEvidence } from "./txBehavior.js";

/**
 * Risk signal identifiers - stable strings for agent consumption
 */
export type RiskSignal =
  | "HASH_PINNED"
  | "HASH_CONFLICT"
  | "HASH_UNAVAILABLE"
  | "INDEXER_CORROBORATED"
  | "INDEXER_CONFLICT"
  | "INDEXER_UNSUPPORTED"
  | "INDEXER_NOT_REQUESTED"
  | "BEHAVIOR_MATCHED"
  | "BEHAVIOR_NO_ACTIVITY"
  | "BEHAVIOR_UNAVAILABLE"
  | "ABI_OPAQUE"
  | "ABI_OPAQUE_ACTIVE"
  | "PHANTOM_ENTRYPOINTS"
  | "HOOK_CONTROLLED"
  | "HOOK_UNVERIFIED"
  | "PRIVILEGE_UNVERIFIED"
  | "PRIVILEGE_ESCALATION_POSSIBLE"
  | "MULTI_RPC_CONFIRMED"
  | "MULTI_RPC_CONFLICT"
  | "SUPPLY_CONFLICT"
  | "OWNER_CONFLICT"
  | "CAPS_CONFLICT"
  | "MINT_REACHABLE"
  | "BURN_REACHABLE"
  | "ADMIN_REACHABLE";

/**
 * Risk level classification
 */
export type RiskLevel =
  | "SAFE_STATIC"
  | "SAFE_DYNAMIC"
  | "OPAQUE_BUT_ACTIVE"
  | "ELEVATED_RISK"
  | "DANGEROUS";

/**
 * Risk synthesis result
 */
export interface RiskSynthesis {
  signals: RiskSignal[];
  risk_level: RiskLevel;
  rationale: string[];
}

/**
 * Input for risk synthesis - matches VerificationReport structure
 */
export interface RiskInput {
  target: {
    kind: "fa" | "coin";
    id: string;
  };
  overallEvidenceTier: "view_only" | "multi_rpc_confirmed" | "multi_rpc_plus_indexer" | "multi_source_confirmed";
  status?: "CONFLICT" | "OK" | "INVALID_ARGS";
  discrepancies: Array<{
    claimType: string;
    detail?: string;
    sources?: string[];
    values?: Record<string, any>;
  }>;
  claims: Array<{
    claimType: string;
    status: "CONFIRMED" | "CONFLICT" | "PARTIAL" | "UNAVAILABLE";
    confidence: "HIGH" | "MEDIUM" | "LOW";
  }>;
  suprascan_fa?: {
    status: "supported" | "partial" | "partial_ok" | "unsupported" | "unsupported_schema" | "error" | "not_requested";
    ok?: boolean;
    urlUsed?: string;
    evidence?: any;
    reason?: string;
    diagnostics?: {
      httpStatus?: number;
      topLevelKeys?: string[];
      jsonPreview?: string;
      rawPath?: string;
    };
  };
  parity?: {
    owner?: "match" | "mismatch" | "unknown";
    supply?: "match" | "mismatch" | "unknown";
    supplyMax?: "match" | "mismatch" | "unknown";
    hooks?: "match" | "mismatch" | "unknown";
  };
  indexer_parity?: {
    status: "supported" | "partial" | "unsupported" | "unsupported_schema" | "error" | "not_requested";
    reason?: string;
    fieldsCompared?: string[];
    evidenceTierImpact: "multi_rpc" | "multi_rpc_plus_indexer";
  };
  behavior?: BehaviorEvidence;
  // Optional surface scan data (from snapshot if available)
  surfaceScan?: {
    hasOpaqueAbi?: boolean;
    hookControlled?: boolean;
    mintReachable?: boolean;
    burnReachable?: boolean;
    adminReachable?: boolean;
    privilegeUnverified?: boolean;
  };
}

/**
 * Synthesize risk signals and verdict from verification evidence
 */
export function synthesizeRisk(input: RiskInput): RiskSynthesis {
  const signals: RiskSignal[] = [];
  const rationale: string[] = [];

  // === Hash Pinning Signals ===
  const hashClaim = input.claims.find(c => 
    c.claimType === "HOOK_MODULE_HASHES" || c.claimType === "MODULE_HASHES"
  );
  if (hashClaim) {
    if (hashClaim.status === "CONFIRMED" && hashClaim.confidence === "HIGH") {
      signals.push("HASH_PINNED");
    } else if (hashClaim.status === "CONFLICT") {
      signals.push("HASH_CONFLICT");
    } else if (hashClaim.status === "UNAVAILABLE") {
      signals.push("HASH_UNAVAILABLE");
    }
  }

  // === Multi-RPC Signals ===
  if (input.overallEvidenceTier === "multi_rpc_confirmed" || input.overallEvidenceTier === "multi_rpc_plus_indexer") {
    if (input.status === "CONFLICT") {
      signals.push("MULTI_RPC_CONFLICT");
      rationale.push("Multi-RPC sources returned conflicting data.");
    } else {
      signals.push("MULTI_RPC_CONFIRMED");
    }
  }

  // === Indexer Signals ===
  if (input.target.kind === "fa") {
    if (input.indexer_parity) {
      if (input.indexer_parity.status === "supported") {
        // Check parity results - only add INDEXER_NOT_REQUESTED if suprascan_fa.ok is false
        // If suprascan is ok (even if parity has mismatches), do NOT add INDEXER_NOT_REQUESTED
        const suprascanOk = (input as any).suprascan_fa?.ok === true;
        
        // Check parity results
        const parityConflict = input.parity && (
          input.parity.owner === "mismatch" ||
          input.parity.supply === "mismatch" ||
          input.parity.hooks === "mismatch"
        );
        if (parityConflict) {
          signals.push("INDEXER_CONFLICT");
          rationale.push("Indexer data conflicts with RPC data.");
        } else {
          signals.push("INDEXER_CORROBORATED");
        }
        
        // Do NOT add INDEXER_NOT_REQUESTED if suprascan is ok
      } else if (input.indexer_parity.status === "unsupported") {
        signals.push("INDEXER_UNSUPPORTED");
        rationale.push("Indexer does not support this FA object.");
      } else if (input.indexer_parity.status === "not_requested") {
        signals.push("INDEXER_NOT_REQUESTED");
      } else if (input.indexer_parity.status === "error") {
        signals.push("INDEXER_UNSUPPORTED");
        rationale.push("Indexer query failed.");
      }
    }
  }

  // === Discrepancy-based Signals ===
  for (const disc of input.discrepancies) {
    if (disc.claimType === "SUPPLY") {
      signals.push("SUPPLY_CONFLICT");
      rationale.push("Supply values conflict across sources.");
    } else if (disc.claimType === "OWNER") {
      signals.push("OWNER_CONFLICT");
      rationale.push("Owner values conflict across sources.");
    } else if (disc.claimType === "CAPS") {
      signals.push("CAPS_CONFLICT");
      rationale.push("Capability flags conflict across sources.");
    }
  }

  // === Behavior Evidence Signals ===
  if (input.behavior) {
    if (input.behavior.status === "sampled") {
      if (input.behavior.phantom_entries.length > 0) {
        signals.push("PHANTOM_ENTRYPOINTS");
        rationale.push(`${input.behavior.phantom_entries.length} phantom entry point(s) invoked but not in ABI.`);
      } else if (input.behavior.invoked_entries.length > 0) {
        signals.push("BEHAVIOR_MATCHED");
      } else {
        signals.push("BEHAVIOR_NO_ACTIVITY");
      }

      if (input.behavior.opaque_active) {
        signals.push("ABI_OPAQUE_ACTIVE");
        rationale.push("ABI is opaque but transaction activity exists.");
      }
    } else if (input.behavior.status === "no_activity") {
      signals.push("BEHAVIOR_NO_ACTIVITY");
    } else if (input.behavior.status === "ok_empty") {
      // ok_empty means endpoint succeeded but no transactions - not unavailable
      // Don't add BEHAVIOR_UNAVAILABLE signal
    } else if (input.behavior.status === "unavailable" || input.behavior.status === "error") {
      signals.push("BEHAVIOR_UNAVAILABLE");
    }
  }

  // === Surface Scan Signals (if available) ===
  if (input.surfaceScan) {
    if (input.surfaceScan.hasOpaqueAbi && !signals.includes("ABI_OPAQUE_ACTIVE")) {
      signals.push("ABI_OPAQUE");
    }
    if (input.surfaceScan.hookControlled) {
      signals.push("HOOK_CONTROLLED");
    }
    if (input.surfaceScan.mintReachable) {
      signals.push("MINT_REACHABLE");
      rationale.push("Public mint entry point detected.");
    }
    if (input.surfaceScan.burnReachable) {
      signals.push("BURN_REACHABLE");
      rationale.push("Public burn entry point detected.");
    }
    if (input.surfaceScan.adminReachable) {
      signals.push("ADMIN_REACHABLE");
      rationale.push("Public admin entry point detected.");
    }
    if (input.surfaceScan.privilegeUnverified) {
      signals.push("PRIVILEGE_UNVERIFIED");
      rationale.push("Privilege model could not be fully verified.");
    }
  }

  // Check for hook-controlled from claims
  const hooksClaim = input.claims.find(c => c.claimType === "HOOKS");
  if (hooksClaim && hooksClaim.status === "CONFIRMED") {
    if (!signals.includes("HOOK_CONTROLLED")) {
      // Check if hooks are actually present (non-empty)
      // This is a heuristic - if HOOKS claim exists and is confirmed, hooks are present
      signals.push("HOOK_CONTROLLED");
    }
  }

  // === Determine Risk Level ===
  const riskLevel = determineRiskLevel(signals, input);
  
  // Add risk level rationale
  rationale.push(`Risk level: ${riskLevel}`);

  // Deduplicate signals
  const uniqueSignals = [...new Set(signals)] as RiskSignal[];
  
  // Sort signals for deterministic output
  uniqueSignals.sort();

  return {
    signals: uniqueSignals,
    risk_level: riskLevel,
    rationale,
  };
}

/**
 * Determine risk level from signals and input
 */
function determineRiskLevel(signals: RiskSignal[], input: RiskInput): RiskLevel {
  // DANGEROUS: phantom entrypoints or direct evidence of privileged ops
  if (signals.includes("PHANTOM_ENTRYPOINTS")) {
    return "DANGEROUS";
  }

  // Check for privileged operations in behavior (mint/burn/admin in tx sample)
  if (input.behavior?.status === "sampled" && input.behavior.invoked_entries.length > 0) {
    const privilegedPatterns = /mint|burn|admin|upgrade|set_owner|transfer_ownership|freeze|pause/i;
    for (const entry of input.behavior.invoked_entries) {
      if (privilegedPatterns.test(entry.functionName)) {
        // Only dangerous if we can't verify it's in the ABI
        if (input.behavior.phantom_entries.some(p => p.fullId === entry.fullId)) {
          return "DANGEROUS";
        }
      }
    }
  }

  // ELEVATED_RISK: conflicts, or hook-controlled + unverified privileges, or behavior unavailable + opaque ABI
  if (
    signals.includes("MULTI_RPC_CONFLICT") ||
    signals.includes("HASH_CONFLICT") ||
    signals.includes("INDEXER_CONFLICT") ||
    signals.includes("SUPPLY_CONFLICT") ||
    signals.includes("OWNER_CONFLICT") ||
    signals.includes("CAPS_CONFLICT")
  ) {
    return "ELEVATED_RISK";
  }

  if (signals.includes("HOOK_CONTROLLED") && signals.includes("PRIVILEGE_UNVERIFIED")) {
    return "ELEVATED_RISK";
  }

  if (signals.includes("BEHAVIOR_UNAVAILABLE") && signals.includes("ABI_OPAQUE")) {
    return "ELEVATED_RISK";
  }

  // OPAQUE_BUT_ACTIVE: ABI opaque with activity, or indexer unsupported with high activity
  if (signals.includes("ABI_OPAQUE_ACTIVE")) {
    return "OPAQUE_BUT_ACTIVE";
  }

  if (signals.includes("INDEXER_UNSUPPORTED") && input.behavior?.status === "sampled" && input.behavior.tx_count > 10) {
    return "OPAQUE_BUT_ACTIVE";
  }

  if (signals.includes("ABI_OPAQUE") && input.behavior?.status === "sampled" && input.behavior.tx_count > 0) {
    return "OPAQUE_BUT_ACTIVE";
  }

  // SAFE_DYNAMIC: SAFE_STATIC conditions + behavior evidence present and matches ABI
  if (signals.includes("BEHAVIOR_MATCHED") && !signals.includes("PHANTOM_ENTRYPOINTS")) {
    // Check for SAFE_STATIC conditions
    const hasHashPinned = signals.includes("HASH_PINNED");
    const hasMultiRpc = signals.includes("MULTI_RPC_CONFIRMED");
    const noConflicts = !signals.some(s => s.includes("CONFLICT"));
    
    if ((hasHashPinned || hasMultiRpc) && noConflicts) {
      return "SAFE_DYNAMIC";
    }
  }

  // SAFE_STATIC: hash pinned across multi-RPC; no behavior evidence requested/available; no conflicts
  const hasHashPinned = signals.includes("HASH_PINNED");
  const hasMultiRpc = signals.includes("MULTI_RPC_CONFIRMED");
  const noConflicts = !signals.some(s => s.includes("CONFLICT"));
  const noBehavior = !input.behavior || 
    input.behavior.status === "unavailable" || 
    input.behavior.status === "no_activity" ||
    input.behavior.status === "ok_empty";
  
  if ((hasHashPinned || hasMultiRpc) && noConflicts) {
    if (noBehavior) {
      return "SAFE_STATIC";
    }
    // If behavior exists but no phantom entries and no opaque issues
    if (input.behavior?.status === "sampled" && 
        input.behavior.phantom_entries.length === 0 && 
        !input.behavior.opaque_active) {
      return "SAFE_DYNAMIC";
    }
    return "SAFE_STATIC";
  }

  // Default to ELEVATED_RISK if we can't determine safety
  if (input.overallEvidenceTier === "view_only") {
    return "ELEVATED_RISK";
  }

  // If we have multi-RPC confirmation but no hash pinning, still relatively safe
  if (hasMultiRpc && noConflicts) {
    return "SAFE_STATIC";
  }

  return "ELEVATED_RISK";
}

/**
 * Create empty risk synthesis for error cases
 */
export function createEmptyRiskSynthesis(reason: string): RiskSynthesis {
  return {
    signals: [],
    risk_level: "ELEVATED_RISK",
    rationale: [reason, "Risk level: ELEVATED_RISK (insufficient data)"],
  };
}


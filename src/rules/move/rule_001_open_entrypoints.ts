import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";
import { isSafeException } from "../config.js";

/**
 * SVSSA-MOVE-001: Open/Dangerous entrypoints
 * Detects entry/public functions with dangerous names that may lack proper access control
 * Evidence-based: Maximum severity is HIGH (never CRITICAL) based on ABI evidence
 * View-only scans are capped at MEDIUM severity with low confidence
 */
export function rule_001_open_entrypoints(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  const dangerousPatterns = [
    "mint",
    "withdraw",
    "drain",
    "set_admin",
    "set_owner",
    "upgrade",
    "pause",
    "unpause",
    "set_config",
    "set_fee",
    "claim_admin",
    "transfer",
    "burn",
    "destroy",
  ];

  const gatingMarkers = [
    "only_admin",
    "only_owner",
    "require_admin",
    "assert_owner",
    "check_capability",
    "verify_signer",
  ];

  // Step 1: Identify entry functions that match dangerous patterns
  const dangerousFns: Array<{ name: string; matchedPatterns: string[] }> = [];
  
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    // Skip safe staking exceptions (these are handled separately below)
    if (isSafeException(entryFn, "entrypoint")) {
      continue; // Skip for dangerous pattern matching, but will handle separately
    }
    
    // Check if function matches dangerous patterns
    const matchedPatterns = dangerousPatterns.filter((pattern) =>
      fnLower.includes(pattern)
    );

    if (matchedPatterns.length > 0) {
      dangerousFns.push({ name: entryFn, matchedPatterns });
    }
  }

  // Step 2: Early return if no dangerous patterns found
  // Return empty array immediately - no findings when no dangerous patterns exist
  if (dangerousFns.length === 0) {
    return []; // No dangerous patterns = no findings
  }

  // Step 3: Process dangerous functions
  for (const { name: entryFn, matchedPatterns } of dangerousFns) {
    const fnLower = entryFn.toLowerCase();

    // Check for gating markers in function name or strings (heuristic only)
    // Note: This is NOT evidence of absence - it's just pattern matching
    const hasGating = 
      gatingMarkers.some((marker) => fnLower.includes(marker)) ||
      artifact.strings.some((s) =>
        gatingMarkers.some((marker) => s.toLowerCase().includes(marker))
      );

    // Check ABI for signer parameter (if available)
    let hasSignerParam = false;
    let hasAbiEvidence = false;
    if (artifact.abi && capabilities.hasAbi) {
      const fnDef = findFunctionInAbi(artifact.abi, entryFn);
      if (fnDef) {
        hasAbiEvidence = true;
        hasSignerParam = hasSignerParameter(fnDef);
      }
    }

    // Evidence-based severity gating
    // Maximum severity: HIGH (never CRITICAL without verified access control absence)
    let severity: "high" | "medium" | "low" | "info";
    let confidence: number;
    let evidenceKind: "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic";

    if (capabilities.viewOnly) {
      // View-only mode: cannot verify access control, cap at medium with low confidence
      severity = "medium";
      confidence = 0.4;
      evidenceKind = "heuristic";
    } else if (capabilities.hasAbi && hasAbiEvidence) {
      // ABI available: can check signer params
      // Maximum confidence: 0.6 for ABI-based findings
      if (hasSignerParam) {
        // Has signer parameter: indicates potential access control, but verify at runtime
        severity = "high";
        confidence = 0.6;
        evidenceKind = "abi_pattern";
      } else if (hasGating) {
        // Has gating markers in strings (heuristic): medium severity
        severity = "medium";
        confidence = 0.5;
        evidenceKind = "heuristic";
      } else {
        // No signer param and no gating markers: high severity but capped confidence
        severity = "high";
        confidence = 0.6; // Capped at 0.6 - cannot prove absence without verified access control check
        evidenceKind = "abi_pattern";
      }
    } else {
      // No ABI: heuristic only, cap at medium with low confidence
      severity = "medium";
      confidence = 0.4;
      evidenceKind = "heuristic";
    }

    findings.push({
      id: "SVSSA-MOVE-001",
      title: "Open/Dangerous Entrypoint Detected",
      severity,
      confidence,
      description: `Entry function "${entryFn}" matches dangerous patterns (${matchedPatterns.join(", ")}) and may lack proper access control.${capabilities.viewOnly ? " Note: View-only scan; cannot verify access control without ABI/bytecode." : ""}`,
      recommendation: hasGating || hasSignerParam
        ? "Verify that access control checks are properly enforced at runtime."
        : "Add access control checks (e.g., admin/owner verification, capability checks) before executing sensitive operations.",
      evidence: {
        kind: evidenceKind,
        matched: matchedPatterns,
        locations: [{ fn: entryFn, note: "Entry function with dangerous name pattern" }],
      },
      references: [],
    });
  }

  // Handle safe exceptions (emit INFO findings)
  for (const entryFn of artifact.entryFunctions) {
    if (isSafeException(entryFn, "entrypoint")) {
      findings.push({
        id: "SVSSA-MOVE-001-INFO",
        title: "Expected Staking Flow Detected",
        severity: "info",
        confidence: 0.8,
        description: `Entry function "${entryFn}" matches expected staking flow pattern. Verify access control is properly enforced via request/fulfill pattern.`,
        recommendation: "Ensure this function uses proper access control (e.g., request/fulfill pattern, signer verification).",
        evidence: {
          kind: "heuristic",
          matched: [entryFn],
          locations: [{ fn: entryFn, note: "Expected staking flow pattern" }],
        },
        references: [],
      });
    }
  }

  return findings;
}

function findFunctionInAbi(abi: any, functionName: string): any {
  if (Array.isArray(abi.functions)) {
    return abi.functions.find((f: any) => f.name === functionName);
  }
  if (Array.isArray(abi.entry_functions)) {
    return abi.entry_functions.find((f: any) => f.name === functionName);
  }
  if (Array.isArray(abi)) {
    return abi.find((f: any) => f.name === functionName);
  }
  return null;
}

function hasSignerParameter(fnDef: any): boolean {
  if (!fnDef.params || !Array.isArray(fnDef.params)) {
    return false;
  }
  return fnDef.params.some((p: any) => 
    p.type === "&signer" || 
    p.type === "&mut signer" ||
    (typeof p === "string" && p.includes("signer"))
  );
}


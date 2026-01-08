import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";
import { isSafeException } from "../config.js";

/**
 * SVSSA-MOVE-005: Asset outflow primitives
 * Detects transfer/withdraw functions that may lack proper access control
 * Evidence-based: Maximum severity is HIGH (never CRITICAL) based on ABI evidence
 * View-only scans are capped at MEDIUM severity with low confidence
 */
export function rule_005_asset_outflow(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  const outflowPatterns = [
    "transfer",
    "withdraw",
    "burn",
    "mint",
    "deposit",
    "withdraw_request",
    "drain",
    "sweep",
  ];

  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    // Skip safe staking exceptions
    if (isSafeException(entryFn, "outflow")) {
      // Emit informational finding for awareness (does not contribute to FAIL verdicts)
      findings.push({
        id: "SVSSA-MOVE-005-INFO",
        title: "Expected Staking Outflow Pattern",
        severity: "info",
        confidence: 0.8,
        description: `Entry function "${entryFn}" matches expected staking outflow pattern. Verify access control is properly enforced via request/fulfill pattern.`,
        recommendation: "Ensure this function uses proper access control (e.g., request/fulfill pattern, signer verification).",
        evidence: {
          kind: "heuristic",
          matched: [entryFn],
          locations: [{ fn: entryFn, note: "Expected staking outflow pattern" }],
        },
        references: [],
      });
      continue;
    }
    
    const matchedPatterns = outflowPatterns.filter((pattern) =>
      fnLower.includes(pattern)
    );

    if (matchedPatterns.length === 0) {
      continue;
    }

    // Check for access control
    const accessControlKeywords = ["only_admin", "only_owner", "assert_owner", "require_admin"];
    const hasAccessControl = 
      artifact.strings.some((s) =>
        accessControlKeywords.some((keyword) => s.toLowerCase().includes(keyword))
      ) ||
      artifact.functionNames.some((fn) =>
        accessControlKeywords.some((keyword) => fn.toLowerCase().includes(keyword))
      );

    // Check ABI for signer parameter
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
    // Determine evidence kind and base severity first, then apply viewOnly cap only for heuristic/metadata
    let severity: "high" | "medium" | "low" | "info";
    let confidence: number;
    // Explicitly type as full union to prevent TypeScript narrowing
    let evidenceKind: "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic";

    // Step 1: Determine evidence kind and base severity based on available evidence
    if (capabilities.hasAbi && hasAbiEvidence) {
      // ABI available: can check signer params
      // Maximum confidence: 0.6 for ABI-based findings
      evidenceKind = "abi_pattern";
      if (hasSignerParam) {
        // Has signer parameter: indicates potential access control, but verify at runtime
        severity = "high";
        confidence = 0.6;
      } else if (hasAccessControl) {
        // Has access control markers in strings (heuristic): medium severity
        severity = "medium";
        confidence = 0.5;
      } else {
        // No signer param and no access control markers: high severity but capped confidence
        severity = "high";
        confidence = 0.6; // Capped at 0.6 - cannot prove absence without verified access control check
      }
    } else if (capabilities.hasBytecodeOrSource) {
      // Bytecode/source available: use bytecode_pattern evidence
      evidenceKind = "bytecode_pattern";
      if (hasAccessControl) {
        // Has access control markers: high severity (code-backed evidence)
        severity = "high";
        confidence = 0.6;
      } else {
        // No access control markers: high severity
        severity = "high";
        confidence = 0.5;
      }
    } else {
      // No ABI/bytecode: heuristic only
      evidenceKind = "heuristic";
      if (hasAccessControl) {
        // Has access control markers: high severity (but will be capped if viewOnly)
        severity = "high";
        confidence = 0.5;
      } else {
        // No access control markers: medium severity
        severity = "medium";
        confidence = 0.4;
      }
    }

    // Step 2: Apply viewOnly cap ONLY for heuristic/metadata evidence (not code-backed)
    // Type assertion prevents TypeScript narrowing - evidenceKind is typed as full union but TS narrows after assignments
    const evidenceKindFull = evidenceKind as "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic";
    if (capabilities.viewOnly && (evidenceKindFull === "heuristic" || evidenceKindFull === "metadata")) {
      // View-only mode with heuristic/metadata evidence: cap at medium with low confidence
      severity = "medium";
      confidence = 0.4;
    }

    findings.push({
      id: "SVSSA-MOVE-005",
      title: "Asset Outflow Function Without Clear Access Control",
      severity,
      confidence,
      description: `Entry function "${entryFn}" handles asset transfers/outflows (${matchedPatterns.join(", ")}) and may lack proper access control.${capabilities.viewOnly ? " Note: View-only scan; cannot verify access control without ABI/bytecode. Review on-chain code to confirm access control implementation." : ""}`,
      recommendation: capabilities.viewOnly
        ? "Cannot verify access control without ABI/bytecode; review on-chain code to confirm proper access control implementation."
        : hasAccessControl || hasSignerParam
        ? "Verify that access control checks are enforced and consider adding withdrawal limits or rate limiting."
        : "Implement proper access control (admin/owner checks or signer verification) for asset outflow functions.",
      evidence: {
        kind: evidenceKind,
        matched: matchedPatterns,
        locations: [{ fn: entryFn, note: "Asset outflow function detected" }],
      },
      references: [],
    });
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


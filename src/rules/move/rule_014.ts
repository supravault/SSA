import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-014: Access control bypass patterns
 * Detects functions that may bypass access control checks
 * Requires bytecode/ABI for authoritative findings
 */
export function rule_014(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  const bypassPatterns = [
    "bypass",
    "skip",
    "override",
    "force",
    "emergency",
    "admin_override",
    "unchecked",
  ];

  const accessControlMarkers = [
    "only_admin",
    "only_owner",
    "require_admin",
    "assert_owner",
    "check_capability",
    "verify_signer",
    "has_permission",
    "is_authorized",
  ];

  // Check entry functions for bypass patterns
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    // Check if function name suggests bypass
    const hasBypassPattern = bypassPatterns.some((pattern) =>
      fnLower.includes(pattern)
    );

    if (!hasBypassPattern) {
      continue;
    }

    // Check if access control markers are present
    const hasAccessControl = 
      accessControlMarkers.some((marker) => fnLower.includes(marker)) ||
      artifact.strings.some((s) =>
        accessControlMarkers.some((marker) => s.toLowerCase().includes(marker))
      );

    // Check ABI for signer parameter (if available)
    let hasSignerParam = false;
    if (capabilities.hasAbi && artifact.abi) {
      const fnDef = findFunctionInAbi(artifact.abi, entryFn);
      if (fnDef) {
        hasSignerParam = hasSignerParameter(fnDef);
      }
    }

    // If bypass pattern exists but no clear access control, flag it
    if (!hasAccessControl && !hasSignerParam) {
      let severity: "high" | "medium";
      let confidence: number;
      let evidenceKind: "bytecode_pattern" | "abi_pattern" | "heuristic";

      if (capabilities.hasAbi) {
        severity = "high";
        confidence = 0.7;
        evidenceKind = "abi_pattern";
      } else if (capabilities.hasBytecodeOrSource) {
        severity = "high";
        confidence = 0.6;
        evidenceKind = "bytecode_pattern";
      } else {
        severity = "medium";
        confidence = 0.5;
        evidenceKind = "heuristic";
      }

      findings.push({
        id: "SVSSA-MOVE-014",
        title: "Potential Access Control Bypass",
        severity,
        confidence,
        description: `Entry function "${entryFn}" contains bypass-related patterns but no clear access control markers detected. This may allow unauthorized access to privileged operations.`,
        recommendation: "Ensure bypass functions are properly gated with admin/owner checks or capability verification. Review access control logic carefully.",
        evidence: {
          kind: evidenceKind,
          matched: bypassPatterns.filter((p) => fnLower.includes(p)),
          locations: [{ fn: entryFn, note: "Bypass pattern without clear access control" }],
        },
        references: [],
      });
    }
  }

  return findings;
}

/**
 * Helper to find function in ABI
 */
function findFunctionInAbi(abi: any, functionName: string): any {
  if (!abi || typeof abi !== "object") {
    return null;
  }

  // Try common ABI structures
  const functions = abi.functions || abi.exposed_functions || abi.entry_functions || [];
  
  return functions.find(
    (fn: any) =>
      fn.name === functionName ||
      fn.name?.toLowerCase() === functionName.toLowerCase()
  );
}

/**
 * Check if function has signer parameter
 */
function hasSignerParameter(fnDef: any): boolean {
  if (!fnDef || !fnDef.params) {
    return false;
  }

  const params = Array.isArray(fnDef.params) ? fnDef.params : [];
  return params.some(
    (param: any) =>
      param.type === "signer" ||
      param.type === "&signer" ||
      param.type?.includes("signer")
  );
}

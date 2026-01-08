import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-020: Missing input validation
 * Detects functions that may lack proper input validation
 * Requires bytecode/ABI for detection
 */
export function rule_020(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  const sensitiveOperations = [
    "transfer",
    "mint",
    "burn",
    "withdraw",
    "deposit",
    "set",
    "update",
    "create",
  ];

  const validationMarkers = [
    "assert",
    "require",
    "check",
    "validate",
    "verify",
    "ensure",
    "guard",
    "bound",
    "limit",
  ];

  // Check entry functions for missing validation
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    // Check if function performs sensitive operations
    const isSensitive = sensitiveOperations.some((op) =>
      fnLower.includes(op)
    );

    if (!isSensitive) {
      continue;
    }

    // Check for validation markers in function name or strings
    const hasValidation = 
      validationMarkers.some((marker) => fnLower.includes(marker)) ||
      artifact.strings.some((s) =>
        validationMarkers.some((marker) => s.toLowerCase().includes(marker))
      );

    // Check ABI for parameter types that might indicate validation
    let hasTypedParams = false;
    if (capabilities.hasAbi && artifact.abi) {
      const fnDef = findFunctionInAbi(artifact.abi, entryFn);
      if (fnDef && fnDef.params && Array.isArray(fnDef.params) && fnDef.params.length > 0) {
        // If function has parameters, check if they're typed (not just raw addresses/numbers)
        hasTypedParams = fnDef.params.some(
          (param: any) =>
            param.type && 
            (param.type.includes("::") || param.type.includes("Option") || param.type.includes("vector"))
        );
      }
    }

    // If sensitive operation but no clear validation, flag it
    if (!hasValidation && !hasTypedParams) {
      let severity: "high" | "medium" | "low";
      let confidence: number;
      let evidenceKind: "bytecode_pattern" | "abi_pattern" | "heuristic";

      // Higher severity for transfer/mint/withdraw operations
      const isCriticalOp = 
        fnLower.includes("transfer") ||
        fnLower.includes("mint") ||
        fnLower.includes("withdraw") ||
        fnLower.includes("burn");

      if (capabilities.hasAbi) {
        severity = isCriticalOp ? "high" : "medium";
        confidence = isCriticalOp ? 0.7 : 0.6;
        evidenceKind = "abi_pattern";
      } else if (capabilities.hasBytecodeOrSource) {
        severity = isCriticalOp ? "high" : "medium";
        confidence = isCriticalOp ? 0.6 : 0.5;
        evidenceKind = "bytecode_pattern";
      } else {
        severity = "medium";
        confidence = 0.4;
        evidenceKind = "heuristic";
      }

      findings.push({
        id: "SVSSA-MOVE-020",
        title: "Missing Input Validation",
        severity,
        confidence,
        description: `Entry function "${entryFn}" performs sensitive operations but no clear input validation detected. Invalid inputs may cause unexpected behavior or vulnerabilities.`,
        recommendation: "Add input validation checks (bounds checking, null checks, type validation) before performing sensitive operations. Validate all user-provided parameters.",
        evidence: {
          kind: evidenceKind,
          matched: sensitiveOperations.filter((op) => fnLower.includes(op)),
          locations: [{ fn: entryFn, note: "Sensitive operation without clear validation" }],
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

  const functions = abi.functions || abi.exposed_functions || abi.entry_functions || [];
  
  return functions.find(
    (fn: any) =>
      fn.name === functionName ||
      fn.name?.toLowerCase() === functionName.toLowerCase()
  );
}

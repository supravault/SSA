import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-012: Reentrancy risks
 * Detects potential reentrancy vulnerabilities (state changes after external calls)
 * Requires bytecode/ABI for detection
 */
export function rule_012(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  // Reentrancy indicators: external calls followed by state changes
  const externalCallMarkers = [
    "transfer",
    "call",
    "delegate_call",
    "external_call",
    "invoke",
    "borrow_global_mut",
    "move_to",
  ];

  const stateChangeMarkers = [
    "borrow_global_mut",
    "move_to",
    "move_from",
    "transfer",
    "deposit",
    "withdraw",
  ];

  // Check for functions that may have reentrancy risks
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    // Check if function handles transfers/withdrawals (common reentrancy targets)
    const isTransferFunction = 
      fnLower.includes("transfer") ||
      fnLower.includes("withdraw") ||
      fnLower.includes("claim") ||
      fnLower.includes("mint");

    if (!isTransferFunction) {
      continue;
    }

    // Check for external call patterns in strings/bytecode
    const hasExternalCalls = artifact.strings.some((s) =>
      externalCallMarkers.some((marker) => s.toLowerCase().includes(marker))
    );

    const hasStateChanges = artifact.strings.some((s) =>
      stateChangeMarkers.some((marker) => s.toLowerCase().includes(marker))
    );

    // If both external calls and state changes are present, flag potential reentrancy
    if (hasExternalCalls && hasStateChanges) {
      // Check for reentrancy guards
      const guardMarkers = [
        "non_reentrant",
        "reentrancy_guard",
        "locked",
        "mutex",
        "guard",
      ];

      const hasGuard = artifact.strings.some((s) =>
        guardMarkers.some((marker) => s.toLowerCase().includes(marker))
      );

      if (!hasGuard) {
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
          id: "SVSSA-MOVE-012",
          title: "Potential Reentrancy Vulnerability",
          severity,
          confidence,
          description: `Entry function "${entryFn}" performs external calls and state changes but no reentrancy guard detected. This may allow recursive calls to manipulate state.`,
          recommendation: "Implement reentrancy guards (e.g., non-reentrant flags, checks-effects-interactions pattern) to prevent recursive calls during execution.",
          evidence: {
            kind: evidenceKind,
            matched: ["external_call", "state_change"],
            locations: [{ fn: entryFn, note: "Potential reentrancy pattern" }],
          },
          references: [],
        });
      }
    }
  }

  return findings;
}

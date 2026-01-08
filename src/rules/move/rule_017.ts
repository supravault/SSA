import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-017: Denial of Service risks
 * Detects functions that may be vulnerable to DoS attacks (unbounded loops, gas exhaustion, etc.)
 * Requires bytecode/ABI for detection
 */
export function rule_017(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  const dosVulnerablePatterns = [
    "loop",
    "iterate",
    "foreach",
    "while",
    "for",
    "map",
    "filter",
  ];

  const dosVulnerableOperations = [
    "transfer",
    "mint",
    "batch",
    "process",
    "claim",
    "withdraw",
  ];

  // Check for loop patterns in strings/bytecode
  const hasLoopPatterns = artifact.strings.some((s) =>
    dosVulnerablePatterns.some((pattern) => s.toLowerCase().includes(pattern))
  );

  // Check entry functions that may be vulnerable
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    const isVulnerableOp = dosVulnerableOperations.some((op) =>
      fnLower.includes(op)
    );

    // Check for batch operations (common DoS vector)
    const isBatchOp = 
      fnLower.includes("batch") ||
      fnLower.includes("multi") ||
      fnLower.includes("bulk");

    if ((isVulnerableOp || isBatchOp) && hasLoopPatterns) {
      // Check for DoS mitigations
      const mitigationMarkers = [
        "limit",
        "max",
        "bound",
        "cap",
        "threshold",
        "chunk",
        "paginate",
      ];

      const hasMitigation = 
        mitigationMarkers.some((marker) => fnLower.includes(marker)) ||
        artifact.strings.some((s) =>
          mitigationMarkers.some((marker) => s.toLowerCase().includes(marker))
        );

      if (!hasMitigation) {
        let severity: "high" | "medium";
        let confidence: number;
        let evidenceKind: "bytecode_pattern" | "abi_pattern" | "heuristic";

        if (capabilities.hasAbi) {
          severity = isBatchOp ? "high" : "medium";
          confidence = isBatchOp ? 0.7 : 0.6;
          evidenceKind = "abi_pattern";
        } else if (capabilities.hasBytecodeOrSource) {
          severity = isBatchOp ? "high" : "medium";
          confidence = isBatchOp ? 0.6 : 0.5;
          evidenceKind = "bytecode_pattern";
        } else {
          severity = "medium";
          confidence = 0.5;
          evidenceKind = "heuristic";
        }

        findings.push({
          id: "SVSSA-MOVE-017",
          title: "Potential Denial of Service Risk",
          severity,
          confidence,
          description: `Entry function "${entryFn}" performs operations that may be vulnerable to DoS attacks (unbounded loops, batch operations without limits). ${isBatchOp ? "Batch operations detected." : "Loop patterns detected."}`,
          recommendation: "Add limits to batch operations, pagination for large datasets, or gas limits to prevent DoS attacks. Ensure loops have maximum iteration bounds.",
          evidence: {
            kind: evidenceKind,
            matched: dosVulnerablePatterns.filter((p) => 
              artifact.strings.some((s) => s.toLowerCase().includes(p))
            ),
            locations: [{ fn: entryFn, note: "Potential DoS vulnerability" }],
          },
          references: [],
        });
      }
    }
  }

  return findings;
}

import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-015: Timestamp dependence
 * Detects functions that depend on block timestamps which may be manipulated
 * Requires bytecode/ABI for detection
 */
export function rule_015(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  const timestampMarkers = [
    "timestamp",
    "now",
    "time",
    "block_time",
    "current_time",
    "clock",
  ];

  const timeDependentOperations = [
    "vest",
    "unlock",
    "release",
    "expire",
    "deadline",
    "timeout",
    "delay",
    "schedule",
  ];

  // Check for timestamp usage in strings/bytecode
  const hasTimestampUsage = artifact.strings.some((s) =>
    timestampMarkers.some((marker) => s.toLowerCase().includes(marker))
  );

  if (!hasTimestampUsage) {
    return findings; // No timestamp usage detected
  }

  // Check entry functions that may be time-dependent
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    const isTimeDependent = timeDependentOperations.some((op) =>
      fnLower.includes(op)
    );

    if (isTimeDependent) {
      // Check for time manipulation mitigations
      const mitigationMarkers = [
        "tolerance",
        "buffer",
        "window",
        "grace_period",
        "min_duration",
        "max_duration",
      ];

      const hasMitigation = artifact.strings.some((s) =>
        mitigationMarkers.some((marker) => s.toLowerCase().includes(marker))
      );

      let severity: "high" | "medium";
      let confidence: number;
      let evidenceKind: "bytecode_pattern" | "abi_pattern" | "heuristic";

      if (capabilities.hasAbi) {
        severity = hasMitigation ? "medium" : "high";
        confidence = hasMitigation ? 0.6 : 0.7;
        evidenceKind = "abi_pattern";
      } else if (capabilities.hasBytecodeOrSource) {
        severity = hasMitigation ? "medium" : "high";
        confidence = hasMitigation ? 0.5 : 0.6;
        evidenceKind = "bytecode_pattern";
      } else {
        severity = "medium";
        confidence = 0.5;
        evidenceKind = "heuristic";
      }

      findings.push({
        id: "SVSSA-MOVE-015",
        title: "Timestamp Dependence Risk",
        severity,
        confidence,
        description: `Entry function "${entryFn}" depends on block timestamps which may be manipulated by validators. ${hasMitigation ? "Some mitigations detected, but verify robustness." : "No clear mitigations detected."}`,
        recommendation: hasMitigation
          ? "Ensure timestamp-based logic uses tolerance windows or other mitigations to prevent manipulation."
          : "Add mitigations for timestamp manipulation (tolerance windows, minimum durations, or use oracle-based time). Avoid critical logic that depends solely on block timestamps.",
        evidence: {
          kind: evidenceKind,
          matched: timestampMarkers.filter((m) => 
            artifact.strings.some((s) => s.toLowerCase().includes(m))
          ),
          locations: [{ fn: entryFn, note: "Time-dependent operation" }],
        },
        references: [],
      });
    }
  }

  return findings;
}

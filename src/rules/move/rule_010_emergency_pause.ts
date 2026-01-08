import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-010: Emergency pause abuse
 * Detects pause/unpause functions and checks for proper documentation/role separation
 */
export function rule_010_emergency_pause(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  const pausePatterns = ["pause", "unpause", "emergency"];
  const hasPauseFunctions = artifact.entryFunctions.some((fn) =>
    pausePatterns.some((pattern) => fn.toLowerCase().includes(pattern))
  );

  if (!hasPauseFunctions) {
    return findings;
  }

  // Check for role separation (different roles for pause vs unpause)
  const pauseFns = artifact.entryFunctions.filter((fn) =>
    fn.toLowerCase().includes("pause")
  );
  const hasRoleSeparation = pauseFns.length >= 2; // At least pause and unpause

  findings.push({
    id: "SVSSA-MOVE-010",
    title: "Emergency Pause Mechanism Detected",
    severity: hasRoleSeparation ? "info" : "medium",
    confidence: 0.7,
    description: `Detected pause/unpause functions. Emergency pause mechanisms are important for security but must be properly designed to prevent abuse.`,
    recommendation: hasRoleSeparation
      ? "Ensure pause and unpause functions have separate roles, documented pause policies, and time-based restrictions if applicable."
      : "Implement role separation for pause and unpause functions, document pause policies, and consider adding time-based restrictions or multisig requirements.",
    evidence: {
      kind: "abi_pattern",
      matched: pausePatterns.filter((pattern) =>
        artifact.entryFunctions.some((fn) => fn.toLowerCase().includes(pattern))
      ),
      locations: pauseFns.map((fn) => ({
        fn,
        note: "Pause-related function detected",
      })),
    },
      references: [],
  });

  return findings;
}


import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-008: Centralization risk
 * Detects admin functions without multisig/timelock hints
 */
export function rule_008_centralization(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  const adminPatterns = ["admin", "owner", "authority", "governance"];
  const decentralizationHints = ["multisig", "timelock", "delay", "proposal", "vote", "council"];

  const hasAdminFunctions = artifact.entryFunctions.some((fn) =>
    adminPatterns.some((pattern) => fn.toLowerCase().includes(pattern))
  );

  if (!hasAdminFunctions) {
    return findings;
  }

  const hasDecentralizationHints = artifact.strings.some((s) =>
    decentralizationHints.some((hint) => s.toLowerCase().includes(hint))
  );

  if (!hasDecentralizationHints) {
    findings.push({
      id: "SVSSA-MOVE-008",
      title: "Centralization Risk: Admin Functions Without Decentralization Mechanisms",
      severity: "medium",
      confidence: 0.5,
      description: `Detected admin/owner functions but no clear hints of multisig, timelock, or governance mechanisms. Single-point-of-failure admin accounts pose centralization risks.`,
      recommendation: "Consider implementing multisig, timelock delays, or governance mechanisms for admin functions to reduce centralization risk.",
      evidence: {
        kind: "heuristic",
        matched: adminPatterns.filter((pattern) =>
          artifact.entryFunctions.some((fn) => fn.toLowerCase().includes(pattern))
        ),
        locations: artifact.entryFunctions
          .filter((fn) =>
            adminPatterns.some((pattern) => fn.toLowerCase().includes(pattern))
          )
          .map((fn) => ({ fn, note: "Admin function without decentralization hints" })),
      },
      references: [],
    });
  }

  return findings;
}


import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-007: Missing event emissions (observability)
 * Detects sensitive operations that may lack event emissions
 * Evidence-based: Only flags if we have evidence that events can be inspected
 */

export function rule_007_missing_events(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  const sensitiveOperations = ["mint", "withdraw", "transfer", "burn", "admin", "upgrade", "pause"];
  const eventKeywords = ["event", "emit", "handle", "log"];

  const hasSensitiveOps = artifact.entryFunctions.some((fn) =>
    sensitiveOperations.some((op) => fn.toLowerCase().includes(op))
  );

  if (!hasSensitiveOps) {
    return findings;
  }

  // In view-only mode, skip this rule entirely (no penalty)
  // Event verification requires bytecode/source inspection
  if (capabilities.viewOnly) {
    return findings; // Return empty findings - no penalty for view-only scans
  }

  // Check for event hints in bytecode/source strings
  const hasEventHints = artifact.strings.some((s) =>
    eventKeywords.some((keyword) => s.toLowerCase().includes(keyword))
  );

  // Only flag if we have bytecode/source evidence
  if (!hasEventHints && capabilities.hasBytecodeOrSource) {
    findings.push({
      id: "SVSSA-MOVE-007",
      title: "Missing Event Emissions for Sensitive Operations",
      severity: "low",
      confidence: 0.5,
      description: `Detected sensitive operations (mint/withdraw/admin/upgrade) but no clear event emission patterns found in bytecode/source. Events are important for off-chain monitoring and transparency.`,
      recommendation: "Emit events for all sensitive operations (transfers, mints, burns, admin actions) to enable off-chain monitoring and improve transparency.",
      evidence: {
        kind: capabilities.hasBytecodeOrSource ? "bytecode_pattern" : "heuristic",
        matched: sensitiveOperations.filter((op) =>
          artifact.entryFunctions.some((fn) => fn.toLowerCase().includes(op))
        ),
        locations: artifact.entryFunctions
          .filter((fn) =>
            sensitiveOperations.some((op) => fn.toLowerCase().includes(op))
          )
          .map((fn) => ({ fn, note: "Sensitive operation without clear event emission" })),
      },
      references: [],
    });
  }

  return findings;
}


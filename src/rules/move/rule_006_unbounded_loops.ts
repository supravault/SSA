import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-006: Unbounded loops / vector iteration hints
 * Detects potential unbounded loops in public entrypoints
 */
export function rule_006_unbounded_loops(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  const loopKeywords = ["vector", "length", "for", "while", "iter", "loop", "foreach"];
  const hasLoopHints = artifact.strings.some((s) =>
    loopKeywords.some((keyword) => s.toLowerCase().includes(keyword))
  );

  if (!hasLoopHints || artifact.entryFunctions.length === 0) {
    return findings;
  }

  // Check for bounds/limits
  const boundKeywords = ["max", "limit", "bound", "cap", "threshold"];
  const hasBounds = artifact.strings.some((s) =>
    boundKeywords.some((keyword) => s.toLowerCase().includes(keyword))
  );

  findings.push({
    id: "SVSSA-MOVE-006",
    title: "Potential Unbounded Loops in Entry Functions",
    severity: hasBounds ? "medium" : "high",
    confidence: 0.5,
    description: `Detected loop-related patterns in bytecode strings. If entry functions iterate over user-controlled vectors without bounds, this may lead to DoS attacks or excessive gas consumption.`,
    recommendation: hasBounds
      ? "Verify that loop bounds are properly enforced and consider adding maximum iteration limits."
      : "Add explicit bounds checking for all loops that iterate over user-controlled or dynamic data structures.",
    evidence: {
      kind: "bytecode_pattern",
      matched: loopKeywords.filter((kw) =>
        artifact.strings.some((s) => s.toLowerCase().includes(kw))
      ),
      locations: artifact.entryFunctions.map((fn) => ({
        fn,
        note: "Entry function may contain loops",
      })),
    },
      references: [],
  });

  return findings;
}


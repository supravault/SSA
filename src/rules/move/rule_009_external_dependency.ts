import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-009: External dependency/oracle usage
 * Detects oracle/external dependency usage without bounds
 */
export function rule_009_external_dependency(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  const oracleKeywords = ["oracle", "price", "feed", "vrf", "random", "external"];
  const boundKeywords = ["bounds", "max", "min", "limit", "threshold", "sanity"];

  const hasOracleHints = artifact.strings.some((s) =>
    oracleKeywords.some((keyword) => s.toLowerCase().includes(keyword))
  );

  if (!hasOracleHints) {
    return findings;
  }

  const hasBounds = artifact.strings.some((s) =>
    boundKeywords.some((keyword) => s.toLowerCase().includes(keyword))
  );

  findings.push({
    id: "SVSSA-MOVE-009",
    title: "External Dependency/Oracle Usage Without Clear Bounds",
    severity: hasBounds ? "medium" : "high",
    confidence: 0.6,
    description: `Detected oracle/external dependency patterns (${oracleKeywords.filter((kw) =>
      artifact.strings.some((s) => s.toLowerCase().includes(kw))
    ).join(", ")}) but ${hasBounds ? "limited" : "no"} bounds checking hints. Oracle manipulation or stale data can lead to financial losses.`,
    recommendation: hasBounds
      ? "Verify that oracle values are bounded (min/max) and consider adding staleness checks and multiple oracle sources."
      : "Implement bounds checking (min/max values), staleness checks, and consider using multiple oracle sources for critical price feeds.",
    evidence: {
      kind: "bytecode_pattern",
      matched: oracleKeywords.filter((kw) =>
        artifact.strings.some((s) => s.toLowerCase().includes(kw))
      ),
      locations: artifact.entryFunctions.map((fn) => ({
        fn,
        note: "Function may use external dependencies",
      })),
    },
      references: [],
  });

  return findings;
}


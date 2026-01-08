import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-003: Re-initialization / init callable
 * Detects init/initialize functions that may be callable multiple times
 */
export function rule_003_hardcoded_privileged(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  const initPatterns = ["init", "initialize", "setup", "reinit", "reinitialize"];

  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    const matchedPatterns = initPatterns.filter((pattern) =>
      fnLower.includes(pattern)
    );

    if (matchedPatterns.length === 0) {
      continue;
    }

    // Check for one-time init guards
    const guardKeywords = ["one_time", "init_once", "already_init", "initialized"];
    const hasGuard = 
      artifact.strings.some((s) =>
        guardKeywords.some((keyword) => s.toLowerCase().includes(keyword))
      ) ||
      artifact.functionNames.some((fn) =>
        guardKeywords.some((keyword) => fn.toLowerCase().includes(keyword))
      );

    findings.push({
      id: "SVSSA-MOVE-003",
      title: "Potentially Callable Initialization Function",
      severity: hasGuard ? "medium" : "high",
      confidence: hasGuard ? 0.5 : 0.8,
      description: `Entry function "${entryFn}" appears to be an initialization function. If callable multiple times, it may allow re-initialization attacks.`,
      recommendation: hasGuard
        ? "Verify that initialization guards are properly enforced at runtime."
        : "Add a one-time initialization guard to prevent re-initialization attacks.",
      evidence: {
        kind: "abi_pattern",
        matched: matchedPatterns,
        locations: [{ fn: entryFn, note: "Initialization function detected" }],
      },
      references: [],
    });
  }

  return findings;
}


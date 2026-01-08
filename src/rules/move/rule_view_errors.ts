import type { Finding } from "../../core/types.js";
import { REQUIRED_VIEWS, OPTIONAL_VIEWS, type ViewError } from "../../rpc/supra.js";

/**
 * Create findings for missing/failed view calls
 */
export function createViewErrorFindings(viewErrors: ViewError[]): Finding[] {
  const findings: Finding[] = [];

  if (viewErrors.length === 0) {
    return findings;
  }

  // Filter out skipped and unsupported views (they don't contribute to risk)
  const trueErrors = viewErrors.filter((e) => e.type === "error");
  const skippedViews = viewErrors.filter((e) => e.type === "skipped");
  const unsupportedViews = viewErrors.filter((e) => e.type === "unsupported");

  // Separate required vs optional view errors (only true errors)
  const requiredErrors = trueErrors.filter((e) => REQUIRED_VIEWS.includes(e.viewName));
  const optionalErrors = trueErrors.filter((e) => OPTIONAL_VIEWS.includes(e.viewName));

  // High severity finding for missing required views (but verdict should be INCONCLUSIVE, not FAIL)
  if (requiredErrors.length > 0) {
    findings.push({
      id: "SVSSA-MOVE-VIEW-001",
      title: "Missing Required View Functions",
      severity: "high",
      confidence: 1.0,
      description: `Failed to fetch ${requiredErrors.length} required view function(s): ${requiredErrors.map((e) => e.viewName).join(", ")}. This prevents complete security analysis.`,
      recommendation: "Ensure all required view functions are available and accessible. Check RPC endpoint connectivity and module deployment status.",
      evidence: {
        kind: "heuristic", // View availability is heuristic, not evidence-backed
        matched: requiredErrors.map((e) => e.viewName),
        locations: requiredErrors.map((e) => ({
          fn: e.functionId,
          note: `Failed: ${e.error}`,
        })),
      },
      references: [],
    });
  }

  // Low/Medium severity finding for missing optional views
  if (optionalErrors.length > 0) {
    findings.push({
      id: "SVSSA-MOVE-VIEW-002",
      title: "Missing Optional View Functions",
      severity: optionalErrors.length > 3 ? "medium" : "low",
      confidence: 0.8,
      description: `Failed to fetch ${optionalErrors.length} optional view function(s): ${optionalErrors.map((e) => e.viewName).join(", ")}. Some analysis features may be limited.`,
      recommendation: "Optional views provide additional context but are not critical. Consider fixing if comprehensive analysis is needed.",
      evidence: {
        kind: "heuristic",
        matched: optionalErrors.map((e) => e.viewName),
        locations: optionalErrors.map((e) => ({
          fn: e.functionId,
          note: `Failed: ${e.error}`,
        })),
      },
      references: [],
    });
  }

  return findings;
}


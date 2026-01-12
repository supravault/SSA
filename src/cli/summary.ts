// src/cli/summary.ts
import type { ScanResult } from "../core/types.js";
import type { PulseMetadata } from "./pulse.js";
import type { SignedBadge } from "../crypto/badgeSigner.js";

export type SummaryVerdict =
  | "excellent"
  | "good"
  | "fair"
  | "poor"
  | "pass"
  | "warn"
  | "fail"
  | "inconclusive";

export interface SummaryJson {
  scan_id: string;
  created_utc: string;

  kind: string;
  target: string;
  level: number;

  verdict: SummaryVerdict;
  score: number;

  badge?: any;
  signed_badge?: SignedBadge | null;

  monitoring?: any;
  monitoring_enabled?: boolean;

  pulse?: PulseMetadata | null;

  files: {
    report_json: string;
    summary_json: string;
    pdf?: string | null;
  };

  // keep it flexible (your project evolves fast)
  meta?: Record<string, any>;
}

type EngineVerdict = "pass" | "warn" | "fail" | "inconclusive";

/**
 * Generates the user-facing summary.json.
 * IMPORTANT: Must be exported (ssa.ts imports it).
 */
export function generateSummaryJson(
  scanResult: ScanResult,
  kind: string,
  target: string,
  level: number,
  outDir: string,
  pdfEnabled: boolean,
  pulseMetadata: PulseMetadata | null,
  badgeResult: any,
  signedBadge: SignedBadge | null
): SummaryJson {
  const created_utc = new Date().toISOString();

  // Prefer explicit numeric score if present; otherwise fallback to risk_score.
  const riskScore =
    (scanResult as any)?.summary?.risk_score ??
    (scanResult as any)?.summary?.score ??
    0;

  const score = Number.isFinite(Number(riskScore)) ? Number(riskScore) : 0;

  // Score bucket (cosmetic verdict)
  let scoreVerdict: SummaryVerdict;
  if (score >= 90) scoreVerdict = "excellent";
  else if (score >= 75) scoreVerdict = "good";
  else if (score >= 60) scoreVerdict = "fair";
  else scoreVerdict = "poor";

  // Engine verdict (authoritative)
  const rawEngineVerdict = (scanResult as any)?.summary?.verdict;
  const engineVerdict: EngineVerdict | null =
    rawEngineVerdict === "pass" ||
    rawEngineVerdict === "warn" ||
    rawEngineVerdict === "fail" ||
    rawEngineVerdict === "inconclusive"
      ? rawEngineVerdict
      : null;

  // Final verdict: engine verdict overrides buckets when meaningful.
  // - fail always wins
  // - warn overrides score bucket
  // - inconclusive overrides score bucket
  // - pass does NOT override (we prefer bucket for UI), but is preserved in meta.
  let verdict: SummaryVerdict = scoreVerdict;
  if (engineVerdict === "fail") verdict = "fail";
  else if (engineVerdict === "warn") verdict = "warn";
  else if (engineVerdict === "inconclusive") verdict = "inconclusive";

  const monitoring = (scanResult as any)?.meta?.monitoring;
  const monitoring_enabled = (scanResult as any)?.meta?.monitoring_enabled === true;

  return {
    scan_id: (scanResult as any)?.request_id || (scanResult as any)?.id || "unknown",
    created_utc,

    kind,
    target,
    level,

    verdict,
    score,

    badge: badgeResult ?? undefined,
    signed_badge: signedBadge ?? null,

    monitoring: monitoring ?? undefined,
    monitoring_enabled,

    pulse: pulseMetadata ?? null,

    files: {
      report_json: "report.json",
      summary_json: "summary.json",
      pdf: pdfEnabled ? "report.pdf" : null,
    },

    meta: {
      engine: (scanResult as any)?.engine ?? undefined,
      severity_counts: (scanResult as any)?.summary?.severity_counts ?? undefined,
      engine_verdict: engineVerdict ?? undefined,
    },
  };
}









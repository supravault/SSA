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

  // If your pipeline writes a “total score” elsewhere, prefer it
  // (this keeps it resilient across formats).
  const score = Number.isFinite(Number(riskScore)) ? Number(riskScore) : 0;

  // Basic verdict mapping:
  // - if score >= 90 => excellent
  // - else show score and preserve engine verdict when present
  let verdict: SummaryVerdict = "good";
  if (score >= 90) verdict = "excellent";
  else if (score >= 75) verdict = "good";
  else if (score >= 60) verdict = "fair";
  else verdict = "poor";

  const engineVerdict = (scanResult as any)?.summary?.verdict;
  if (
    engineVerdict === "fail" ||
    engineVerdict === "warn" ||
    engineVerdict === "pass" ||
    engineVerdict === "inconclusive"
  ) {
    // If engine explicitly says fail, it overrides the cosmetic score bucket
    if (engineVerdict === "fail") verdict = "fail";
    else if (engineVerdict === "warn" && verdict !== "fail") verdict = "warn";
    else if (engineVerdict === "inconclusive" && verdict !== "fail" && verdict !== "warn") verdict = "inconclusive";
    // NOTE: we intentionally don't force "pass" here because score buckets
    // are more informative for the UI; pass is still reflected in meta.engine below.
  }

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
      // keep the "engine verdict" for debugging / UI chips
      engine_verdict: engineVerdict ?? undefined,
    },
  };
}







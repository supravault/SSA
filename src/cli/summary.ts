// src/cli/summary.ts
// Generate summary.json for Base44 ingestion

import type { ScanResult } from "../core/types.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import type { SignedBadge } from "../crypto/badgeSigner.js";
import type { PulseMetadata } from "./pulse.js";
import { getIsoTimestamp } from "../utils/time.js";
import { join } from "path";
import { existsSync } from "fs";

export interface SummaryJson {
  target: {
    kind: "coin" | "fa" | "wallet";
    value: string;
  };
  time_utc: string;
  level: number;
  verdict: "pass" | "warn" | "fail" | "error" | "inconclusive";
  score: number;
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  badge: {
    tier: string;
    label: string;
    security_verified: boolean;
    continuously_monitored: boolean;
    expires_at_iso: string | null;
    reason?: string;
    signed?: {
      fingerprint: string;
      badge_id: string;
      verification_url?: string;
    };
  };
  artifacts: {
    report_json: string;
    report_pdf: string | null;
    snapshot: string | null;
    diff: string | null;
    pulse: string | null;
  };
}

/**
 * Generate summary.json from scan result
 */
export function generateSummaryJson(
  scanResult: ScanResult,
  kind: "coin" | "fa" | "wallet",
  target: string,
  level: number,
  outDir: string,
  pdfRequested: boolean,
  pulseMetadata: PulseMetadata | null,
  badgeResult?: BadgeResult,
  signedBadge?: SignedBadge | null
): SummaryJson {
  // Use badge result if provided, otherwise fall back to badge_eligibility
  const badge = badgeResult || (scanResult as any).badge;
  const badgeEligibility = scanResult.summary.badge_eligibility || {
    scanned: true,
    no_critical: true,
    security_verified: false,
    continuously_monitored: false,
    reasons: [],
    expires_at_iso: undefined,
  };

  // Determine artifacts
  const artifacts: SummaryJson["artifacts"] = {
    report_json: "report.json",
    report_pdf: pdfRequested ? "report.pdf" : null,
    snapshot: null,
    diff: null,
    pulse: null,
  };

  // Check for snapshot/diff artifacts
  const artifactsPath = join(outDir, "artifacts");
  if (existsSync(join(artifactsPath, "snapshot.json"))) {
    artifacts.snapshot = "artifacts/snapshot.json";
  }
  if (existsSync(join(artifactsPath, "diff.json"))) {
    artifacts.diff = "artifacts/diff.json";
  }
  if (pulseMetadata && pulseMetadata.filename) {
    artifacts.pulse = `artifacts/${pulseMetadata.filename}`;
  }

  return {
    target: {
      kind,
      value: target,
    },
    time_utc: scanResult.timestamp_iso,
    level,
    verdict: scanResult.summary.verdict === "inconclusive" ? "warn" : scanResult.summary.verdict,
    score: scanResult.summary.risk_score,
    severity: scanResult.summary.severity_counts,
    badge: {
      tier: badge?.tier || "NONE",
      label: badge?.label || "No Badge",
      security_verified: badge?.tier === "SECURITY_VERIFIED" || badge?.tier === "CONTINUOUSLY_MONITORED" || badgeEligibility.security_verified || false,
      continuously_monitored: badge?.continuously_monitored || badgeEligibility.continuously_monitored || false,
      expires_at_iso: badge?.expires_at_iso || badgeEligibility.expires_at_iso || null,
      reason: badge?.reason,
      signed: signedBadge ? {
        fingerprint: signedBadge.fingerprint,
        badge_id: signedBadge.payload.scan_id,
        verification_url: process.env.SSA_BADGE_VERIFICATION_URL || `https://ssa.supra.com/verify/${signedBadge.payload.scan_id}`,
      } : undefined,
    },
    artifacts,
  };
}

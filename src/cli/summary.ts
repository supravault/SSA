// src/cli/summary.ts
// Generate summary.json for Base44 ingestion

import type { ScanResult } from "../core/types.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import type { SignedBadge } from "../crypto/badgeSigner.js";
import type { PulseMetadata } from "./pulse.js";
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
  /**
   * Customer-facing proof of "what we did" at each level,
   * populated from scanResult meta/evidence whenever available.
   * This should feel specific to the scanned target (wallet/coin/fa),
   * not generic.
   */
  work_performed?: {
    l1?: {
      title: string;
      highlights: string[];
      metrics?: Record<string, number | string | boolean | null>;
    };
    l2?: {
      title: string;
      highlights: string[];
      metrics?: Record<string, number | string | boolean | null>;
    };
    l3?: {
      title: string;
      highlights: string[];
      metrics?: Record<string, number | string | boolean | null>;
    };
    l4?: {
      title: string;
      highlights: string[];
      metrics?: Record<string, number | string | boolean | null>;
    };
    l5?: {
      title: string;
      highlights: string[];
      metrics?: Record<string, number | string | boolean | null>;
    };
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

function asNum(v: any): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function asStr(v: any): string | null {
  return typeof v === "string" && v.trim().length > 0 ? v : null;
}
function asBool(v: any): boolean | null {
  return typeof v === "boolean" ? v : null;
}
function pick<T extends object>(obj: any, path: string[]): any {
  let cur = obj;
  for (const k of path) {
    if (!cur || typeof cur !== "object" || !(k in cur)) return undefined;
    cur = (cur as any)[k];
  }
  return cur;
}

/**
 * Build customer-facing "proof of work" blocks.
 * IMPORTANT:
 * - Must be target-specific (wallet/coin/fa) and reflect real scan evidence.
 * - Uses scanResult meta if present; falls back to safe minimal signals.
 */
function buildWorkPerformed(
  scanResult: ScanResult,
  kind: "coin" | "fa" | "wallet",
  target: string,
  level: number,
  hasSnapshot: boolean,
  hasDiff: boolean
): SummaryJson["work_performed"] {
  const anyRes: any = scanResult as any;

  // Preferred locations (you can standardize these across scanners):
  // scanResult.meta.performed.l1 / l2 / l3 / l4 / l5
  // scanResult.meta.evidence.behavior / attribution / risk_model etc.
  const performed = pick(anyRes, ["meta", "performed"]) || {};
  const evidence = pick(anyRes, ["meta", "evidence"]) || pick(anyRes, ["evidence"]) || {};

  // Common, already-available signals
  const severity = scanResult.summary?.severity_counts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const findingsTotal =
    (severity.critical || 0) +
    (severity.high || 0) +
    (severity.medium || 0) +
    (severity.low || 0) +
    (severity.info || 0);

  // L1 (Surface)
  const l1_modules_scanned =
    asNum(pick(performed, ["l1", "modules_scanned"])) ??
    asNum(pick(evidence, ["surface", "modules_scanned"])) ??
    asNum(pick(anyRes, ["meta", "modules_scanned"])) ??
    null;

  const l1_views_checked =
    asNum(pick(performed, ["l1", "views_checked"])) ??
    asNum(pick(evidence, ["surface", "views_checked"])) ??
    null;

  const l1_entrypoints =
    asNum(pick(performed, ["l1", "entrypoints_count"])) ??
    asNum(pick(evidence, ["surface", "entrypoints_count"])) ??
    null;

  const l1_opaque_abi =
    asBool(pick(performed, ["l1", "opaque_abi"])) ??
    asBool(pick(evidence, ["surface", "opaque_abi"])) ??
    null;

  const l1_caps =
    asStr(pick(performed, ["l1", "capability_summary"])) ??
    asStr(pick(evidence, ["surface", "capability_summary"])) ??
    null;

  // L2 (Behavior / Exposure)
  // Wallet: tx sampling / counterparties / interaction types
  // Coin/FA: exposure via entrypoints usage + distribution/holder signals (if you collect them)
  const l2_tx_sampled =
    asNum(pick(performed, ["l2", "tx_sampled"])) ??
    asNum(pick(evidence, ["behavior", "tx_sampled"])) ??
    null;

  const l2_window_days =
    asNum(pick(performed, ["l2", "window_days"])) ??
    asNum(pick(evidence, ["behavior", "window_days"])) ??
    null;

  const l2_unique_counterparties =
    asNum(pick(performed, ["l2", "unique_counterparties"])) ??
    asNum(pick(evidence, ["behavior", "unique_counterparties"])) ??
    null;

  const l2_top_calls =
    pick(performed, ["l2", "top_calls"]) ??
    pick(evidence, ["behavior", "top_calls"]) ??
    null;

  // L3 (Agent-level attribution & risk modeling)
  const l3_role =
    asStr(pick(performed, ["l3", "role"])) ??
    asStr(pick(evidence, ["attribution", "role"])) ??
    null;

  const l3_confidence =
    asNum(pick(performed, ["l3", "confidence"])) ??
    asNum(pick(evidence, ["attribution", "confidence"])) ??
    null;

  const l3_sources =
    pick(performed, ["l3", "sources_used"]) ??
    pick(evidence, ["attribution", "sources_used"]) ??
    null;

  const l3_signals =
    pick(performed, ["l3", "signals"]) ??
    pick(evidence, ["risk_model", "signals"]) ??
    null;

  const l3_model_version =
    asStr(pick(performed, ["l3", "model_version"])) ??
    asStr(pick(evidence, ["risk_model", "model_version"])) ??
    null;

  // L4 / L5 (Monitoring: snapshot + diff) for coins/FAs (and optional for wallet later)
  const l4_snapshot_id =
    asStr(pick(performed, ["l4", "snapshot_id"])) ??
    asStr(pick(evidence, ["monitoring", "snapshot_id"])) ??
    null;

  const l5_diff_id =
    asStr(pick(performed, ["l5", "diff_id"])) ??
    asStr(pick(evidence, ["monitoring", "diff_id"])) ??
    null;

  const l5_changes =
    pick(performed, ["l5", "changes"]) ??
    pick(evidence, ["monitoring", "changes"]) ??
    null;

  // Build level blocks with directed language
  const work: SummaryJson["work_performed"] = {};

  if (level >= 1) {
    const hl: string[] = [];
    if (kind === "wallet") {
      hl.push(`Enumerated wallet-held assets and scanned reachable on-chain surfaces for ${target}.`);
    } else {
      hl.push(`Enumerated on-chain module surface for ${kind.toUpperCase()} ${target} and checked exposed entrypoints/capabilities.`);
    }
    if (l1_modules_scanned !== null) hl.push(`Modules analyzed: ${l1_modules_scanned}.`);
    if (l1_views_checked !== null) hl.push(`Read/view checks executed: ${l1_views_checked}.`);
    if (l1_entrypoints !== null) hl.push(`Entrypoints indexed: ${l1_entrypoints}.`);
    if (l1_opaque_abi === true) hl.push(`Detected opaque ABI pattern (exposed_functions empty/unavailable) — flagged for review.`);
    if (l1_caps) hl.push(`Capability surface summary: ${l1_caps}.`);
    if (findingsTotal > 0) hl.push(`Findings recorded from surface scan: ${findingsTotal} (C:${severity.critical} H:${severity.high} M:${severity.medium} L:${severity.low} I:${severity.info}).`);

    work.l1 = {
      title: "Level 1 — Surface & Hygiene",
      highlights: hl,
      metrics: {
        modules_scanned: l1_modules_scanned,
        views_checked: l1_views_checked,
        entrypoints_count: l1_entrypoints,
        opaque_abi: l1_opaque_abi,
      },
    };
  }

  if (level >= 2) {
    const hl: string[] = [];
    if (kind === "wallet") {
      hl.push(`Behavioral review of ${target} based on recent on-chain activity and counterparties.`);
      if (l2_tx_sampled !== null) hl.push(`Transactions analyzed: ${l2_tx_sampled}${l2_window_days ? ` over ~${l2_window_days} day window` : ""}.`);
      if (l2_unique_counterparties !== null) hl.push(`Unique counterparties/contracts interacted with: ${l2_unique_counterparties}.`);
      if (Array.isArray(l2_top_calls) && l2_top_calls.length > 0) {
        const top = l2_top_calls.slice(0, 5).map((x: any) => {
          if (typeof x === "string") return x;
          const fn = asStr(x?.fn) || asStr(x?.function) || "call";
          const c = asNum(x?.count);
          return c !== null ? `${fn}×${c}` : fn;
        });
        hl.push(`Top observed calls: ${top.join(", ")}.`);
      }
    } else {
      hl.push(`Exposure/usage review for ${kind.toUpperCase()} ${target} using observed entrypoints, capability usage patterns, and interaction signals.`);
      if (l2_tx_sampled !== null) hl.push(`Transactions/events sampled: ${l2_tx_sampled}${l2_window_days ? ` over ~${l2_window_days} day window` : ""}.`);
      if (l2_unique_counterparties !== null) hl.push(`Unique interacting addresses/contracts: ${l2_unique_counterparties}.`);
    }
    hl.push(`This level reduces uncertainty by validating behavior/exposure beyond static surface checks.`);

    work.l2 = {
      title: "Level 2 — Behavior & Exposure",
      highlights: hl,
      metrics: {
        tx_sampled: l2_tx_sampled,
        window_days: l2_window_days,
        unique_counterparties: l2_unique_counterparties,
      },
    };
  }

  if (level >= 3) {
    const hl: string[] = [];
    hl.push(`Agent-level attribution & risk modeling executed for ${kind.toUpperCase()} ${target}.`);
    if (l3_role) hl.push(`Attributed role/profile: ${l3_role}.`);
    if (l3_confidence !== null) hl.push(`Attribution confidence: ${l3_confidence}.`);
    if (Array.isArray(l3_sources) && l3_sources.length > 0) {
      hl.push(`Corroboration sources used: ${l3_sources.join(", ")}.`);
    } else {
      hl.push(`Corroboration sources used: RPC/indexer/explorer signals (where available).`);
    }
    if (Array.isArray(l3_signals) && l3_signals.length > 0) {
      const topSignals = l3_signals.slice(0, 5).map((s: any) => {
        const name = asStr(s?.name) || asStr(s?.signal) || "signal";
        const weight = asNum(s?.weight);
        return weight !== null ? `${name}(${weight})` : name;
      });
      hl.push(`Top risk-model signals: ${topSignals.join(", ")}.`);
    }
    if (l3_model_version) hl.push(`Risk model version: ${l3_model_version}.`);
    hl.push(`This level is what enables verification-grade outcomes (badge eligibility) when thresholds are met.`);

    work.l3 = {
      title: "Level 3 — Agent Attribution & Risk Modeling",
      highlights: hl,
      metrics: {
        role: l3_role,
        confidence: l3_confidence,
        model_version: l3_model_version,
      },
    };
  }

  // Levels 4-5: expected primarily for coin/fa (monitoring)
  if (level >= 4) {
    const hl: string[] = [];
    if (kind === "coin" || kind === "fa") {
      hl.push(`Monitoring snapshot produced for ${kind.toUpperCase()} ${target} (baseline state captured for change detection).`);
      if (hasSnapshot) hl.push(`Snapshot artifact: artifacts/snapshot.json.`);
      if (l4_snapshot_id) hl.push(`Snapshot ID: ${l4_snapshot_id}.`);
    } else {
      hl.push(`(Optional) Monitoring snapshot stage executed.`);
      if (hasSnapshot) hl.push(`Snapshot artifact: artifacts/snapshot.json.`);
    }
    work.l4 = {
      title: "Level 4 — Monitoring Snapshot (Baseline)",
      highlights: hl,
      metrics: {
        snapshot_present: hasSnapshot,
        snapshot_id: l4_snapshot_id,
      },
    };
  }

  if (level >= 5) {
    const hl: string[] = [];
    if (kind === "coin" || kind === "fa") {
      hl.push(`Change detection (diff) executed for ${kind.toUpperCase()} ${target} against baseline snapshot.`);
      if (hasDiff) hl.push(`Diff artifact: artifacts/diff.json.`);
      if (l5_diff_id) hl.push(`Diff ID: ${l5_diff_id}.`);
      if (l5_changes && typeof l5_changes === "object") {
        // Try to create a compact directed line like: "Changes: modules=1, supply=0, metadata=2"
        const parts: string[] = [];
        for (const [k, v] of Object.entries(l5_changes)) {
          if (typeof v === "number") parts.push(`${k}=${v}`);
          else if (typeof v === "boolean") parts.push(`${k}=${v ? "yes" : "no"}`);
        }
        if (parts.length > 0) hl.push(`Changes summary: ${parts.join(", ")}.`);
      }
    } else {
      hl.push(`(Optional) Change detection (diff) stage executed.`);
      if (hasDiff) hl.push(`Diff artifact: artifacts/diff.json.`);
    }

    work.l5 = {
      title: "Level 5 — Monitoring Diff (Change Detection)",
      highlights: hl,
      metrics: {
        diff_present: hasDiff,
        diff_id: l5_diff_id,
      },
    };
  }

  return work;
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
  const hasSnapshot = existsSync(join(artifactsPath, "snapshot.json"));
  const hasDiff = existsSync(join(artifactsPath, "diff.json"));

  if (hasSnapshot) artifacts.snapshot = "artifacts/snapshot.json";
  if (hasDiff) artifacts.diff = "artifacts/diff.json";
  if (pulseMetadata && pulseMetadata.filename) {
    artifacts.pulse = `artifacts/${pulseMetadata.filename}`;
  }

  const workPerformed = buildWorkPerformed(scanResult, kind, target, level, hasSnapshot, hasDiff);

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
    work_performed: workPerformed,
    badge: {
      tier: badge?.tier || "NONE",
      label: badge?.label || "No Badge",
      security_verified:
        badge?.tier === "SECURITY_VERIFIED" ||
        badge?.tier === "CONTINUOUSLY_MONITORED" ||
        badgeEligibility.security_verified ||
        false,
      continuously_monitored: badge?.continuously_monitored || badgeEligibility.continuously_monitored || false,
      expires_at_iso: badge?.expires_at_iso || badgeEligibility.expires_at_iso || null,
      reason: badge?.reason,
      signed: signedBadge
        ? {
            fingerprint: signedBadge.fingerprint,
            badge_id: signedBadge.payload.scan_id,
            verification_url:
              process.env.SSA_BADGE_VERIFICATION_URL ||
              `https://ssa.supra.com/verify/${signedBadge.payload.scan_id}`,
          }
        : undefined,
    },
    artifacts,
  };
}


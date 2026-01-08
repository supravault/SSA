// src/report/archive/archive.ts
// Report archiving and storage

import { mkdirSync, writeFileSync, copyFileSync, existsSync, readFileSync } from "fs";
import { join, dirname, basename } from "path";
import { createHash } from "crypto";
import type { ScanResult } from "../../core/types.js";
import type { BadgeResult } from "../../policy/badgePolicy.js";
import type { PulseMetadata } from "../../cli/pulse.js";

export interface ArchiveIndex {
  scan_id: string;
  target: {
    chain: string;
    type: string;
    id: string;
  };
  level: number;
  verdict: string;
  risk_score: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  badges_issued: string[];
  expires_at: string | null;
  pulse_included: boolean;
  timestamp_iso: string;
}

/**
 * Compute SHA256 hash of a file
 */
function computeFileHash(filePath: string): string {
  const hash = createHash("sha256");
  const data = readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex");
}

/**
 * Archive scan report
 */
export function archiveReport(
  scanResult: ScanResult,
  badgeResult: BadgeResult | null,
  signedBadge: any,
  pdfPath: string,
  pulsePath: string | null,
  baseDir: string = "data/reports"
): string {
  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";
  const chain = target?.chain || "supra";
  const targetId = target?.module_id || target?.address || scanResult.request_id;
  
  // Sanitize target ID for filesystem
  const sanitizedTargetId = targetId.replace(/[^a-zA-Z0-9]/g, "_").substring(0, 50);
  
  // Create archive path: data/reports/<chain>/<target_type>/<target_id>/<scan_id>/
  const archivePath = join(
    baseDir,
    chain,
    kind,
    sanitizedTargetId,
    scanResult.request_id
  );

  mkdirSync(archivePath, { recursive: true });

  // Write report.json
  writeFileSync(
    join(archivePath, "report.json"),
    JSON.stringify(scanResult, null, 2)
  );

  // Copy PDF
  if (existsSync(pdfPath)) {
    copyFileSync(pdfPath, join(archivePath, "report.pdf"));
  }

  // Write badge.json if signed badge exists
  if (signedBadge) {
    writeFileSync(
      join(archivePath, "badge.json"),
      JSON.stringify(signedBadge, null, 2)
    );
  } else if (badgeResult && badgeResult.tier !== "NONE") {
    // Write badge result even if not signed
    writeFileSync(
      join(archivePath, "badge.json"),
      JSON.stringify(badgeResult, null, 2)
    );
  }

  // Copy pulse artifact if present
  if (pulsePath && existsSync(pulsePath)) {
    const pulseDir = join(archivePath, "pulse");
    mkdirSync(pulseDir, { recursive: true });
    const pulseFileName = basename(pulsePath);
    copyFileSync(pulsePath, join(pulseDir, pulseFileName));
  }

  // Create index.json
  const badgesIssued: string[] = [];
  if (badgeResult && badgeResult.tier !== "NONE") {
    badgesIssued.push(badgeResult.tier);
  }

  const index: ArchiveIndex = {
    scan_id: scanResult.request_id,
    target: {
      chain,
      type: kind,
      id: targetId,
    },
    level: (scanResult as any).scan_level_num || 1,
    verdict: scanResult.summary.verdict,
    risk_score: scanResult.summary.risk_score,
    severity_counts: scanResult.summary.severity_counts,
    badges_issued: badgesIssued,
    expires_at: badgeResult?.expires_at_iso || null,
    pulse_included: !!pulsePath,
    timestamp_iso: scanResult.timestamp_iso,
  };

  writeFileSync(
    join(archivePath, "index.json"),
    JSON.stringify(index, null, 2)
  );

  return archivePath;
}

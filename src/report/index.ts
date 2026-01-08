// src/report/index.ts
// Main report generation entry point

import { renderPdf, closeBrowser } from "./render/pdf.js";
import { archiveReport } from "./archive/archive.js";
import type { ScanResult } from "../core/types.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import type { PulseMetadata } from "../cli/pulse.js";

export interface ReportOptions {
  scanResult: ScanResult;
  badgeResult: BadgeResult | null;
  signedBadge?: any;
  pulseMetadata?: PulseMetadata | null;
  pulsePath?: string | null;
  outputDir?: string;
  baseArchiveDir?: string;
}

export interface ReportOutput {
  pdfPath: string;
  archivePath: string;
  indexPath: string;
}

/**
 * Generate and archive PDF report
 */
export async function generateReport(options: ReportOptions): Promise<ReportOutput> {
  const {
    scanResult,
    badgeResult,
    signedBadge,
    pulseMetadata,
    pulsePath,
    outputDir = "tmp",
    baseArchiveDir = "data/reports",
  } = options;

  const { mkdirSync } = await import("fs");
  const { join } = await import("path");

  // Create output directory
  mkdirSync(outputDir, { recursive: true });

  // Generate PDF
  const pdfPath = join(outputDir, `report_${scanResult.request_id}.pdf`);
  await renderPdf(scanResult, badgeResult, signedBadge || null, pulseMetadata || null, pdfPath);

  // Archive report
  const archivePath = archiveReport(
    scanResult,
    badgeResult,
    signedBadge,
    pdfPath,
    pulsePath || null,
    baseArchiveDir
  );

  const indexPath = join(archivePath, "index.json");

  return {
    pdfPath,
    archivePath,
    indexPath,
  };
}

/**
 * Cleanup browser instance (call when done)
 */
export { closeBrowser };

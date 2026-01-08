// src/report/fullIntegratedGenerator.ts
// Full Integrated Report PDF generator with canonical structure

import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import type { ScanResult } from "../core/types.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import { createHash } from "crypto";
import { buildFullIntegratedViewModel } from "./viewModel/fullIntegratedViewModel.js";
import { renderFullIntegratedHtml } from "./templates/fullIntegratedReportHtml.js";
import { renderHtmlToPdf, closeHtmlPdfBrowser } from "./htmlPdf.js";

export interface FullIntegratedInputs {
  scans: ScanResult[];
  badges: (BadgeResult | null)[];
  riskBadges: (BadgeResult | null)[];
  signedBadges?: any[];
  pulseSummary?: {
    tier: string;
    score?: number;
    timestamp?: string;
    timestamp_utc?: string;
    interpretation?: string;
    summary?: string;
    verdict?: string;
    disclosure?: string;
    verdictDerived?: boolean; // Flag indicating if verdict was derived from score
  };
  generatorVersion: string;
  timestampUtc: string;
}

export interface FullIntegratedReportOptions {
  inputs: FullIntegratedInputs;
  projectName: string;
  outputPath: string;
  reportId: string;
  inputChecksum: string;
  isFullIntegrated: boolean; // True if Pulse tier is Premium/Spotlight
}

/**
 * Canonicalize JSON with stable key ordering
 */
export function canonicalizeJson(obj: any): string {
  if (obj === null || obj === undefined) {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalizeJson).join(",") + "]";
  }
  if (typeof obj === "object") {
    const sortedKeys = Object.keys(obj).sort();
    const items = sortedKeys.map(key => {
      return JSON.stringify(key) + ":" + canonicalizeJson(obj[key]);
    });
    return "{" + items.join(",") + "}";
  }
  return JSON.stringify(obj);
}

/**
 * Compute input checksum from canonicalized inputs bundle
 */
export function computeInputChecksum(inputs: FullIntegratedInputs): string {
  const canonical = canonicalizeJson(inputs);
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Extract report ID from input checksum (first 12 chars)
 */
export function deriveReportId(inputChecksum: string): string {
  return inputChecksum.substring(0, 12).toUpperCase();
}

/**
 * Safely extract verdict from a scan object
 * Returns "UNKNOWN" if no verdict can be determined (never throws)
 */
export function getScanVerdict(scan: any): string {
  // Try summary.verdict first
  if (scan?.summary?.verdict) {
    return scan.summary.verdict;
  }
  
  // Try direct verdict property
  if (scan?.verdict) {
    return scan.verdict;
  }
  
  // Try to derive from risk.risk_level
  if ((scan as any)?.risk?.risk_level) {
    const riskLevel = (scan as any).risk.risk_level.toUpperCase();
    if (riskLevel === "LOW_RISK") {
      return "pass";
    } else if (riskLevel === "ELEVATED_RISK") {
      return "pass_with_notes";
    } else if (riskLevel === "HIGH_RISK") {
      return "warn";
    }
  }
  
  // Fallback to UNKNOWN (never throw)
  return "UNKNOWN";
}

/**
 * Derive Pulse verdict from score if verdict is not provided
 * Returns verdict and a flag indicating if it was derived
 */
export function derivePulseVerdict(score?: number, existingVerdict?: string): { verdict: string; derived: boolean } {
  // If verdict already exists, use it
  if (existingVerdict) {
    return { verdict: existingVerdict, derived: false };
  }
  
  // Derive from score if available
  if (score !== undefined && score !== null) {
    if (score >= 85) {
      return { verdict: "PASS", derived: true };
    } else if (score >= 70) {
      return { verdict: "PASS_WITH_NOTES", derived: true };
    } else {
      return { verdict: "WARN", derived: true };
    }
  }
  
  // Fallback to UNKNOWN if no score available
  return { verdict: "UNKNOWN", derived: true };
}

/**
 * Generate Full Integrated Report PDF
 */
export async function generateFullIntegratedReport(
  options: FullIntegratedReportOptions
): Promise<string> {
  const { inputs, projectName, outputPath, reportId, inputChecksum, isFullIntegrated } = options;

  try {
    // Build view model
    const viewModel = buildFullIntegratedViewModel(inputs, projectName, reportId, inputChecksum);

    // Generate HTML
    const html = renderFullIntegratedHtml(viewModel, isFullIntegrated);

    // Render HTML to PDF using Playwright
    await renderHtmlToPdf(html, outputPath);

    // Compute PDF checksum after file is written
    const pdfBytes = readFileSync(outputPath);
    const pdfChecksum = createHash("sha256").update(pdfBytes).digest("hex");

    return pdfChecksum;
  } finally {
    // Close browser instance
    await closeHtmlPdfBrowser();
  }
}

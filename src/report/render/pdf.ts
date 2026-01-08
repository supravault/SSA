// src/report/render/pdf.ts
// PDF rendering using Playwright

import type { Browser } from "playwright";
import { generateReportHtml } from "../templates/reportHtml.js";
import type { ScanResult } from "../../core/types.js";
import type { BadgeResult } from "../../policy/badgePolicy.js";
import type { PulseMetadata } from "../../cli/pulse.js";

let browser: Browser | null = null;

/**
 * Initialize browser instance (reused across renders)
 * Lazy import playwright to avoid blocking wallet scans
 */
async function getBrowser(): Promise<Browser> {
  if (!browser) {
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: true,
    });
  }
  return browser;
}

/**
 * Close browser instance
 */
export async function closeBrowser(): Promise<void> {
  if (browser) {
    await browser.close();
    browser = null;
  }
}

/**
 * Render PDF from scan result
 */
export async function renderPdf(
  scanResult: ScanResult,
  badgeResult: BadgeResult | null,
  signedBadge: any,
  pulseMetadata: PulseMetadata | null,
  outputPath: string
): Promise<void> {
  const browserInstance = await getBrowser();
  const page = await browserInstance.newPage();

  try {
    // Generate HTML
    const html = generateReportHtml({
      scanResult,
      badgeResult,
      signedBadge,
      pulseMetadata,
      reportId: scanResult.request_id,
      generatedAt: new Date().toISOString(),
    });

    // Set HTML content
    await page.setContent(html, { waitUntil: "networkidle" });

    // Generate PDF
    await page.pdf({
      path: outputPath,
      format: "A4",
      margin: {
        top: "20mm",
        right: "15mm",
        bottom: "20mm",
        left: "15mm",
      },
      printBackground: true,
      preferCSSPageSize: true,
    });
  } finally {
    await page.close();
  }
}

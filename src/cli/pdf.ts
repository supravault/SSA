// src/cli/pdf.ts
// PDF report generator

import { createWriteStream } from "fs";
import type { ScanResult } from "../core/types.js";
import type { PulseMetadata } from "./pulse.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import type { SignedBadge } from "../crypto/badgeSigner.js";

/**
 * Generate PDF report from scan result
 * Uses pdfkit for lightweight PDF generation
 */
export async function generatePdfReport(
  scanResult: ScanResult,
  pulseMetadata: PulseMetadata | null,
  outputPath: string,
  badgeResult?: BadgeResult,
  signedBadge?: SignedBadge | null
): Promise<void> {
  try {
    // Try to use pdfkit if available
    let PDFDocument: any;
    try {
      const pdfkit = await import("pdfkit");
      PDFDocument = pdfkit.default || (pdfkit as any).PDFDocument || pdfkit;
    } catch (error) {
      console.warn("PDF generation requires pdfkit. Install with: npm install pdfkit @types/pdfkit");
      console.warn(`Error: ${error instanceof Error ? error.message : String(error)}`);
      // Create a simple text file as fallback
      const { writeFileSync } = await import("fs");
      const textReport = `SSA Security Scan Report
========================

Target: ${scanResult.target.module_id || scanResult.target.address}
Timestamp: ${scanResult.timestamp_iso}
Verdict: ${scanResult.summary.verdict.toUpperCase()}
Risk Score: ${scanResult.summary.risk_score}/100

Findings: ${scanResult.findings.length}
${scanResult.findings.map((f) => `- ${f.id}: ${f.title} (${f.severity})`).join("\n")}

Note: Full PDF report requires pdfkit. Install with: npm install pdfkit @types/pdfkit
`;
      writeFileSync(outputPath.replace(".pdf", ".txt"), textReport);
      return;
    }

    // Create PDF document
    const doc = new PDFDocument({ margin: 50 });
    const stream = createWriteStream(outputPath);
    doc.pipe(stream);

    // Header
    doc.fontSize(20).text("SSA Security Scan Report", { align: "center" });
    doc.moveDown();

    // Target information
    doc.fontSize(14).text("Target Information", { underline: true });
    doc.fontSize(10);
    doc.text(`Target: ${scanResult.target.module_id || scanResult.target.address}`);
    doc.text(`Kind: ${(scanResult as any).target?.kind || "unknown"}`);
    doc.text(`Scan Level: ${(scanResult as any).scan_level_str || scanResult.scan_level}`);
    doc.text(`Timestamp: ${scanResult.timestamp_iso}`);
    doc.moveDown();

    // Summary
    doc.fontSize(14).text("Summary", { underline: true });
    doc.fontSize(10);
    doc.text(`Verdict: ${scanResult.summary.verdict.toUpperCase()}`);
    doc.text(`Risk Score: ${scanResult.summary.risk_score}/100`);
    
    // Badge information
    const badge = badgeResult || (scanResult as any).badge;
    if (badge && badge.tier !== "NONE") {
      doc.text(`Badge: ${badge.label}`);
      if (badge.expires_at_iso) {
        doc.text(`Expires: ${badge.expires_at_iso}`);
      } else if (badge.continuously_monitored) {
        doc.text(`Status: Continuously Monitored (rolling)`);
      }
      
      // Include signed badge information if available
      if (signedBadge) {
        doc.moveDown(0.5);
        doc.fontSize(9).fillColor("gray");
        doc.text(`Badge ID: ${signedBadge.payload.scan_id}`);
        const verificationUrl = process.env.SSA_BADGE_VERIFICATION_URL || 
          `https://ssa.supra.com/verify/${signedBadge.payload.scan_id}`;
        doc.text(`Verification: ${verificationUrl}`);
        doc.text(`Signature Fingerprint: ${signedBadge.fingerprint}`);
        doc.fontSize(10).fillColor("black");
      }
    } else {
      const badgeEligibility = scanResult.summary.badge_eligibility;
      if (badgeEligibility) {
        doc.text(`Security Verified: ${badgeEligibility.security_verified ? "Yes" : "No"}`);
        if (badgeEligibility.expires_at_iso) {
          doc.text(`Expires: ${badgeEligibility.expires_at_iso}`);
        }
      }
    }
    doc.moveDown();

    // Severity summary table
    doc.fontSize(14).text("Severity Summary", { underline: true });
    doc.fontSize(10);
    const counts = scanResult.summary.severity_counts;
    doc.text(`Critical: ${counts.critical}`);
    doc.text(`High: ${counts.high}`);
    doc.text(`Medium: ${counts.medium}`);
    doc.text(`Low: ${counts.low}`);
    doc.text(`Info: ${counts.info}`);
    doc.moveDown();

    // Findings
    if (scanResult.findings.length > 0) {
      doc.fontSize(14).text("Findings", { underline: true });
      doc.fontSize(10);

      // Group by severity
      const bySeverity: Record<string, typeof scanResult.findings> = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        info: [],
      };

      for (const finding of scanResult.findings) {
        if (!bySeverity[finding.severity]) {
          bySeverity[finding.severity] = [];
        }
        bySeverity[finding.severity].push(finding);
      }

      for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
        const findings = bySeverity[severity];
        if (findings.length > 0) {
          doc.fontSize(12).text(`${severity.toUpperCase()} (${findings.length})`, { underline: true });
          doc.fontSize(10);
          for (const finding of findings) {
            doc.text(`ID: ${finding.id}`);
            doc.text(`Title: ${finding.title}`);
            doc.text(`Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
            doc.text(`Description: ${finding.description}`);
            if (finding.recommendation) {
              doc.text(`Recommendation: ${finding.recommendation}`);
            }
            if ((finding as any).module_id) {
              doc.text(`Module: ${(finding as any).module_id}`);
            }
            doc.moveDown(0.5);
          }
        }
      }
      doc.moveDown();
    }

    // Supra Pulse Intelligence section
    if (pulseMetadata) {
      doc.addPage();
      doc.fontSize(14).text("Supra Pulse Intelligence (Integrated)", { underline: true });
      doc.fontSize(10);
      doc.text("Supra Pulse report integrated and attached.");
      doc.text(`Filename: ${pulseMetadata.filename}`);
      doc.text(`SHA256: ${pulseMetadata.sha256}`);
      doc.text(`Kind: ${pulseMetadata.kind.toUpperCase()}`);

      if (pulseMetadata.extracted_summary && pulseMetadata.extracted_summary.length > 0) {
        doc.moveDown();
        doc.fontSize(12).text("Key Points:", { underline: true });
        doc.fontSize(10);
        for (const point of pulseMetadata.extracted_summary.slice(0, 10)) {
          doc.text(`• ${point}`);
        }
      }

      if (pulseMetadata.raw_text_excerpt) {
        doc.moveDown();
        doc.fontSize(12).text("Excerpt:", { underline: true });
        doc.fontSize(9);
        doc.text(pulseMetadata.raw_text_excerpt.substring(0, 500));
      }
    }

    // Finalize PDF
    doc.end();

    // Wait for stream to finish
    await new Promise((resolve, reject) => {
      stream.on("finish", resolve);
      stream.on("error", reject);
    });
  } catch (error) {
    console.error(`PDF generation failed: ${error instanceof Error ? error.message : String(error)}`);
    // Don't fail the scan if PDF generation fails
  }
}

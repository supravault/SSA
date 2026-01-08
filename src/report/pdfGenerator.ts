// src/report/pdfGenerator.ts
// PDF report generator with badge placement and red wax seal

import { readFileSync, existsSync, createWriteStream } from "fs";
import { join } from "path";
import type { ScanResult } from "../core/types.js";
import type { BadgeResult } from "../policy/badgePolicy.js";
import type { PulseMetadata } from "../cli/pulse.js";
import PDFDocument from "pdfkit";
import { createHash } from "crypto";
import QRCode from "qrcode";

export interface PdfReportOptions {
  scanResult: ScanResult;
  badgeResult: BadgeResult | null;
  riskBadgeResult: BadgeResult | null;
  signedBadge?: any;
  pulseMetadata?: PulseMetadata | null;
  pulseData?: {
    projectName?: string;
    tier?: string;
    premiumTotalScore?: number;
    keyBreakdown?: string[];
    extracted_summary?: string[];
  };
  walletScanResult?: ScanResult | null; // Optional wallet scan
  outputPath: string;
  verificationUrl?: string; // Base URL for verification
}

/**
 * Generate PDF report with badge placement and red wax seal
 */
export async function generatePdfReport(options: PdfReportOptions): Promise<void> {
  const {
    scanResult,
    badgeResult,
    riskBadgeResult,
    signedBadge,
    pulseMetadata,
    pulseData,
    walletScanResult,
    outputPath,
    verificationUrl = "https://ssa.supra.com/verify",
  } = options;

  const doc = new PDFDocument({
    size: "A4",
    margins: { top: 50, bottom: 50, left: 50, right: 50 },
  });

  const stream = createWriteStream(outputPath);
  doc.pipe(stream);

  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";
  const scanLevel = (scanResult as any).scan_level_num ||
    (typeof scanResult.scan_level === "string"
      ? parseInt(scanResult.scan_level.replace(/[^0-9]/g, "")) || 1
      : 1);

  // Check if eligible for Full Integrated Report
  // Requires: Pulse tier is Premium or Spotlight (not Free/summary)
  const pulseTier = pulseData?.tier?.toLowerCase() || "";
  const isEligibleTier = pulseTier === "premium" || pulseTier === "spotlight";
  const isFullIntegrated = !!(pulseMetadata && pulseData && isEligibleTier);
  
  const walletTarget = walletScanResult?.target as any;
  const walletKind = walletTarget?.kind || "unknown";
  const walletScanLevel = walletScanResult ? 
    ((walletScanResult as any).scan_level_num ||
      (typeof walletScanResult.scan_level === "string"
        ? parseInt(walletScanResult.scan_level.replace(/[^0-9]/g, "")) || 1
        : 1)) : null;

  // Header on every page
  function addHeader() {
    doc.fontSize(10).fillColor("#666");
    doc.text("SSA Security Scan Report", 50, 30, { align: "left" });
    doc.text(`Report ID: ${scanResult.request_id}`, 50, 42, { align: "left" });
    doc.text(`Generated: ${new Date().toISOString()}`, 50, 54, { align: "left" });
    doc.fillColor("#000");
  }

  // Page 1: Summary + Primary Badge
  addHeader();
  doc.fontSize(24).fillColor("#1a1a1a");
  doc.text("SSA Security Scan Report", 50, 100, { align: "center" });
  
  doc.fontSize(14).fillColor("#666");
  doc.text(`${target.module_id || target.address || "Unknown"}`, 50, 130, { align: "center" });
  doc.text(`Type: ${kind.toUpperCase()} | Level: ${scanLevel}${kind === "wallet" ? " (Wallets support levels 1–3 only)" : ""}`, 50, 150, { align: "center" });

  // Badge placement (if eligible)
  if (badgeResult && badgeResult.tier !== "NONE") {
    const badgeY = 200;
    doc.fontSize(18).fillColor("#2c3e50");
    doc.text(badgeResult.label, 50, badgeY, { align: "center" });
    if (badgeResult.expires_at_iso) {
      doc.fontSize(10).fillColor("#666");
      doc.text(`Expires: ${badgeResult.expires_at_iso}`, 50, badgeY + 25, { align: "center" });
    } else if (badgeResult.continuously_monitored) {
      doc.fontSize(10).fillColor("#666");
      doc.text("Status: Continuously Monitored (rolling)", 50, badgeY + 25, { align: "center" });
    }
  }

  // Risk badge (if present)
  if (riskBadgeResult && riskBadgeResult.tier !== "NONE") {
    const riskY = badgeResult && badgeResult.tier !== "NONE" ? 280 : 200;
    doc.fontSize(16).fillColor("#e74c3c");
    doc.text(riskBadgeResult.label, 50, riskY, { align: "center" });
  }

  // Executive Summary
  doc.fontSize(16).fillColor("#2c3e50");
  doc.text("Executive Summary", 50, 350);

  doc.fontSize(12);
  doc.text(`Verdict: ${scanResult.summary.verdict.toUpperCase()}`, 50, 380);
  doc.text(`Risk Score: ${scanResult.summary.risk_score}/100`, 50, 400);
  doc.text(`Severity Counts:`, 50, 420);
  doc.text(`  Critical: ${scanResult.summary.severity_counts.critical}`, 70, 440);
  doc.text(`  High: ${scanResult.summary.severity_counts.high}`, 70, 455);
  doc.text(`  Medium: ${scanResult.summary.severity_counts.medium}`, 70, 470);
  doc.text(`  Low: ${scanResult.summary.severity_counts.low}`, 70, 485);
  doc.text(`  Info: ${scanResult.summary.severity_counts.info}`, 70, 500);

  // Supra Pulse Executive Summary Box (if included)
  if (isFullIntegrated && pulseData) {
    doc.addPage();
    addHeader();
    doc.fontSize(16).fillColor("#2c3e50");
    doc.text("Executive Summary - Full Integrated Report", 50, 100);

    // Supra Pulse Premium total score + tier
    doc.fontSize(14).fillColor("#2980b9");
    doc.text("Supra Pulse Analysis", 50, 130);
    if (pulseData.projectName) {
      doc.fontSize(12).fillColor("#000");
      doc.text(`Project: ${pulseData.projectName}`, 50, 150);
    }
    if (pulseData.tier) {
      doc.fontSize(12).fillColor("#000");
      doc.text(`Tier: ${pulseData.tier.toUpperCase()}`, 50, 165);
    }
    if (pulseData.premiumTotalScore !== undefined) {
      doc.fontSize(12).fillColor("#000");
      doc.text(`Total Score: ${pulseData.premiumTotalScore}`, 50, 180);
    }

    // Key extracted notes
    if (pulseData.keyBreakdown && pulseData.keyBreakdown.length > 0) {
      doc.fontSize(12).fillColor("#2c3e50");
      doc.text("Key Extracted Notes:", 50, 210);
      let y = 230;
      for (const line of pulseData.keyBreakdown.slice(0, 10)) {
        doc.fontSize(10).fillColor("#000");
        doc.text(`• ${line}`, 70, y, { width: 500 });
        y += 15;
      }
    }

    // Verification choices
    let summaryY = pulseData.keyBreakdown && pulseData.keyBreakdown.length > 0 ? 400 : 250;
    
    doc.fontSize(14).fillColor("#2980b9");
    doc.text("Verification Choices", 50, summaryY);
    
    // Wallet verification (if present)
    if (walletScanResult) {
      doc.fontSize(12).fillColor("#000");
      doc.text(`Wallet Level Selected: ${walletScanLevel}`, 50, summaryY + 25);
      doc.text(`Wallet Result: ${walletScanResult.summary.verdict.toUpperCase()}`, 50, summaryY + 40);
    }
    
    // Coin/FA verification
    doc.fontSize(12).fillColor("#000");
    doc.text(`${kind === "coin" ? "Coin" : "FA"} Level Selected: ${scanLevel}`, 50, summaryY + (walletScanResult ? 60 : 25));
    doc.text(`${kind === "coin" ? "Coin" : "FA"} Result: ${scanResult.summary.verdict.toUpperCase()}`, 50, summaryY + (walletScanResult ? 75 : 40));

    // Results per target
    doc.fontSize(14).fillColor("#2980b9");
    doc.text("Results per Target", 50, summaryY + (walletScanResult ? 110 : 70));
    doc.fontSize(12).fillColor("#000");
    doc.text(`Verdict: ${scanResult.summary.verdict}`, 50, summaryY + (walletScanResult ? 135 : 95));
    doc.text(`Risk Score: ${scanResult.summary.risk_score}/100`, 50, summaryY + (walletScanResult ? 150 : 110));
    doc.text(`Severity Counts: C:${scanResult.summary.severity_counts.critical} H:${scanResult.summary.severity_counts.high} M:${scanResult.summary.severity_counts.medium} L:${scanResult.summary.severity_counts.low} I:${scanResult.summary.severity_counts.info}`, 50, summaryY + (walletScanResult ? 165 : 125));
    doc.text(`Timestamp: ${scanResult.timestamp_iso}`, 50, summaryY + (walletScanResult ? 180 : 140));
    if (badgeResult?.expires_at_iso) {
      doc.text(`Expires At: ${badgeResult.expires_at_iso}`, 50, summaryY + (walletScanResult ? 195 : 155));
    }
  }

  // Findings pages
  const findingsBySeverity: Record<string, typeof scanResult.findings> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };

  for (const finding of scanResult.findings) {
    findingsBySeverity[finding.severity].push(finding);
  }

  for (const [severity, findings] of Object.entries(findingsBySeverity)) {
    if (findings.length === 0) continue;

    doc.addPage();
    addHeader();
    doc.fontSize(18).fillColor("#2c3e50");
    doc.text(`${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity Findings`, 50, 100);

    let y = 130;
    for (const finding of findings) {
      if (y > 700) {
        doc.addPage();
        addHeader();
        y = 100;
      }

      doc.fontSize(12).fillColor("#1a1a1a");
      doc.text(finding.id, 50, y, { underline: true });
      y += 15;

      doc.fontSize(14).fillColor("#2c3e50");
      doc.text(finding.title, 50, y, { width: 500 });
      y += 20;

      doc.fontSize(10).fillColor("#666");
      const severityColor = {
        critical: "#e74c3c",
        high: "#e67e22",
        medium: "#f39c12",
        low: "#3498db",
        info: "#95a5a6",
      }[finding.severity] || "#000";
      doc.fillColor(severityColor);
      doc.text(`Severity: ${finding.severity.toUpperCase()}`, 50, y);
      y += 15;

      doc.fontSize(10).fillColor("#000");
      doc.text(finding.description, 50, y, { width: 500 });
      y += 30;

      if (finding.recommendation) {
        doc.fontSize(10).fillColor("#2980b9");
        doc.text(`Recommendation: ${finding.recommendation}`, 50, y, { width: 500 });
        y += 20;
      }

      // Evidence snippets
      if ((finding as any).evidence?.matched && (finding as any).evidence.matched.length > 0) {
        doc.fontSize(9).fillColor("#7f8c8d");
        doc.text("Evidence:", 50, y);
        y += 12;
        for (const match of (finding as any).evidence.matched.slice(0, 3)) {
          doc.text(`  • ${match}`, 70, y, { width: 450 });
          y += 12;
        }
      }

      y += 20;
    }
  }

  // Supra Pulse section (if included and eligible)
  if (pulseMetadata && isEligibleTier) {
    doc.addPage();
    addHeader();
    doc.fontSize(18).fillColor("#2c3e50");
    doc.text("Supra Pulse Integration", 50, 100);

    doc.fontSize(12);
    doc.text(`Pulse File: ${pulseMetadata.filename}`, 50, 130);
    doc.text(`Kind: ${pulseMetadata.kind.toUpperCase()}`, 50, 150);
    
    if (pulseData?.tier) {
      doc.text(`Tier: ${pulseData.tier.toUpperCase()}`, 50, 170);
    }
    
    if (pulseData?.premiumTotalScore !== undefined) {
      doc.text(`Total Score: ${pulseData.premiumTotalScore}`, 50, 190);
    }
    
    doc.text(`SHA256: ${pulseMetadata.sha256}`, 50, 210, { width: 500 });

    // Key extracted notes
    if (pulseData?.keyBreakdown && pulseData.keyBreakdown.length > 0) {
      doc.fontSize(12).fillColor("#2c3e50");
      doc.text("Key Extracted Notes:", 50, 250);
      let y = 270;
      for (const line of pulseData.keyBreakdown) {
        doc.fontSize(10).fillColor("#000");
        doc.text(`• ${line}`, 70, y, { width: 500 });
        y += 15;
      }
    } else if (pulseData?.extracted_summary && pulseData.extracted_summary.length > 0) {
      doc.fontSize(12).fillColor("#2c3e50");
      doc.text("Extracted Summary:", 50, 250);
      let y = 270;
      for (const line of pulseData.extracted_summary.slice(0, 10)) {
        doc.fontSize(10).fillColor("#000");
        doc.text(`• ${line}`, 70, y, { width: 500 });
        y += 15;
      }
    }
  }

  // Last page: Red wax seal (only when Full Integrated)
  if (isFullIntegrated) {
    doc.addPage();
    addHeader();

    // Red wax seal stamp - Classic embossed red wax (no glossy effect)
    const centerX = 300;
    const centerY = 300;
    const radius = 70;

    // Create embossed effect with multiple circles
    // Outer dark red ring
    doc.circle(centerX, centerY, radius)
      .fillColor("#8B0000")
      .fill();

    // Middle ring (slightly lighter)
    doc.circle(centerX, centerY, radius - 5)
      .fillColor("#A52A2A")
      .fill();

    // Inner circle (base red)
    doc.circle(centerX, centerY, radius - 10)
      .fillColor("#8B0000")
      .fill();

    // Center circle (darker for embossed effect)
    doc.circle(centerX, centerY, radius - 20)
      .fillColor("#5C0000")
      .fill();

    // Text ring: "SSA · FULL INTEGRATED REPORT"
    // Position text around the seal
    doc.fontSize(9).fillColor("#FFFFFF");
    const textY = centerY - radius - 5;
    doc.text("SSA · FULL INTEGRATED REPORT", centerX - 90, textY, {
      width: 180,
      align: "center",
    });

    // SSA logo/PFP in center (placeholder - would use actual logo image)
    doc.fontSize(20).fillColor("#FFFFFF");
    doc.text("SSA", centerX - 15, centerY - 8, { align: "center" });

    // Signature / Verification block
    const sigY = centerY + radius + 40;
    doc.fontSize(12).fillColor("#000");
    doc.text("Signature / Verification", 50, sigY);

    // Compute report hash
    const reportHash = createHash("sha256")
      .update(JSON.stringify(scanResult))
      .digest("hex");

    doc.fontSize(10).fillColor("#000");
    doc.text(`Report Hash: ${reportHash.substring(0, 32)}...`, 50, sigY + 25);

    // Badge signature
    if (signedBadge) {
      const badgeSig = signedBadge.fingerprint || signedBadge.signature.substring(0, 32);
      doc.text(`Badge Signature: ${badgeSig}...`, 50, sigY + 40);
    }

    // SSA public key fingerprint
    try {
      const publicKeyPath = join(process.cwd(), "docs", "keys", "ssa_public_key.json");
      if (existsSync(publicKeyPath)) {
        const publicKeyData = JSON.parse(readFileSync(publicKeyPath, "utf-8"));
        if (publicKeyData.public_key) {
          const keyFingerprint = createHash("sha256")
            .update(publicKeyData.public_key)
            .digest("hex")
            .substring(0, 16)
            .toUpperCase();
          doc.text(`SSA Public Key Fingerprint: ${keyFingerprint}`, 50, sigY + 55);
        }
      }
    } catch {
      // Public key not found, skip
    }

    // QR code to verification URL
    const verifyUrl = `${verificationUrl}/${scanResult.request_id}`;
    doc.text(`Verification URL: ${verifyUrl}`, 50, sigY + 70);

    // Generate QR code
    try {
      const qrCodeDataUrl = await QRCode.toDataURL(verifyUrl, {
        width: 150,
        margin: 1,
        color: {
          dark: "#000000",
          light: "#FFFFFF",
        },
      });

      // Convert data URL to buffer and embed in PDF
      const base64Data = qrCodeDataUrl.split(",")[1];
      const qrBuffer = Buffer.from(base64Data, "base64");
      
      doc.image(qrBuffer, 50, sigY + 90, {
        width: 150,
        height: 150,
      });
    } catch (error) {
      // QR code generation failed, show placeholder
      doc.fontSize(9).fillColor("#666");
      doc.text("[QR Code]", 50, sigY + 90);
    }
  }

  doc.end();

  return new Promise((resolve, reject) => {
    stream.on("finish", resolve);
    stream.on("error", reject);
  });
}

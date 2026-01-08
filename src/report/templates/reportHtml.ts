// src/report/templates/reportHtml.ts
// HTML template for SSA PDF reports

import type { ScanResult } from "../../core/types.js";
import type { BadgeResult } from "../../policy/badgePolicy.js";
import type { PulseMetadata } from "../../cli/pulse.js";

export interface ReportTemplateData {
  scanResult: ScanResult;
  badgeResult: BadgeResult | null;
  signedBadge?: any;
  pulseMetadata?: PulseMetadata | null;
  reportId: string;
  generatedAt: string;
}

/**
 * Generate HTML template for PDF report
 */
export function generateReportHtml(data: ReportTemplateData): string {
  const { scanResult, badgeResult, signedBadge, pulseMetadata, reportId, generatedAt } = data;
  const target = scanResult.target as any;
  const kind = target?.kind || "unknown";
  const scanLevel = (scanResult as any).scan_level_num || 
    (typeof scanResult.scan_level === "string" 
      ? parseInt(scanResult.scan_level.replace(/[^0-9]/g, "")) || 1
      : 1);

  // Determine if Fully Integrated badge should be shown
  const isFullyIntegrated = badgeResult?.tier === "FULLY_INTEGRATED";

  // Group findings by severity
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

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSA Security Scan Report - ${target.module_id || target.address || "Unknown"}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      background: white;
    }
    .page {
      page-break-after: always;
      padding: 60px 50px;
      min-height: 100vh;
    }
    .page:last-child {
      page-break-after: auto;
    }
    h1 {
      font-size: 32px;
      margin-bottom: 20px;
      color: #1a1a1a;
    }
    h2 {
      font-size: 24px;
      margin-top: 30px;
      margin-bottom: 15px;
      color: #2c3e50;
      border-bottom: 2px solid #3498db;
      padding-bottom: 5px;
    }
    h3 {
      font-size: 18px;
      margin-top: 20px;
      margin-bottom: 10px;
      color: #34495e;
    }
    .cover-page {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
    }
    .badge-block {
      margin: 40px 0;
      padding: 30px;
      border: 3px solid #3498db;
      border-radius: 10px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      min-width: 400px;
    }
    .badge-block h2 {
      color: white;
      border: none;
      font-size: 28px;
      margin: 0 0 10px 0;
    }
    .badge-block .badge-label {
      font-size: 20px;
      font-weight: 600;
      margin: 10px 0;
    }
    .badge-block .badge-expiry {
      font-size: 14px;
      opacity: 0.9;
      margin-top: 10px;
    }
    .no-badge {
      padding: 30px;
      border: 2px solid #e74c3c;
      border-radius: 10px;
      background: #fff5f5;
      color: #c0392b;
      margin: 40px 0;
    }
    .target-info {
      margin: 30px 0;
      padding: 20px;
      background: #f8f9fa;
      border-radius: 5px;
    }
    .target-info strong {
      color: #2c3e50;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
      margin: 20px 0;
    }
    .summary-card {
      padding: 20px;
      border: 1px solid #ddd;
      border-radius: 5px;
      background: #f8f9fa;
    }
    .summary-card h3 {
      margin-top: 0;
      color: #2c3e50;
    }
    .summary-card .value {
      font-size: 32px;
      font-weight: bold;
      color: #3498db;
      margin: 10px 0;
    }
    .verdict {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 4px;
      font-weight: bold;
      text-transform: uppercase;
    }
    .verdict.pass {
      background: #27ae60;
      color: white;
    }
    .verdict.warn {
      background: #f39c12;
      color: white;
    }
    .verdict.fail {
      background: #e74c3c;
      color: white;
    }
    .severity-table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    .severity-table th,
    .severity-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    .severity-table th {
      background: #34495e;
      color: white;
      font-weight: 600;
    }
    .severity-table tr:hover {
      background: #f8f9fa;
    }
    .finding {
      margin: 20px 0;
      padding: 15px;
      border-left: 4px solid #ddd;
      background: #f8f9fa;
    }
    .finding.critical {
      border-left-color: #e74c3c;
      background: #fff5f5;
    }
    .finding.high {
      border-left-color: #e67e22;
      background: #fff8f0;
    }
    .finding.medium {
      border-left-color: #f39c12;
      background: #fffbf0;
    }
    .finding.low {
      border-left-color: #3498db;
      background: #f0f8ff;
    }
    .finding.info {
      border-left-color: #95a5a6;
      background: #f8f9fa;
    }
    .finding-id {
      font-weight: bold;
      color: #2c3e50;
      font-size: 16px;
    }
    .finding-title {
      font-size: 18px;
      margin: 5px 0;
      color: #1a1a1a;
    }
    .finding-severity {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 12px;
      font-weight: bold;
      text-transform: uppercase;
      margin: 5px 0;
    }
    .finding-severity.critical {
      background: #e74c3c;
      color: white;
    }
    .finding-severity.high {
      background: #e67e22;
      color: white;
    }
    .finding-severity.medium {
      background: #f39c12;
      color: white;
    }
    .finding-severity.low {
      background: #3498db;
      color: white;
    }
    .finding-severity.info {
      background: #95a5a6;
      color: white;
    }
    .finding-description {
      margin: 10px 0;
      line-height: 1.6;
    }
    .finding-recommendation {
      margin: 10px 0;
      padding: 10px;
      background: white;
      border-radius: 3px;
      border-left: 3px solid #3498db;
    }
    .finding-recommendation strong {
      color: #2c3e50;
    }
    .metadata-table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    .metadata-table th,
    .metadata-table td {
      padding: 10px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    .metadata-table th {
      background: #ecf0f1;
      font-weight: 600;
      width: 200px;
    }
    .pulse-section {
      margin: 30px 0;
      padding: 20px;
      background: #f0f8ff;
      border: 2px solid #3498db;
      border-radius: 5px;
    }
    .pulse-section h3 {
      color: #2980b9;
      margin-top: 0;
    }
    .signature-section {
      margin: 30px 0;
      padding: 20px;
      background: #f8f9fa;
      border: 1px solid #ddd;
      border-radius: 5px;
    }
    .footer {
      position: fixed;
      bottom: 20px;
      left: 50px;
      right: 50px;
      text-align: center;
      font-size: 10px;
      color: #7f8c8d;
      border-top: 1px solid #ddd;
      padding-top: 10px;
    }
    @media print {
      .page {
        padding: 40px 30px;
      }
      .footer {
        position: fixed;
      }
    }
  </style>
</head>
<body>
  <!-- Cover Page -->
  <div class="page cover-page">
    <h1>SSA Security Scan Report</h1>
    <div class="target-info">
      <p><strong>Target:</strong> ${target.module_id || target.address || "Unknown"}</p>
      <p><strong>Type:</strong> ${kind.toUpperCase()}</p>
      <p><strong>Scan Level:</strong> ${scanLevel}${kind === "wallet" ? " (Wallets support levels 1–3 only)" : ""}</p>
      <p><strong>Report ID:</strong> ${reportId}</p>
      <p><strong>Generated:</strong> ${generatedAt}</p>
    </div>
    ${badgeResult && badgeResult.tier !== "NONE" ? `
    <div class="badge-block">
      <h2>${badgeResult.label}</h2>
      ${badgeResult.expires_at_iso ? `<div class="badge-expiry">Expires: ${badgeResult.expires_at_iso}</div>` : ""}
      ${badgeResult.continuously_monitored ? `<div class="badge-expiry">Status: Continuously Monitored (rolling)</div>` : ""}
      ${signedBadge ? `<div class="badge-expiry" style="margin-top: 10px; font-size: 12px;">Signature: ${signedBadge.fingerprint}</div>` : ""}
    </div>
    ` : `
    <div class="no-badge">
      <h2>⚠️ SSA Verification Failed</h2>
      <p>${badgeResult?.reason || "Verification requirements not met"}</p>
      <p style="margin-top: 10px;">Verification badges are withheld.</p>
    </div>
    `}
  </div>

  <!-- Executive Summary -->
  <div class="page">
    <h1>Executive Summary</h1>
    <div class="summary-grid">
      <div class="summary-card">
        <h3>Verdict</h3>
        <div class="value verdict ${scanResult.summary.verdict}">${scanResult.summary.verdict.toUpperCase()}</div>
      </div>
      <div class="summary-card">
        <h3>Risk Score</h3>
        <div class="value">${scanResult.summary.risk_score}/100</div>
      </div>
    </div>
    <h2>Severity Summary</h2>
    <table class="severity-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Count</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="finding-severity critical">Critical</span></td>
          <td>${scanResult.summary.severity_counts.critical}</td>
        </tr>
        <tr>
          <td><span class="finding-severity high">High</span></td>
          <td>${scanResult.summary.severity_counts.high}</td>
        </tr>
        <tr>
          <td><span class="finding-severity medium">Medium</span></td>
          <td>${scanResult.summary.severity_counts.medium}</td>
        </tr>
        <tr>
          <td><span class="finding-severity low">Low</span></td>
          <td>${scanResult.summary.severity_counts.low}</td>
        </tr>
        <tr>
          <td><span class="finding-severity info">Info</span></td>
          <td>${scanResult.summary.severity_counts.info}</td>
        </tr>
      </tbody>
    </table>
    <h2>Top Findings</h2>
    ${scanResult.findings.slice(0, 5).map(f => `
      <div class="finding ${f.severity}">
        <div class="finding-id">${f.id}</div>
        <div class="finding-title">${f.title}</div>
        <span class="finding-severity ${f.severity}">${f.severity}</span>
        <div class="finding-description">${f.description}</div>
      </div>
    `).join("")}
    ${scanResult.findings.length > 5 ? `<p style="margin-top: 20px;"><em>... and ${scanResult.findings.length - 5} more findings (see detailed findings section)</em></p>` : ""}
  </div>

  <!-- Findings Pages -->
  ${Object.entries(findingsBySeverity).filter(([_, findings]) => findings.length > 0).map(([severity, findings]) => `
  <div class="page">
    <h1>${severity.charAt(0).toUpperCase() + severity.slice(1)} Severity Findings</h1>
    ${findings.map(f => `
      <div class="finding ${f.severity}">
        <div class="finding-id">${f.id}</div>
        <div class="finding-title">${f.title}</div>
        <span class="finding-severity ${f.severity}">${f.severity}</span>
        <div class="finding-description">
          <strong>Description:</strong> ${f.description}
        </div>
        ${f.recommendation ? `
        <div class="finding-recommendation">
          <strong>Recommendation:</strong> ${f.recommendation}
        </div>
        ` : ""}
        ${(f as any).module_id ? `
        <div style="margin-top: 10px; font-size: 12px; color: #7f8c8d;">
          <strong>Module:</strong> ${(f as any).module_id}
        </div>
        ` : ""}
        <div style="margin-top: 10px; font-size: 12px; color: #7f8c8d;">
          <strong>Confidence:</strong> ${(f.confidence * 100).toFixed(0)}%
        </div>
      </div>
    `).join("")}
  </div>
  `).join("")}

  <!-- Appendices -->
  <div class="page">
    <h1>Appendices</h1>
    
    <h2>Scan Metadata</h2>
    <table class="metadata-table">
      <tr>
        <th>Scan ID</th>
        <td>${scanResult.request_id}</td>
      </tr>
      <tr>
        <th>Target</th>
        <td>${target.module_id || target.address}</td>
      </tr>
      <tr>
        <th>Type</th>
        <td>${kind}</td>
      </tr>
      <tr>
        <th>Scan Level</th>
        <td>${scanLevel}${kind === "wallet" ? " (Wallets support levels 1–3 only)" : ""}</td>
      </tr>
      <tr>
        <th>Timestamp</th>
        <td>${scanResult.timestamp_iso}</td>
      </tr>
      <tr>
        <th>Scanner Version</th>
        <td>${scanResult.engine.name} ${scanResult.engine.version}</td>
      </tr>
      <tr>
        <th>RPC URL</th>
        <td>${scanResult.meta.rpc_url}</td>
      </tr>
      <tr>
        <th>Duration</th>
        <td>${scanResult.meta.duration_ms}ms</td>
      </tr>
    </table>

    <h2>Badge Eligibility</h2>
    ${badgeResult ? `
      <table class="metadata-table">
        <tr>
          <th>Badge Tier</th>
          <td>${badgeResult.tier}</td>
        </tr>
        <tr>
          <th>Badge Label</th>
          <td>${badgeResult.label}</td>
        </tr>
        <tr>
          <th>Expires At</th>
          <td>${badgeResult.expires_at_iso || "N/A (rolling)"}</td>
        </tr>
        <tr>
          <th>Continuously Monitored</th>
          <td>${badgeResult.continuously_monitored ? "Yes" : "No"}</td>
        </tr>
        ${badgeResult.reason ? `
        <tr>
          <th>Reason</th>
          <td>${badgeResult.reason}</td>
        </tr>
        ` : ""}
      </table>
    ` : `
      <p>No badge issued. Verification requirements were not met.</p>
    `}

    ${signedBadge ? `
    <h2>Badge Signature</h2>
    <div class="signature-section">
      <table class="metadata-table">
        <tr>
          <th>Signature Fingerprint</th>
          <td>${signedBadge.fingerprint}</td>
        </tr>
        <tr>
          <th>Algorithm</th>
          <td>${signedBadge.algorithm}</td>
        </tr>
        <tr>
          <th>Public Key</th>
          <td style="font-family: monospace; font-size: 10px;">${signedBadge.public_key.substring(0, 50)}...</td>
        </tr>
        <tr>
          <th>Verification</th>
          <td>Use public key from docs/keys/ssa_public_key.json to verify signature</td>
        </tr>
      </table>
    </div>
    ` : ""}

    ${pulseMetadata ? `
    <h2>Supra Pulse Integration</h2>
    <div class="pulse-section">
      <h3>Supra Pulse Report Attached</h3>
      <table class="metadata-table">
        <tr>
          <th>Pulse File</th>
          <td>${pulseMetadata.filename}</td>
        </tr>
        <tr>
          <th>Kind</th>
          <td>${pulseMetadata.kind.toUpperCase()}</td>
        </tr>
        <tr>
          <th>SHA256 Hash</th>
          <td style="font-family: monospace; font-size: 10px;">${pulseMetadata.sha256}</td>
        </tr>
        ${pulseMetadata.extracted_summary && pulseMetadata.extracted_summary.length > 0 ? `
        <tr>
          <th>Key Points</th>
          <td>
            <ul style="margin-left: 20px;">
              ${pulseMetadata.extracted_summary.map(point => `<li>${point}</li>`).join("")}
            </ul>
          </td>
        </tr>
        ` : ""}
      </table>
      <p style="margin-top: 15px;">
        <strong>Note:</strong> The full Supra Pulse report has been integrated into this SSA scan report.
        ${isFullyIntegrated ? "This report qualifies for the SSA · Fully Integrated badge tier." : ""}
      </p>
    </div>
    ` : ""}
  </div>

  <div class="footer">
    <p>SSA Security Scan Report | Generated: ${generatedAt} | Report ID: ${reportId}</p>
    <p>This report is generated by SSA (Supra Security Agent) scanner. For verification, see docs/keys/ssa_public_key.json</p>
  </div>
</body>
</html>`;

  return html;
}

// src/report/templates/fullIntegratedReportHtml.ts
// HTML template for Full Integrated Report (and standard reports)

import type { FullIntegratedViewModel } from "../viewModel/fullIntegratedViewModel.js";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Load SVG file and return as data URI
 */
function loadSvgAsDataUri(svgPath: string): string {
  // Resolve from repo root (not from dist/)
  // __dirname in dist is dist/src/report/templates, so go up 4 levels to repo root
  const repoRoot = resolve(__dirname, "../../../../");
  const fullPath = resolve(repoRoot, svgPath);
  if (!existsSync(fullPath)) {
    console.warn(`Warning: SVG file not found: ${fullPath}`);
    return "";
  }
  const svgContent = readFileSync(fullPath, "utf-8");
  // Remove XML declaration if present
  const cleanSvg = svgContent.replace(/<\?xml[^>]*\?>/i, "").trim();
  // Encode as data URI
  const encoded = encodeURIComponent(cleanSvg);
  return `data:image/svg+xml;charset=utf-8,${encoded}`;
}

/**
 * Render Full Integrated Report HTML
 */
export function renderFullIntegratedHtml(
  data: FullIntegratedViewModel,
  isFullIntegrated: boolean
): string {
  const { projectName, reportId, timestampUtc, inputChecksum, scans, badges, overallVerdict, aggregateRiskScore, totalFindings, severityCounts, pulse, verdictWarnings } = data;

  const reportTitle = isFullIntegrated ? "SSA FULL INTEGRATED REPORT" : "SSA REPORT";

  // Load SVG icons
  const logoUri = loadSvgAsDataUri("tools/icons/logo_embedded.svg");
  const waxSealUri = loadSvgAsDataUri("tools/icons/wax_embedded.svg");

  // Badge SVG URIs
  const badgeSvgs: Record<string, string> = {
    SURFACE_VERIFIED: loadSvgAsDataUri("tools/icons/surface_verified_embedded.svg"),
    SECURITY_VERIFIED: loadSvgAsDataUri("tools/icons/security_verified_embedded.svg"),
    WALLET_VERIFIED: loadSvgAsDataUri("tools/icons/wallet_verified_embedded.svg"),
    CONTINUOUSLY_MONITORED: loadSvgAsDataUri("tools/icons/continuously_monitored_embedded.svg"),
  };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportTitle} - ${projectName}</title>
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
      font-size: 11pt;
    }
    .page {
      page-break-after: always;
      padding: 60px 50px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .page:last-child {
      page-break-after: auto;
    }
    .cover-page {
      justify-content: center;
      align-items: center;
      text-align: center;
    }
    .logo {
      width: 120px;
      height: 120px;
      margin-bottom: 30px;
    }
    h1 {
      font-size: 32px;
      margin-bottom: 20px;
      color: #1a1a1a;
      font-weight: 600;
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
    .project-name {
      font-size: 24px;
      color: #2c3e50;
      margin-bottom: 40px;
    }
    .assets-list {
      text-align: left;
      margin: 30px 0;
      max-width: 500px;
    }
    .asset-item {
      margin: 10px 0;
      font-family: 'Courier New', monospace;
      font-size: 12pt;
      word-break: break-all;
      line-height: 1.8;
    }
    .address-short {
      font-family: 'Courier New', monospace;
      font-size: 10pt;
    }
    .address-grouped {
      font-family: 'Courier New', monospace;
      font-size: 9pt;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-all;
      letter-spacing: 0.5px;
    }
    .meta-info {
      margin-top: 40px;
      font-size: 10pt;
      color: #666;
    }
    .verdict-box {
      background: ${overallVerdict === "High Risk" ? "#fee" : overallVerdict === "Conditional" ? "#fff3cd" : "#d4edda"};
      border: 2px solid ${overallVerdict === "High Risk" ? "#f5c6cb" : overallVerdict === "Conditional" ? "#ffc107" : "#c3e6cb"};
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
    }
    .verdict-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 10px;
    }
    .risk-score {
      font-size: 14px;
      color: #666;
    }
    .severity-counts {
      display: flex;
      gap: 15px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .severity-item {
      padding: 5px 10px;
      border-radius: 4px;
      font-size: 11pt;
    }
    .severity-critical { background: #fee; color: #721c24; }
    .severity-high { background: #fce4ec; color: #880e4f; }
    .severity-medium { background: #fff3cd; color: #856404; }
    .severity-low { background: #d1ecf1; color: #0c5460; }
    .severity-info { background: #e2e3e5; color: #383d41; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    th {
      background: #f8f9fa;
      font-weight: 600;
      color: #2c3e50;
    }
    .badge-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
      margin: 30px 0;
    }
    .badge-card {
      border: 2px solid #ddd;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      background: white;
    }
    .badge-card.not-earned {
      opacity: 0.25;
      filter: grayscale(1);
    }
    .badge-icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 15px;
    }
    .badge-title {
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 8px;
      color: #2c3e50;
    }
    .badge-meaning {
      font-size: 11px;
      color: #666;
      margin-bottom: 10px;
    }
    .badge-status {
      font-size: 12px;
      font-weight: 600;
      padding: 5px 10px;
      border-radius: 4px;
      display: inline-block;
    }
    .badge-status.earned {
      background: #d4edda;
      color: #155724;
    }
    .badge-status.not-earned {
      background: #f8d7da;
      color: #721c24;
    }
    .finding {
      margin: 20px 0;
      padding: 15px;
      border-left: 4px solid #ddd;
      background: #f8f9fa;
    }
    .finding-critical { border-left-color: #dc3545; }
    .finding-high { border-left-color: #fd7e14; }
    .finding-medium { border-left-color: #ffc107; }
    .finding-low { border-left-color: #17a2b8; }
    .finding-info { border-left-color: #6c757d; }
    .finding-title {
      font-weight: 600;
      margin-bottom: 8px;
      color: #2c3e50;
    }
    .finding-description {
      color: #666;
      font-size: 10pt;
      line-height: 1.6;
    }
    .pulse-section {
      background: #f0f8ff;
      border: 2px solid #3498db;
      border-radius: 8px;
      padding: 20px;
      margin: 30px 0;
    }
    .pulse-disclosure {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px solid #ddd;
      font-size: 10pt;
      font-style: italic;
      color: #666;
    }
    .wax-seal-container {
      text-align: center;
      margin: 40px 0;
    }
    .wax-seal {
      width: 200px;
      height: 200px;
      margin: 0 auto;
    }
    .warning-box {
      background: #fff3cd;
      border: 1px solid #ffc107;
      border-radius: 4px;
      padding: 10px;
      margin: 10px 0;
      font-size: 10pt;
      color: #856404;
    }
    .disclaimer {
      font-size: 9pt;
      color: #666;
      line-height: 1.8;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <!-- PAGE 1: Cover -->
  <div class="page cover-page">
    ${logoUri ? `<img src="${logoUri}" alt="SSA Logo" class="logo" />` : ''}
    <h1>${reportTitle}</h1>
    <div style="font-size: 14px; color: #666; margin-bottom: 10px;">SUPRA SECURITY AGENT</div>
    <div class="project-name">${projectName}</div>
    
    <div class="assets-list">
      <h3>Assets Covered</h3>
      ${scans.map(scan => `
        <div class="asset-item">
          <strong>${scan.kind.toUpperCase()}:</strong> <span class="address-short">${scan.shortId}</span>
        </div>
      `).join('')}
    </div>

    <div class="meta-info">
      <div>Scan Timestamp (UTC): ${timestampUtc}</div>
      <div>Report ID: ${reportId}</div>
      <div>Input Checksum: ${inputChecksum.substring(0, 32)}...</div>
    </div>
  </div>

  <!-- PAGE 2: Executive Summary -->
  <div class="page">
    <h2>Executive Summary</h2>
    
    ${verdictWarnings.length > 0 ? `
      <div class="warning-box">
        <strong>Note:</strong> ${verdictWarnings.join('; ')}
      </div>
    ` : ''}

    <div class="verdict-box">
      <div class="verdict-title">Overall Verdict: ${overallVerdict}</div>
      <div class="risk-score">Aggregate Risk Score: ${aggregateRiskScore}</div>
      <div class="severity-counts">
        <span class="severity-item severity-critical">Critical: ${severityCounts.critical}</span>
        <span class="severity-item severity-high">High: ${severityCounts.high}</span>
        <span class="severity-item severity-medium">Medium: ${severityCounts.medium}</span>
        <span class="severity-item severity-low">Low: ${severityCounts.low}</span>
        <span class="severity-item severity-info">Info: ${severityCounts.info}</span>
      </div>
    </div>

    <p style="margin-top: 20px; line-height: 1.8;">
      This report aggregates security findings from ${scans.length} scan(s) covering ${scans.map(s => s.kind).join(', ')} assets.
      ${totalFindings > 0 ? `A total of ${totalFindings} findings were identified across all scans.` : 'No findings were identified.'}
      ${overallVerdict === "High Risk" ? 'Critical or high severity findings require immediate attention.' : overallVerdict === "Conditional" ? 'Some findings require review before deployment.' : 'The assessed assets show no critical security issues.'}
    </p>
  </div>

  <!-- PAGE 3: Verification Matrix -->
  <div class="page">
    <h2>Verification Matrix</h2>
    <table>
      <thead>
        <tr>
          <th>Asset</th>
          <th>Levels Run</th>
          <th>Badges Earned</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>
        ${scans.map((scan, idx) => {
          const badge = badges.find(b => b.earned && (
            (scan.kind === "wallet" && b.tier === "WALLET_VERIFIED") ||
            (scan.kind !== "wallet" && (b.tier === "SURFACE_VERIFIED" || b.tier === "SECURITY_VERIFIED" || b.tier === "CONTINUOUSLY_MONITORED"))
          ));
          const badgeLabel = badge ? badge.label : "None";
          return `
            <tr>
              <td class="address-short">${scan.kind.toUpperCase()}: ${scan.shortId}</td>
              <td>L${scan.scanLevel}</td>
              <td>${badgeLabel}</td>
              <td>${scan.verdict.toUpperCase()}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  </div>

  <!-- PAGE 4: Badge Display Grid -->
  <div class="page">
    <h2>Badge Display</h2>
    <div class="badge-grid">
      ${badges.map(badge => {
        const svgUri = badgeSvgs[badge.tier] || '';
        return `
          <div class="badge-card ${badge.earned ? '' : 'not-earned'}">
            ${svgUri ? `<img src="${svgUri}" alt="${badge.label}" class="badge-icon" />` : ''}
            <div class="badge-title">${badge.label}</div>
            <div class="badge-meaning">${badge.meaning}</div>
            <div class="badge-status ${badge.earned ? 'earned' : 'not-earned'}">
              ${badge.earned ? '✓ Earned' : 'Not Earned'}
            </div>
          </div>
        `;
      }).join('')}
    </div>
  </div>

  <!-- PAGES 5..N: Detailed Findings per Asset -->
  ${scans.map(scan => `
    <div class="page">
      <h2>Detailed Findings: ${scan.kind.toUpperCase()}</h2>
      <div class="address-short" style="margin-bottom: 20px;">
        <strong>Identifier:</strong> ${scan.shortId}
      </div>
      ${scan.id.length > 42 && scan.id.startsWith("0x") ? `
        <div class="address-grouped" style="margin-bottom: 20px;">
          <strong>Full Address:</strong><br>${scan.groupedId}
        </div>
      ` : ''}
      
      <h3>Severity Summary</h3>
      <div class="severity-counts">
        <span class="severity-item severity-critical">Critical: ${scan.severityCounts.critical}</span>
        <span class="severity-item severity-high">High: ${scan.severityCounts.high}</span>
        <span class="severity-item severity-medium">Medium: ${scan.severityCounts.medium}</span>
        <span class="severity-item severity-low">Low: ${scan.severityCounts.low}</span>
        <span class="severity-item severity-info">Info: ${scan.severityCounts.info}</span>
      </div>

      <h3>Key Findings</h3>
      ${scan.findings.length > 0 ? scan.findings.map(finding => `
        <div class="finding finding-${finding.severity}">
          <div class="finding-title">[${finding.severity.toUpperCase()}] ${finding.title}</div>
          <div class="finding-description">${finding.description}</div>
        </div>
      `).join('') : '<p>No findings reported for this asset.</p>'}
    </div>
  `).join('')}

  ${pulse && (pulse.tier === "Premium" || pulse.tier === "Spotlight") ? `
    <!-- Supra Pulse Integration Section -->
    <div class="page">
      <h2>Supra Pulse Integration</h2>
      <div class="pulse-section">
        <h3>Pulse Tier: ${pulse.tier}</h3>
        ${pulse.score !== undefined ? `<p><strong>Pulse Score:</strong> ${pulse.score}</p>` : ''}
        ${pulse.timestamp ? `<p><strong>Pulse Timestamp:</strong> ${pulse.timestamp}</p>` : ''}
        ${pulse.summary ? `<p>${pulse.summary}</p>` : ''}
        ${pulse.verdictDerived ? `
          <div class="warning-box">
            Supra Pulse verdict derived from score (verdict not provided).
          </div>
        ` : ''}
        <div class="pulse-disclosure">
          ${pulse.disclosure || "Supra Pulse analysis is provided as a third-party supplemental signal and does not replace SSA findings."}
        </div>
      </div>
    </div>
  ` : ''}

  ${isFullIntegrated ? `
    <!-- Final Attestation Page (Full Integrated only) -->
    <div class="page">
      <h2>Final Attestation</h2>
      
      <!-- Combined SSA + Supra Pulse Summary Paragraph -->
      <div style="margin-bottom: 40px; line-height: 1.8; font-size: 11pt;">
        <p style="margin-bottom: 15px;">
          <strong>SSA (Supra Security Agent) Scan Summary:</strong> This report aggregates security findings from ${scans.length} scan(s) covering ${scans.map(s => s.kind).join(', ')} assets. 
          The overall verdict is <strong>${overallVerdict}</strong> with an aggregate risk score of <strong>${aggregateRiskScore}/100</strong>. 
          ${severityCounts.critical > 0 ? `Critical findings: ${severityCounts.critical}. ` : ''}
          ${severityCounts.high > 0 ? `High severity findings: ${severityCounts.high}. ` : ''}
          ${totalFindings > 0 ? `Total findings identified: ${totalFindings}.` : 'No security findings were identified.'}
        </p>
        ${pulse && (pulse.tier === "Premium" || pulse.tier === "Spotlight") ? `
          <p style="margin-bottom: 15px;">
            <strong>Supra Pulse ${pulse.tier} Summary:</strong> 
            ${pulse.score !== undefined ? `The Supra Pulse analysis assigned a score of <strong>${pulse.score}</strong> out of 100. ` : ''}
            ${pulse.summary ? pulse.summary + ' ' : ''}
            ${pulse.verdict ? `Verdict: <strong>${pulse.verdict}</strong>. ` : ''}
            This supplemental analysis provides additional context but does not replace the SSA security findings above.
          </p>
        ` : ''}
        <p style="margin-top: 20px; font-size: 10pt; color: #666;">
          This Full Integrated Report combines automated security scanning (SSA) with third-party market analysis (Supra Pulse ${pulse?.tier || 'Premium'}) to provide a comprehensive assessment of the project's security posture and market signals.
        </p>
      </div>
      
      <div class="wax-seal-container">
        ${waxSealUri ? `<img src="${waxSealUri}" alt="SSA Full Integrated Report Seal" class="wax-seal" />` : ''}
        <h3 style="margin-top: 20px;">SSA FULL INTEGRATED REPORT</h3>
        <div class="meta-info" style="margin-top: 30px;">
          <div>Report ID: ${reportId}</div>
          <div>Input Checksum: ${inputChecksum}</div>
          <div>Generated: ${timestampUtc}</div>
        </div>
      </div>
    </div>
  ` : ''}

  <!-- Disclaimer Page -->
  <div class="page">
    <h2>Disclaimer</h2>
    <div class="disclaimer">
      <p><strong>SSA (Supra Security Agent) Security Assessment Report</strong></p>
      <p>This report provides a risk assessment based on automated security scanning at the time of analysis. SSA (Supra Security Agent) does not provide guarantees, endorsements, or warranties regarding the security of the assessed assets.</p>
      <p><strong>Time-of-Scan Limitation:</strong> This report reflects the security state at the time of scanning. Security conditions may change over time, and this report does not guarantee future security.</p>
      <p><strong>Independent Due Diligence:</strong> Users must conduct their own independent security review and due diligence. This report is a tool to assist in security assessment but should not be the sole basis for security decisions.</p>
      <p><strong>No Formal Audit:</strong> This report is not a formal security audit. It is an automated analysis based on rule-based scanning and should be considered alongside other security measures.</p>
    </div>
  </div>
</body>
</html>`;

  return html;
}

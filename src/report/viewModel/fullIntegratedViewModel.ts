// src/report/viewModel/fullIntegratedViewModel.ts
// View model builder for Full Integrated Report HTML template

import type { FullIntegratedInputs } from "../fullIntegratedGenerator.js";
import { getScanVerdict } from "../fullIntegratedGenerator.js";
import { formatAddressShort, formatAddressGrouped } from "../utils.js";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

export interface ScanViewModel {
  kind: string;
  id: string;
  shortId: string;
  groupedId: string;
  verdict: string;
  riskScore: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  scanLevel: number;
  findings: Array<{
    id: string;
    title: string;
    description: string;
    severity: string;
  }>;
  notes?: string;
}

export interface BadgeViewModel {
  tier: string;
  label: string;
  earned: boolean;
  meaning: string;
  svgContent?: string; // Inline SVG content
}

export interface PulseViewModel {
  tier: string;
  score?: number;
  verdict?: string;
  verdictDerived: boolean;
  timestamp?: string;
  summary?: string;
  disclosure?: string;
}

export interface FullIntegratedViewModel {
  projectName: string;
  reportId: string;
  timestampUtc: string;
  inputChecksum: string;
  scans: ScanViewModel[];
  badges: BadgeViewModel[];
  overallVerdict: string;
  aggregateRiskScore: number;
  totalFindings: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  pulse?: PulseViewModel;
  verdictWarnings: string[];
}

/**
 * Load SVG file and return as inline content (data URI or inline SVG)
 */
function loadSvgInline(svgPath: string): string | undefined {
  try {
    const absolutePath = resolve(svgPath);
    if (!existsSync(absolutePath)) {
      return undefined;
    }
    const svgContent = readFileSync(absolutePath, "utf-8");
    // Return as inline SVG (strip XML declaration if present)
    return svgContent.replace(/<\?xml[^>]*\?>/i, "").trim();
  } catch (error) {
    console.warn(`Warning: Could not load SVG ${svgPath}: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

/**
 * Build view model from Full Integrated inputs
 */
export function buildFullIntegratedViewModel(
  inputs: FullIntegratedInputs,
  projectName: string,
  reportId: string,
  inputChecksum: string
): FullIntegratedViewModel {
  const { scans, badges, pulseSummary } = inputs;

  // Build scan view models
  const scanViewModels: ScanViewModel[] = scans.map((scan) => {
    const target = scan.target as any;
    const kind = target?.kind || "unknown";
    const identifier = target?.module_id || target?.address || target?.id || "Unknown";
    
    // Format addresses
    let shortId = identifier;
    let groupedId = identifier;
    if (identifier && identifier.length > 42 && identifier.startsWith("0x")) {
      shortId = formatAddressShort(identifier);
      groupedId = formatAddressGrouped(identifier);
    }

    const verdict = getScanVerdict(scan);
    const riskScore = scan?.summary?.risk_score ?? (scan as any)?.risk?.score ?? 0;
    const sevCounts = scan?.summary?.severity_counts ?? {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const scanLevel = (scan as any).scan_level_num ||
      (typeof scan.scan_level === "string"
        ? parseInt(scan.scan_level.replace(/[^0-9]/g, "")) || 1
        : 1);

    return {
      kind,
      id: identifier,
      shortId,
      groupedId,
      verdict,
      riskScore,
      severityCounts: sevCounts,
      scanLevel,
      findings: (scan?.findings ?? []).slice(0, 20).map((f) => ({
        id: f.id,
        title: f.title || "Untitled Finding",
        description: f.description || "",
        severity: f.severity || "info",
      })),
    };
  });

  // Build badge view models with SVG content
  const badgeTiers = [
    {
      tier: "SURFACE_VERIFIED",
      label: "SSA Surface Verified",
      meaning: "Passed Level 1 security verification",
      svg: "surface_verified_embedded.svg",
    },
    {
      tier: "SECURITY_VERIFIED",
      label: "SSA Security Verified",
      meaning: "Passed Levels 1-3 with low risk score",
      svg: "security_verified_embedded.svg",
    },
    {
      tier: "WALLET_VERIFIED",
      label: "SSA Wallet Verified",
      meaning: "Wallet address verified (Levels 1-3)",
      svg: "wallet_verified_embedded.svg",
    },
    {
      tier: "CONTINUOUSLY_MONITORED",
      label: "SSA Continuously Monitored",
      meaning: "Active monitoring (Levels 4-5)",
      svg: "continuously_monitored_embedded.svg",
    },
  ];

  const earnedTiers = new Set(
    badges.filter((b) => b && b.tier !== "NONE").map((b) => b!.tier as string)
  );

  const badgeViewModels: BadgeViewModel[] = badgeTiers.map((badgeDef) => {
    const earned = earnedTiers.has(badgeDef.tier);
    // SVG content will be loaded in the HTML template
    // We don't need to load it here since we'll use data URIs
    
    return {
      tier: badgeDef.tier,
      label: badgeDef.label,
      earned,
      meaning: badgeDef.meaning,
      svgContent: undefined, // Will be loaded in template
    };
  });

  // Aggregate statistics
  let totalRiskScore = 0;
  let totalFindings = 0;
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const verdictWarnings: string[] = [];

  for (const scan of scans) {
    const verdict = getScanVerdict(scan);
    if (verdict === "UNKNOWN") {
      const target = scan.target as any;
      const identifier = target?.module_id || target?.address || "Unknown";
      verdictWarnings.push(`${identifier}: verdict not found, using UNKNOWN`);
    }

    const riskScore = scan?.summary?.risk_score ?? (scan as any)?.risk?.score ?? 0;
    const sevCounts = scan?.summary?.severity_counts ?? {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    totalRiskScore += riskScore;
    totalFindings += scan?.findings?.length ?? 0;
    severityCounts.critical += sevCounts.critical ?? 0;
    severityCounts.high += sevCounts.high ?? 0;
    severityCounts.medium += sevCounts.medium ?? 0;
    severityCounts.low += sevCounts.low ?? 0;
    severityCounts.info += sevCounts.info ?? 0;
  }

  const avgRiskScore = scans.length > 0 ? Math.round(totalRiskScore / scans.length) : 0;
  let overallVerdict = "Pass";
  if (severityCounts.critical > 0) {
    overallVerdict = "High Risk";
  } else if (severityCounts.high > 0 || avgRiskScore >= 25) {
    overallVerdict = "Conditional";
  }

  // Add Pulse verdict derivation warning if applicable
  if (pulseSummary?.verdictDerived && pulseSummary.score !== undefined) {
    verdictWarnings.push(
      `Supra Pulse verdict derived from score ${pulseSummary.score} (verdict not provided).`
    );
  }

  // Build Pulse view model
  const pulseViewModel: PulseViewModel | undefined = pulseSummary
    ? {
        tier: pulseSummary.tier,
        score: pulseSummary.score,
        verdict: pulseSummary.verdict,
        verdictDerived: pulseSummary.verdictDerived ?? false,
        timestamp: pulseSummary.timestamp || pulseSummary.timestamp_utc,
        summary: pulseSummary.summary || pulseSummary.interpretation,
        disclosure:
          pulseSummary.disclosure ||
          "Supra Pulse analysis is provided as a third-party supplemental signal and does not replace SSA findings.",
      }
    : undefined;

  return {
    projectName,
    reportId,
    timestampUtc: inputs.timestampUtc,
    inputChecksum,
    scans: scanViewModels,
    badges: badgeViewModels,
    overallVerdict,
    aggregateRiskScore: avgRiskScore,
    totalFindings,
    severityCounts,
    pulse: pulseViewModel,
    verdictWarnings,
  };
}

// src/api/ssaRoutes.ts
// Unified SSA Scanning API for Base44

import express, { Request, Response } from "express";
import { randomUUID } from "crypto";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { scanFAToken } from "../core/faScanner.js";
import { scanCoinToken } from "../core/coinScanner.js";
import { verifySurface } from "../agent/verify.js";
import { calculateBadgeEligibility } from "../core/scoring.js";
import { getIsoTimestamp, addDays } from "../utils/time.js";
import type { ScanResult, BadgeEligibility } from "../core/types.js";
import { deriveBadge } from "../policy/badgePolicy.js";

const router = express.Router();

// Data directory for scan persistence
const DATA_DIR = process.env.SSA_DATA_DIR || "data";
const SCANS_DIR = join(DATA_DIR, "scans");

// Ensure directories exist
mkdirSync(SCANS_DIR, { recursive: true });

/**
 * Request body for POST /api/ssa/scan
 */
interface ScanRequest {
  targetType: "coin" | "fa" | "wallet";
  target: string;
  level: number;
  rpcUrl?: string;
  options?: Record<string, any>;
  supraPulseReportId?: string;
}

/**
 * Response for POST /api/ssa/scan
 */
interface ScanResponse {
  scanId: string;
  summary: {
    verdict: string;
    risk_score: number;
    severity_counts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    badge_eligibility: BadgeEligibility & { expiresAt?: string };
  };
  timestamp_iso: string;
}

/**
 * Validate scan request
 */
export function validateScanRequest(req: ScanRequest): { valid: boolean; error?: string } {
  // Validate targetType
  if (!["coin", "fa", "wallet"].includes(req.targetType)) {
    return { valid: false, error: "targetType must be 'coin', 'fa', or 'wallet'" };
  }

  // Validate target
  if (!req.target || typeof req.target !== "string" || req.target.trim().length === 0) {
    return { valid: false, error: "target is required and must be a non-empty string" };
  }

  // Validate level based on targetType
  if (req.targetType === "wallet") {
    if (!Number.isInteger(req.level) || req.level < 1 || req.level > 3) {
      return { valid: false, error: "Wallet scans support levels 1–3 only." };
    }
  } else {
    // coin or fa
    if (!Number.isInteger(req.level) || req.level < 1 || req.level > 5) {
      return { valid: false, error: "Coin/FA scans support levels 1–5 only." };
    }
  }

  return { valid: true };
}

/**
 * Derive badge eligibility from scan result
 */
export function deriveBadgeEligibility(
  scanResult: ScanResult,
  continuouslyMonitored: boolean = false
): BadgeEligibility & { expiresAt?: string } {
  const threshold = 30; // Risk score threshold for security_verified
  const verdict = scanResult.summary.verdict;
  const riskScore = scanResult.summary.risk_score;
  const badgeEligibility = scanResult.summary.badge_eligibility;

  // Override security_verified based on verdict and risk score
  const securityVerified = verdict === "pass" && riskScore <= threshold;

  // Calculate expiresAt (earliest expiry from badge eligibility)
  let expiresAt: string | undefined;
  if (badgeEligibility.expires_at_iso) {
    expiresAt = badgeEligibility.expires_at_iso;
  } else if (securityVerified) {
    // Default expiry: 14 days for security verified
    expiresAt = addDays(scanResult.timestamp_iso, 14);
  } else {
    // Default expiry: 30 days for scanned
    expiresAt = addDays(scanResult.timestamp_iso, 30);
  }

  return {
    ...badgeEligibility,
    security_verified: securityVerified,
    continuously_monitored: continuouslyMonitored,
    expiresAt,
  };
}

/**
 * Run scan based on targetType and level
 */
async function runScanByType(
  targetType: "coin" | "fa" | "wallet",
  target: string,
  level: number,
  rpcUrl: string,
  options: Record<string, any> = {}
): Promise<ScanResult> {
  if (targetType === "wallet") {
    // Wallet scans use agent pipeline (levels 1-3)
    // NEVER call runScan(module) for wallets - it requires module_name
    // For wallet scans, we need to determine if it's a coin or FA wallet
    // For now, we'll treat wallet as FA wallet (most common case)
    // TODO: Add logic to detect coin vs FA wallet based on resources
    const mode = level === 1 ? "fast" : level === 2 ? "strict" : "agent";
    const verifyResult = await verifySurface(
      { kind: "fa", id: target }, // Treat wallet as FA for now
      {
        rpcUrl: rpcUrl,
        rpc2Url: options.rpc2,
        mode: mode as "fast" | "strict" | "agent",
        withSupraScan: options.withSupraScan !== false,
        timeoutMs: options.timeoutMs || 8000,
        retries: options.retries || 1,
        txLimit: options.txLimit || 20,
        skipTx: options.skipTx || false,
        preferV2: options.preferV2 || false,
      }
    );

    // Convert VerificationReport to ScanResult-like structure
    // Note: verifySurface returns VerificationReport, not ScanResult
    // We need to adapt it
    const riskScore = (verifyResult as any).riskSynthesis?.overallRisk || (verifyResult as any).riskScore || 0;
    const verdict = riskScore >= 60 ? "fail" : riskScore >= 25 ? "warn" : "pass";
    
    const scanResult: ScanResult = {
      request_id: randomUUID(),
      target: {
        chain: "supra",
        module_address: target,
        module_name: "", // Wallets don't have module_name
        module_id: target,
        kind: "wallet",
      },
      scan_level: `level${level}` as any,
      timestamp_iso: verifyResult.timestamp_iso || getIsoTimestamp(),
      engine: {
        name: "ssa-scanner",
        version: "0.1.0",
        ruleset_version: "move-ruleset-0.1.0",
      },
      artifact: {
        fetch_method: "rpc",
        artifact_hash: `wallet_${target}`,
        binding_note: `Wallet scan for ${target}`,
        artifact_origin: {
          kind: "supra_rpc_v3",
          path: `${rpcUrl}/rpc/v3/accounts/${target}/resources`,
        },
      },
      summary: {
        risk_score: riskScore,
        verdict: verdict,
        severity_counts: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        },
        badge_eligibility: {
          scanned: true,
          no_critical: true,
          security_verified: false,
          continuously_monitored: false,
          reasons: [],
          expires_at_iso: undefined,
        },
        capabilities: {
          poolStats: false,
          totalStaked: false,
          queue: false,
          userViews: false,
        },
      },
      findings: [],
      meta: {
        scan_options: options,
        rpc_url: rpcUrl,
        duration_ms: 0,
        verification_report: verifyResult, // Store full verification report
      },
    };

    return scanResult;
  } else if (targetType === "fa") {
    // FA scans use scanFAToken
    const result = await scanFAToken(target, {
      rpc_url: rpcUrl,
      proxy_base: options.proxy_base,
      fa_owner: options.fa_owner,
    });

    // Map level to scan depth if needed
    // For now, scanFAToken handles all levels internally
    return result;
  } else {
    // Coin scans use scanCoinToken
    const result = await scanCoinToken(target, {
      rpc_url: rpcUrl,
      proxy_base: options.proxy_base,
    });

    return result;
  }
}

/**
 * Persist scan result to file
 */
function persistScanResult(scanId: string, scanResult: ScanResult): string {
  const filePath = join(SCANS_DIR, `${scanId}.json`);
  writeFileSync(filePath, JSON.stringify(scanResult, null, 2), "utf-8");
  return filePath;
}

/**
 * POST /api/ssa/scan
 * Unified scanning endpoint
 */
router.post("/scan", async (req: Request, res: Response) => {
  try {
    const body: ScanRequest = req.body;

    // Validate request
    const validation = validateScanRequest(body);
    if (!validation.valid) {
      return res.status(400).json({
        error: validation.error,
      });
    }

    // Get RPC URL
    const rpcUrl = body.rpcUrl || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";

    // Run scan
    const scanResult = await runScanByType(
      body.targetType,
      body.target.trim(),
      body.level,
      rpcUrl,
      body.options || {}
    );

    // Generate scan ID
    const scanId = randomUUID();

    // Derive badge eligibility
    const badgeEligibility = deriveBadgeEligibility(
      scanResult,
      body.options?.continuouslyMonitored || false
    );

    // Persist result
    persistScanResult(scanId, scanResult);

    // Build response
    const response: ScanResponse = {
      scanId,
      summary: {
        verdict: scanResult.summary.verdict,
        risk_score: scanResult.summary.risk_score,
        severity_counts: scanResult.summary.severity_counts,
        badge_eligibility: badgeEligibility,
      },
      timestamp_iso: scanResult.timestamp_iso,
    };

    res.json(response);
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({
      error: "Scan failed",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

/**
 * GET /api/ssa/scan/:scanId
 * Fetch stored scan result
 */
router.get("/scan/:scanId", (req: Request, res: Response) => {
  try {
    const { scanId } = req.params;

    if (!scanId || typeof scanId !== "string") {
      return res.status(400).json({ error: "Invalid scanId" });
    }

    const filePath = join(SCANS_DIR, `${scanId}.json`);

    if (!existsSync(filePath)) {
      return res.status(404).json({ error: "Scan result not found" });
    }

    const scanResult = JSON.parse(readFileSync(filePath, "utf-8"));
    res.json(scanResult);
  } catch (error) {
    console.error("Get scan error:", error);
    res.status(500).json({
      error: "Failed to retrieve scan result",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

export default router;

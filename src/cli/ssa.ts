#!/usr/bin/env node
// src/cli/ssa.ts
// Unified SSA CLI - One command flow for all scan types

import { Command } from "commander";
import dotenv from "dotenv";
import { mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import { randomUUID } from "crypto";

import { scanFAToken } from "../core/faScanner.js";
import { scanCoinToken } from "../core/coinScanner.js";
import { runScan } from "../core/scanner.js";
import { buildCoinSnapshot, buildFASnapshot } from "../agent/snapshot.js";
import { diffSnapshots } from "../agent/diff.js";

import { fetchAccountModulesV3 } from "../rpc/supraAccountsV3.js";
import { fetchAllModulesV1 } from "../rpc/supraAccountsV1.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";

import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import type { ScanResult, ModuleId } from "../core/types.js";
import { getIsoTimestamp } from "../utils/time.js";

import { generateSummaryJson } from "./summary.js";
import { generatePdfReport } from "./pdf.js";
import { attachSupraPulse, type PulseMetadata } from "./pulse.js";

import { deriveBadge } from "../policy/badgePolicy.js";
import { signBadge, type SignedBadge, type BadgePayload } from "../crypto/badgeSigner.js";

dotenv.config();

const program = new Command();

program.name("ssa").description("SSA Scanner - Unified security scanning for Supra Move").version("0.1.0");

/**
 * List all modules for an account address
 * Handles RPC v3/v2/v1 and SupraScan GraphQL fallback
 */
async function listAccountModules(
  rpcUrl: string,
  address: string
): Promise<Array<{ module_name: string; module_address: string; bytecode?: string; abi?: any }>> {
  const modules: Array<{ module_name: string; module_address: string; bytecode?: string; abi?: any }> = [];
  const seen = new Set<string>();

  // Try RPC v3/v2 first
  try {
    const rpcOptions: RpcClientOptions = {
      rpcUrl,
      timeout: 10000,
      retries: 2,
      retryDelay: 500,
    };

    const v3Result = await fetchAccountModulesV3(address, rpcOptions);
    if (v3Result.modules && Array.isArray(v3Result.modules)) {
      for (const module of v3Result.modules) {
        const moduleName = module.name || "";
        if (moduleName && !seen.has(moduleName)) {
          seen.add(moduleName);
          modules.push({
            module_name: moduleName,
            module_address: address,
            bytecode: module.bytecode,
            abi: module.abi,
          });
        }
      }
    }
  } catch (error) {
    console.warn(
      `RPC v3/v2 module enumeration failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Fallback to RPC v1 if v3 failed or returned empty
  if (modules.length === 0) {
    try {
      const v1Modules = await fetchAllModulesV1(rpcUrl, address);
      for (const module of v1Modules) {
        const moduleName = module.name || "";
        if (moduleName && !seen.has(moduleName)) {
          seen.add(moduleName);
          modules.push({
            module_name: moduleName,
            module_address: address,
            bytecode: module.bytecode || module.code,
            abi: module.abi || module.move_abi,
          });
        }
      }
    } catch (error) {
      console.warn(`RPC v1 module enumeration failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Fallback to SupraScan GraphQL if RPC failed
  if (modules.length === 0) {
    try {
      const query = `
        query AddressDetail($address: String, $blockchainEnvironment: BlockchainEnvironment) {
          addressDetail(address: $address, blockchainEnvironment: $blockchainEnvironment) {
            addressDetailSupra {
              resources
            }
          }
        }
      `;

      const data = await suprascanGraphql<{
        data?: {
          addressDetail?: {
            addressDetailSupra?: {
              resources?: string;
            };
          };
        };
      }>(
        query,
        { address, blockchainEnvironment: "mainnet" },
        { env: "mainnet", timeoutMs: 8000 }
      );

      // Parse resources to extract module names
      const resourcesStr = data.data?.addressDetail?.addressDetailSupra?.resources;
      if (resourcesStr && typeof resourcesStr === "string") {
        try {
          const resources = JSON.parse(resourcesStr);
          if (Array.isArray(resources)) {
            for (const resource of resources) {
              if (resource.type && resource.type.includes("PackageRegistry")) {
                const packages = resource.data?.packages || [];
                for (const pkg of packages) {
                  const account = pkg.account || address;
                  const pkgModules = pkg.modules || [];
                  for (const mod of pkgModules) {
                    const moduleName = mod.name || "";
                    if (moduleName && !seen.has(moduleName)) {
                      seen.add(moduleName);
                      modules.push({
                        module_name: moduleName,
                        module_address: account,
                      });
                    }
                  }
                }
              }
            }
          }
        } catch {
          // Resources parsing failed, continue
        }
      }
    } catch (error) {
      console.warn(
        `SupraScan GraphQL module enumeration failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  return modules;
}

/**
 * Map scan level to scan level string
 */
function mapLevelToScanLevel(level: number): "quick" | "standard" | "full" | "monitor" {
  if (level === 1) return "quick";
  if (level === 2) return "standard";
  if (level === 3) return "full";
  if (level >= 4) return "monitor";
  return "quick";
}

/**
 * Scan a wallet/creator address
 * Enumerates all modules and scans each, then aggregates results
 */
async function scanWallet(
  address: string,
  level: number,
  rpcUrl: string,
  options: Record<string, any> = {}
): Promise<ScanResult> {
  console.log(`Enumerating modules for wallet ${address}...`);
  const modules = await listAccountModules(rpcUrl, address);

  if (modules.length === 0) {
    return {
      request_id: randomUUID(),
      target: {
        chain: "supra",
        module_address: address,
        module_name: "",
        module_id: address,
        address,
      } as any,
      scan_level: mapLevelToScanLevel(level),
      timestamp_iso: getIsoTimestamp(),
      engine: {
        name: "ssa-scanner",
        version: "0.1.0",
        ruleset_version: "move-ruleset-0.1.0",
      },
      artifact: {
        fetch_method: "rpc",
        artifact_hash: `wallet_${address}`,
        binding_note: `Wallet scan for ${address}`,
        artifact_origin: {
          kind: "supra_rpc_v3",
          path: `${rpcUrl}/rpc/v3/accounts/${address}/modules`,
        },
      } as any,
      summary: {
        risk_score: 0,
        verdict: "pass",
        severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        badge_eligibility: {
          scanned: true,
          no_critical: true,
          security_verified: false,
          continuously_monitored: false,
          reasons: ["No modules found at wallet address"],
          expires_at_iso: undefined,
        },
        capabilities: { poolStats: false, totalStaked: false, queue: false, userViews: false },
      } as any,
      findings: [],
      meta: {
        scan_options: options,
        rpc_url: rpcUrl,
        duration_ms: 0,
        wallet_modules: [],
      } as any,
    };
  }

  console.log(`Found ${modules.length} module(s). Scanning each...`);

  const moduleScans: Array<{
    module_id: string;

    // ✅ Added: module profile + quick per-module summary fields
    module_profile?: string;
    module_profile_reason?: string;
    verdict?: "pass" | "warn" | "fail" | "inconclusive" | string;
    risk_score?: number;

    summary: any;
    findings: any[];
    meta: any;
  }> = [];

  const allFindings: any[] = [];
  let maxRiskScore = 0;
  const aggregatedSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let verdict: "pass" | "warn" | "fail" | "inconclusive" = "pass";

  for (const module of modules) {
    const moduleId: ModuleId = { address: module.module_address, module_name: module.module_name };

    try {
      console.log(`  Scanning ${moduleId.address}::${moduleId.module_name}...`);
      const scanResult = await runScan(moduleId, {
        scan_level: mapLevelToScanLevel(level),
        rpc_url: rpcUrl,
        proxy_base: options.proxy_base,
      });

      const annotatedFindings = (scanResult.findings || []).map((f: any) => ({
        ...f,
        module_id: `${moduleId.address}::${moduleId.module_name}`,
      }));
      allFindings.push(...annotatedFindings);

      for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
        aggregatedSeverityCounts[severity] += scanResult.summary.severity_counts?.[severity] ?? 0;
      }

      maxRiskScore = Math.max(maxRiskScore, scanResult.summary.risk_score ?? 0);

      if (scanResult.summary.verdict === "fail") verdict = "fail";
      else if (scanResult.summary.verdict === "warn" && verdict !== "fail") verdict = "warn";

      moduleScans.push({
        module_id: `${moduleId.address}::${moduleId.module_name}`,

        // ✅ NEW: keep per-module classification + reason (if your rules set it)
        module_profile: scanResult.meta?.module_profile,
        module_profile_reason: scanResult.meta?.module_profile_reason,
        verdict: scanResult.summary?.verdict,
        risk_score: scanResult.summary?.risk_score,

        summary: scanResult.summary,
        findings: annotatedFindings,
        meta: scanResult.meta,
      });
    } catch (error) {
      console.warn(
        `  Failed to scan ${moduleId.address}::${moduleId.module_name}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );

      // Still record a stub entry so report.meta.wallet_modules stays complete
      moduleScans.push({
        module_id: `${moduleId.address}::${moduleId.module_name}`,
        module_profile: "unknown",
        module_profile_reason: "Scan threw error before module_profile could be computed",
        verdict: "inconclusive",
        risk_score: 0,
        summary: null,
        findings: [],
        meta: { error: error instanceof Error ? error.message : String(error) },
      });
      if (verdict === "pass") verdict = "inconclusive";
    }
  }

  return {
    request_id: randomUUID(),
    target: {
      address,
      module_name: "",
      module_id: address,
      kind: "wallet",
      chain: "supra",
    } as any,
    scan_level: mapLevelToScanLevel(level),
    timestamp_iso: getIsoTimestamp(),
    engine: {
      name: "ssa-scanner",
      version: "0.1.0",
      ruleset_version: "move-ruleset-0.1.0",
    },
    artifact: {
      fetch_method: "rpc",
      artifact_hash: `wallet_${address}`,
      binding_note: `Wallet scan for ${address}`,
      artifact_origin: {
        kind: "supra_rpc_v3",
        path: `${rpcUrl}/rpc/v3/accounts/${address}/modules`,
      },
    } as any,
    summary: {
      risk_score: maxRiskScore,
      verdict,
      severity_counts: aggregatedSeverityCounts,
      badge_eligibility: {
        scanned: true,
        no_critical: aggregatedSeverityCounts.critical === 0,
        security_verified: false,
        continuously_monitored: false,
        reasons: [],
        expires_at_iso: undefined,
      },
      capabilities: { poolStats: false, totalStaked: false, queue: false, userViews: false },
    } as any,
    findings: allFindings,
    meta: {
      scan_options: options,
      rpc_url: rpcUrl,
      duration_ms: 0,
      wallet_modules: moduleScans,
    } as any,
  };
}

/**
 * Main scan command
 */
program
  .command("scan")
  .description("Run a security scan")
  .requiredOption("--kind <kind>", "Scan kind: coin, fa, wallet, or creator")
  .requiredOption("--level <level>", "Scan level (1-5 for coin/fa, 1-3 for wallet/creator)", (v) => parseInt(v, 10))
  .option("--coinType <coinType>", "Coin type (for --kind coin): 0xADDR::MODULE::COIN")
  .option("--fa <faAddress>", "FA address (for --kind fa): 0x...")
  .option("--address <address>", "Wallet/creator address (for --kind wallet/creator): 0x...")
  .requiredOption("--rpc <url>", "Supra RPC URL")
  .option("--out <dir>", "Output directory (default: ./out)", "./out")
  .option("--pdf", "Generate PDF report")
  .option("--pulse <pathOrUrl>", "Attach Supra Pulse report (PDF or JSON path/URL)")
  .option("--prev <path>", "Previous snapshot path (for level 5 diff)")
  .option("--curr <path>", "Current snapshot path (for level 5 diff)")
  .option("--delay <ms>", "Delay between snapshots for level 5 (default: 1000)", (v) => parseInt(v, 10), 1000)
  .option("--proxy_base <url>", "Optional HTTP proxy base for RPC/adapters")
  .option("--fa_owner <addr>", "Optional FA owner override (when needed)")
  .action(async (options) => {
    try {
      const { kind, level, rpc, out, pdf, pulse, prev, curr, delay, proxy_base, fa_owner } = options;

      const normalizedKind = kind === "creator" ? "wallet" : kind;

      // Validate level based on kind
      if (normalizedKind === "wallet") {
        if (level < 1 || level > 3) {
          const errorSummary = {
            error: {
              code: "INVALID_LEVEL",
              message: "Wallet scans support levels 1–3 only.",
              allowed_levels: [1, 2, 3],
            },
          };
          mkdirSync(out, { recursive: true });
          writeFileSync(join(out, "summary.json"), JSON.stringify(errorSummary, null, 2));
          console.error("Error: Wallet scans support levels 1–3 only.");
          process.exit(1);
        }
      } else {
        if (level < 1 || level > 5) {
          const errorSummary = {
            error: {
              code: "INVALID_LEVEL",
              message: "Coin/FA scans support levels 1–5 only.",
              allowed_levels: [1, 2, 3, 4, 5],
            },
          };
          mkdirSync(out, { recursive: true });
          writeFileSync(join(out, "summary.json"), JSON.stringify(errorSummary, null, 2));
          console.error("Error: Coin/FA scans support levels 1–5 only.");
          process.exit(1);
        }
      }

      // Validate target based on kind
      let target: string | null = null;
      if (normalizedKind === "coin") {
        if (!options.coinType) {
          console.error("Error: --coinType is required for --kind coin");
          process.exit(1);
        }
        target = options.coinType;
      } else if (normalizedKind === "fa") {
        if (!options.fa) {
          console.error("Error: --fa is required for --kind fa");
          process.exit(1);
        }
        target = options.fa;
      } else if (normalizedKind === "wallet") {
        if (!options.address) {
          console.error("Error: --address is required for --kind wallet/creator");
          process.exit(1);
        }
        target = options.address;
      }

      if (!target) {
        console.error("Error: Invalid target for scan kind");
        process.exit(1);
      }

      // Create output directory structure
      mkdirSync(out, { recursive: true });
      const artifactsDir = join(out, "artifacts");
      mkdirSync(artifactsDir, { recursive: true });

      console.log(`Scanning ${normalizedKind} ${target} at level ${level}...`);

      // Run scan
      let scanResult: ScanResult;
      if (normalizedKind === "wallet") {
        scanResult = await scanWallet(target, level, rpc, { ...options, proxy_base });
      } else if (normalizedKind === "fa") {
        scanResult = await scanFAToken(target, {
          rpc_url: rpc,
          proxy_base,
          fa_owner,
        } as any);
      } else {
        scanResult = await scanCoinToken(target, {
          rpc_url: rpc,
          proxy_base,
        } as any);
      }

      // Add scan level number and target kind to result
      (scanResult as any).scan_level_num = level;
      (scanResult as any).scan_level_str = `L${level}`;
      (scanResult as any).target = {
        ...(scanResult as any).target,
        kind: normalizedKind,
        chain: "supra",
      };

      // Handle level 4/5 snapshot/diff logic for coin/fa
      if ((normalizedKind === "coin" || normalizedKind === "fa") && level >= 4) {
        if (level === 4) {
          console.log("Creating snapshot baseline...");
          const snapshot =
            normalizedKind === "coin"
              ? await buildCoinSnapshot({ scanResult, rpcUrl: rpc })
              : await buildFASnapshot({ scanResult, rpcUrl: rpc });

          writeFileSync(join(artifactsDir, "snapshot.json"), JSON.stringify(snapshot, null, 2));
        }

        if (level === 5) {
          if (prev && curr) {
            console.log("Creating diff from provided snapshots...");
            const prevSnapshot = JSON.parse(readFileSync(prev, "utf-8"));
            const currSnapshot = JSON.parse(readFileSync(curr, "utf-8"));
            const diff = diffSnapshots(prevSnapshot, currSnapshot);
            writeFileSync(join(artifactsDir, "diff.json"), JSON.stringify(diff, null, 2));
          } else {
            console.log("Creating snapshot v1...");
            const snapshot1 =
              normalizedKind === "coin"
                ? await buildCoinSnapshot({ scanResult, rpcUrl: rpc })
                : await buildFASnapshot({ scanResult, rpcUrl: rpc });

            writeFileSync(join(artifactsDir, "snapshot_v1.json"), JSON.stringify(snapshot1, null, 2));

            console.log(`Waiting ${delay}ms before creating snapshot v2...`);
            await new Promise((resolve) => setTimeout(resolve, delay));

            const scanResult2 =
              normalizedKind === "fa"
                ? await scanFAToken(target, { rpc_url: rpc, proxy_base } as any)
                : await scanCoinToken(target, { rpc_url: rpc, proxy_base } as any);

            console.log("Creating snapshot v2...");
            const snapshot2 =
              normalizedKind === "coin"
                ? await buildCoinSnapshot({ scanResult: scanResult2, rpcUrl: rpc })
                : await buildFASnapshot({ scanResult: scanResult2, rpcUrl: rpc });

            writeFileSync(join(artifactsDir, "snapshot_v2.json"), JSON.stringify(snapshot2, null, 2));

            const diff = diffSnapshots(snapshot1, snapshot2);
            writeFileSync(join(artifactsDir, "diff.json"), JSON.stringify(diff, null, 2));
          }
        }
      }

      // Derive badge using authoritative policy
      const badgeResult = deriveBadge(scanResult);

      (scanResult as any).badge = badgeResult;
      if ((scanResult as any).summary?.badge_eligibility) {
        (scanResult as any).summary.badge_eligibility.security_verified =
          badgeResult.tier === "SECURITY_VERIFIED" || badgeResult.tier === "CONTINUOUSLY_MONITORED";
        (scanResult as any).summary.badge_eligibility.continuously_monitored = badgeResult.continuously_monitored;
        (scanResult as any).summary.badge_eligibility.expires_at_iso = badgeResult.expires_at_iso || undefined;
      }

      // Attach Supra Pulse if provided
      let pulseMetadata: PulseMetadata | null = null;
      if (pulse) {
        console.log(`Attaching Supra Pulse report: ${pulse}...`);
        pulseMetadata = await attachSupraPulse(pulse, artifactsDir);
        if (pulseMetadata) {
          (scanResult as any).external_intel = { supra_pulse: pulseMetadata };
        }
      }

      // Write report.json
      writeFileSync(join(out, "report.json"), JSON.stringify(scanResult, null, 2));

      // Sign badge if private key is available
      let signedBadge: SignedBadge | null = null;
      const privateKey = process.env.SSA_BADGE_SIGNING_PRIVATE_KEY || process.env.SSA_BADGE_SIGNING_KEY;
      if (privateKey && badgeResult.tier !== "NONE") {
        try {
          const badgePayload: BadgePayload = {
            tier: badgeResult.tier,
            label: badgeResult.label,
            timestamp_iso: scanResult.timestamp_iso,
            expires_at_iso: badgeResult.expires_at_iso,
            continuously_monitored: badgeResult.continuously_monitored,
            scan_id: scanResult.request_id,
            target: {
              kind: normalizedKind,
              value: target,
            },
          };
          signedBadge = await signBadge(badgePayload, privateKey);
        } catch (error) {
          console.warn(`Failed to sign badge: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      // Generate summary.json (includes badge)
      const summary = generateSummaryJson(
        scanResult,
        normalizedKind,
        target,
        level,
        out,
        !!pdf,
        pulseMetadata,
        badgeResult,
        signedBadge
      );
      writeFileSync(join(out, "summary.json"), JSON.stringify(summary, null, 2));

      // Write badge file if signed
      if (signedBadge) {
        const scanId = scanResult.request_id;
        writeFileSync(join(out, `badge_${scanId}.json`), JSON.stringify(signedBadge, null, 2));
      }

      // Generate PDF if requested
      if (pdf) {
        console.log("Generating PDF report...");
        await generatePdfReport(scanResult, pulseMetadata, join(out, "report.pdf"));
      }

      console.log(`\nScan complete!`);
      console.log(`  Report: ${join(out, "report.json")}`);
      console.log(`  Summary: ${join(out, "summary.json")}`);
      if (pdf) console.log(`  PDF: ${join(out, "report.pdf")}`);
    } catch (error) {
      console.error("Scan failed:", error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program.parse(process.argv);





#!/usr/bin/env node

import { Command } from "commander";
import dotenv from "dotenv";
import { writeFileSync, existsSync, readFileSync } from "fs";
import { runScan } from "./core/scanner.js";
import { scanFAToken } from "./core/faScanner.js";
import { scanCoinToken } from "./core/coinScanner.js";
import { validateModuleId } from "./utils/validate.js";
import type { ModuleId, ScanLevel } from "./core/types.js";
import { buildCoinSnapshot, buildFASnapshot } from "./agent/snapshot.js";
import { diffSnapshots } from "./agent/diff.js";
import { applySeverityRules } from "./agent/rules.js";
import { formatHuman } from "./agent/format.js";
import {
  readJsonFile,
  writeJsonAtomic,
  snapshotPathForCoin,
  snapshotPathForFA,
  ensureDir,
} from "./agent/storage.js";
import type { CoinSnapshot, FASnapshot, CoinIdentity, FAIdentity } from "./agent/types.js";
import { runMonitor, type MonitorTarget } from "./agent/monitor.js";

dotenv.config();

const program = new Command();

program
  .name("ssa-scan")
  .description("SSA Scanner - Security scanner for Supra Move modules")
  .version("0.1.0");

// Module scan command (refactored from root)
program
  .command("module")
  .description("Scan a Supra Move module")
  .requiredOption("--address <address>", "Module address (0x...)")
  .requiredOption("--module <name>", "Module name")
  .option("--level <level>", "Scan level (quick|standard|full|monitor)", "quick")
  .option("--out <file>", "Output file path (JSON)")
  .option("--rpc <url>", "Supra RPC URL (overrides SUPRA_RPC_URL env)")
  .option("--artifact <path>", "Path to local artifact file (.move, .json, .mv, .blob, .bin)")
  .option("--artifact-dir <dir>", "Directory containing artifacts (auto-detects module)")
  .action(async (options) => {
    try {
      const moduleId: ModuleId = {
        address: options.address.trim(),
        module_name: options.module.trim(),
      };

      // Validate module ID
      const validation = validateModuleId(moduleId);
      if (!validation.valid) {
        console.error(`Error: ${validation.error}`);
        process.exitCode = 1;
        return;
      }

      const rpcUrl = options.rpc || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
      const scanLevel = (options.level as ScanLevel) || "quick";

      console.log(`Scanning ${moduleId.address}::${moduleId.module_name}...`);
      console.log(`Scan level: ${scanLevel}`);
      console.log(`RPC URL: ${rpcUrl}`);
      console.log("");

      const result = await runScan(moduleId, {
        scan_level: scanLevel,
        rpc_url: rpcUrl,
        artifact_path: options.artifact,
        artifact_dir: options.artifactDir,
      });

      // Print summary
      console.log("=== Scan Summary ===");
      console.log(`Request ID: ${result.request_id}`);
      console.log(`Verdict: ${result.summary.verdict.toUpperCase()}`);
      console.log(`Risk Score: ${result.summary.risk_score}/100`);
      
      // Print artifact mode and capabilities
      if (result.meta.artifact_mode) {
        console.log(`Artifact Mode: ${result.meta.artifact_mode.toUpperCase()}`);
      }
      if (result.meta.rule_capabilities) {
        const caps = result.meta.rule_capabilities;
        console.log(`Rule Capabilities:`);
        console.log(`  viewOnly: ${caps.viewOnly ? "✅" : "❌"}`);
        console.log(`  hasAbi: ${caps.hasAbi ? "✅" : "❌"}`);
        console.log(`  hasBytecodeOrSource: ${caps.hasBytecodeOrSource ? "✅" : "❌"}`);
      }
      if (result.meta.artifact_loaded) {
        const components = result.meta.artifact_components;
        if (components) {
          console.log(`Artifact Loaded: ✅`);
          const componentList = [];
          if (components.hasSource) componentList.push("source");
          if (components.hasAbi) componentList.push("ABI");
          if (components.hasBytecode) componentList.push("bytecode");
          console.log(`  Components: ${componentList.join(", ") || "none"}`);
          console.log(`  Origin: ${components.origin.kind} (${components.origin.path})`);
          if (components.onChainBytecodeFetched) {
            console.log(`  On-chain bytecode fetched: ✅`);
          }
          if (components.moduleIdMatch !== undefined) {
            console.log(`  Module ID match: ${components.moduleIdMatch ? "✅" : "❌"}`);
            if (!components.moduleIdMatch) {
              console.log(`    ⚠️  Warning: Local artifact module ID does not match scan target`);
            }
          }
        }
      } else {
        console.log(`Artifact Loaded: ❌`);
        console.log(`  Hint: To enable evidence-based scanning:`);
        console.log(`    - Export Move source/ABI from Supra IDE`);
        console.log(`    - Set SSA_LOCAL_SOURCE, SSA_LOCAL_BYTECODE, or SSA_LOCAL_ABI env vars`);
        console.log(`    - Or set SSA_LOCAL_ARTIFACT_DIR to a directory containing artifacts`);
      }
      
      console.log(`Severity Counts:`);
      console.log(`  Critical: ${result.summary.severity_counts.critical}`);
      console.log(`  High: ${result.summary.severity_counts.high}`);
      console.log(`  Medium: ${result.summary.severity_counts.medium}`);
      console.log(`  Low: ${result.summary.severity_counts.low}`);
      console.log(`  Info: ${result.summary.severity_counts.info}`);
      console.log(`Total Findings: ${result.findings.length}`);
      console.log("");

      // Print top 3 findings
      if (result.findings.length > 0) {
        console.log("=== Top Findings ===");
        const topFindings = result.findings
          .sort((a, b) => {
            const severityOrder: Record<string, number> = {
              critical: 5,
              high: 4,
              medium: 3,
              low: 2,
              info: 1,
            };
            return severityOrder[b.severity] - severityOrder[a.severity];
          })
          .slice(0, 3);

        topFindings.forEach((finding, idx) => {
          console.log(`${idx + 1}. [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.title}`);
          console.log(`   ${finding.description}`);
          console.log("");
        });
      }

      // Write to file if specified
      if (options.out) {
        writeFileSync(options.out, JSON.stringify(result, null, 2), "utf-8");
        console.log(`Full results written to: ${options.out}`);
      } else {
        console.log("Tip: Use --out <file> to save full results to a JSON file");
      }
    } catch (error) {
      console.error("Scan failed:", error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

// FA token scan command
program
  .command("fa")
  .description("Scan an FA token")
  .requiredOption("--fa <address>", "FA token address (0x...)")
  .option("--owner <address>", "FA owner address (optional, for owner-specific checks)")
  .option("--out <file>", "Output file path (JSON)")
  .option("--rpc <url>", "Supra RPC URL (overrides SUPRA_RPC_URL env)")
  .action(async (options) => {
    try {
      const faAddress = options.fa.trim().toLowerCase();
      const rpcUrl = options.rpc || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";

      console.log(`Scanning FA Token: ${faAddress}...`);
      console.log(`RPC URL: ${rpcUrl}`);
      if (options.owner) {
        console.log(`Owner: ${options.owner}`);
      }
      console.log("");

      const result = await scanFAToken(faAddress, {
        rpc_url: rpcUrl,
        fa_owner: options.owner,
      });

      // Print FA scan summary
      console.log("=== FA Scan Summary ===");
      console.log(`Request ID: ${result.request_id}`);
      console.log(`Verdict: ${result.summary.verdict.toUpperCase()}`);
      if (result.meta.verdict_reason) {
        console.log(`Reason: ${result.meta.verdict_reason}`);
      }
      console.log(`Risk Score: ${result.summary.risk_score}/100`);
      
      const evidenceTier = result.meta.rule_capabilities?.viewOnly ? "Heuristic (view-only)" : "Authoritative (bytecode)";
      console.log(`Evidence Tier: ${evidenceTier}`);
      console.log("");

      // Print FA metadata
      if (result.meta.fa_metadata) {
        const meta = result.meta.fa_metadata;
        console.log("=== FA Token Metadata ===");
        console.log(`Address: ${meta.address}`);
        if (meta.symbol) console.log(`Symbol: ${meta.symbol}`);
        if (meta.name) console.log(`Name: ${meta.name}`);
        if (meta.decimals !== undefined) console.log(`Decimals: ${meta.decimals}`);
        if (meta.totalSupply !== undefined) console.log(`Total Supply: ${meta.totalSupply}`);
        if (meta.creator) console.log(`Creator: ${meta.creator}`);
        console.log("");
      }

      // Print data sources
      console.log("=== Data Sources ===");
      console.log(`RPC View: ✅`);
      console.log(`RPC v3 Bytecode: ${result.meta.artifact_components?.onChainBytecodeFetched ? "✅" : "❌"}`);
      if (result.meta.fa_modules && result.meta.fa_modules.length > 0) {
        console.log(`Modules Discovered: ${result.meta.fa_modules.join(", ")}`);
      }
      console.log("");

      console.log(`Severity Counts:`);
      console.log(`  Critical: ${result.summary.severity_counts.critical}`);
      console.log(`  High: ${result.summary.severity_counts.high}`);
      console.log(`  Medium: ${result.summary.severity_counts.medium}`);
      console.log(`  Low: ${result.summary.severity_counts.low}`);
      console.log(`  Info: ${result.summary.severity_counts.info}`);
      console.log(`Total Findings: ${result.findings.length}`);
      console.log("");

      // Print top findings
      if (result.findings.length > 0) {
        console.log("=== Top Findings ===");
        const topFindings = result.findings
          .sort((a, b) => {
            const severityOrder: Record<string, number> = {
              critical: 5,
              high: 4,
              medium: 3,
              low: 2,
              info: 1,
            };
            return severityOrder[b.severity] - severityOrder[a.severity];
          })
          .slice(0, 5);

        topFindings.forEach((finding, idx) => {
          const evidenceLabel = finding.evidence.kind === "heuristic" ? " (heuristic)" : " (authoritative)";
          console.log(`${idx + 1}. [${finding.severity.toUpperCase()}] ${finding.id}: ${finding.title}${evidenceLabel}`);
          console.log(`   ${finding.description}`);
          console.log("");
        });
      }

      // Write to file if specified
      if (options.out) {
        writeFileSync(options.out, JSON.stringify(result, null, 2), "utf-8");
        console.log(`Full results written to: ${options.out}`);
      } else {
        console.log("Tip: Use --out <file> to save full results to a JSON file");
      }
    } catch (error) {
      console.error("FA scan failed:", error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

// Watch command (Level 3)
program
  .command("watch")
  .description("Watch a token for changes (Level 3 Agent/Watcher Mode)")
  .requiredOption("--type <type>", "Token type (coin|fa)")
  .requiredOption("--target <target>", "Target: coin type (for coin) or FA address (for fa)")
  .option("--once", "Run once and exit (don't loop)")
  .option("--loop-ms <ms>", "Loop interval in milliseconds", "60000")
  .option("--state-dir <dir>", "State directory for snapshots", "state")
  .option("--json", "Output JSON format")
  .option("--rpc <url>", "Supra RPC URL (overrides SUPRA_RPC_URL env)")
  .option("--ignore-supply", "Ignore supply changes in diffs (for deterministic testing)")
  .option("--prev-snapshot <path>", "Load previous snapshot from file (test harness mode)")
  .option("--curr-snapshot <path>", "Load current snapshot from file (test harness mode)")
  .action(async (options) => {
    try {
      const tokenType = options.type.toLowerCase();
      const target = options.target.trim();
      const rpcUrl = options.rpc || process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
      const stateDir = options.stateDir || "state";
      const loopMs = parseInt(options.loopMs || "60000", 10);
      const once = options.once || false;
      const jsonOutput = options.json || false;
      const prevSnapshotPath = options.prevSnapshot;
      const currSnapshotPath = options.currSnapshot;
      const testHarnessMode = !!(prevSnapshotPath && currSnapshotPath);
      
      // In test harness mode, skip state directory setup
      if (!testHarnessMode) {
        // Ensure state directory exists
        ensureDir(stateDir);
      }
      
      const runWatch = async (): Promise<void> => {
        // Suppress console.log during scan/snapshot/diff phase if JSON output is requested
        const origLog = console.log;
        const origWarn = console.warn;
        if (jsonOutput) {
          console.log = () => {}; // Suppress stdout logs
          console.warn = () => {}; // Suppress warnings to stdout (errors still go to stderr)
        }
        
        let snapshotPath: string;
        let prevSnapshot: CoinSnapshot | FASnapshot | null = null;
        let prevReadError: string | null = null;
        let prevSnapshotPresent = false;
        let currentSnapshot: CoinSnapshot | FASnapshot;
        
        try {
          if (testHarnessMode) {
            // TEST HARNESS MODE: Load snapshots from provided paths
            // Do NOT call RPC, do NOT build snapshots, do NOT write state files
            
            if (!existsSync(prevSnapshotPath!)) {
              throw new Error(`Previous snapshot file not found: ${prevSnapshotPath}`);
            }
            if (!existsSync(currSnapshotPath!)) {
              throw new Error(`Current snapshot file not found: ${currSnapshotPath}`);
            }
            
            // Load previous snapshot
            const prev = tokenType === "coin"
              ? readJsonFile<CoinSnapshot>(prevSnapshotPath!)
              : readJsonFile<FASnapshot>(prevSnapshotPath!);
            
            if (prev === null) {
              throw new Error(`Failed to parse previous snapshot from ${prevSnapshotPath}`);
            }
            prevSnapshot = prev;
            prevSnapshotPresent = true;
            
            // Load current snapshot
            const curr = tokenType === "coin"
              ? readJsonFile<CoinSnapshot>(currSnapshotPath!)
              : readJsonFile<FASnapshot>(currSnapshotPath!);
            
            if (curr === null) {
              throw new Error(`Failed to parse current snapshot from ${currSnapshotPath}`);
            }
            currentSnapshot = curr;
            
            // Use current snapshot path as snapshotPath for output
            snapshotPath = currSnapshotPath!;
            
            if (process.env.SSA_DEBUG_DIFF === "1") {
              console.error(`[WATCH DEBUG] Test harness mode: loaded prev from ${prevSnapshotPath}, curr from ${currSnapshotPath}`);
            }
          } else {
            // NORMAL MODE: Compute snapshotPath, read from state, scan, build
            
            // STEP 1: Compute snapshotPath FIRST (before scanning)
            if (tokenType === "coin") {
              // Parse coin type to extract components for path
              const parts = target.split("::");
              const publisherAddress = parts[0] || "unknown";
              const moduleName = parts[1] || "unknown";
              const symbol = parts[2] || "UNKNOWN";
              
              snapshotPath = snapshotPathForCoin(
                stateDir,
                target, // coinType
                moduleName,
                symbol
              );
            } else if (tokenType === "fa") {
              snapshotPath = snapshotPathForFA(stateDir, target);
            } else {
              throw new Error(`Invalid token type: ${tokenType}. Must be 'coin' or 'fa'`);
            }
            
            // STEP 2: READ previous snapshot FIRST (before scanning)
            if (existsSync(snapshotPath)) {
              prevSnapshotPresent = true;
              try {
                const prev = tokenType === "coin"
                  ? readJsonFile<CoinSnapshot>(snapshotPath)
                  : readJsonFile<FASnapshot>(snapshotPath);
                
                if (prev !== null) {
                  prevSnapshot = prev;
                  // Debug: Log that we successfully read prev snapshot
                  if (process.env.SSA_DEBUG_DIFF === "1") {
                    console.error(`[WATCH DEBUG] Successfully read prev snapshot from ${snapshotPath}`);
                    if ("objectOwner" in prev.identity) {
                      console.error(`[WATCH DEBUG] Prev snapshot objectOwner: ${prev.identity.objectOwner}`);
                    }
                  }
                } else {
                  // File exists but readJsonFile returned null - parse error
                  // Try to read raw content to get better error message (also strip BOM)
                  try {
                    const raw = readFileSync(snapshotPath, "utf-8");
                    const text = raw.replace(/^\uFEFF/, ""); // Strip UTF-8 BOM if present
                    JSON.parse(text); // This will throw if invalid JSON
                    // If we get here, JSON is valid but readJsonFile returned null (shouldn't happen)
                    prevReadError = "Snapshot file exists but could not be parsed (unknown error)";
                  } catch (parseError) {
                    prevReadError = parseError instanceof Error ? parseError.message : String(parseError);
                  }
                }
              } catch (error) {
                // Unexpected error during read
                prevReadError = error instanceof Error ? error.message : String(error);
              }
            } else {
              // File doesn't exist - this is normal for first run
              prevSnapshotPresent = false;
              if (process.env.SSA_DEBUG_DIFF === "1") {
                console.error(`[WATCH DEBUG] No prev snapshot found at ${snapshotPath}`);
              }
            }
            
            // STEP 3: Run scan and build CURRENT snapshot
            let scanResult;
            
            if (tokenType === "coin") {
              // Scan coin token
              scanResult = await scanCoinToken(target, { rpc_url: rpcUrl });
              
              // Build snapshot
              const coinMeta = scanResult.meta.coin_metadata;
              if (!coinMeta) {
                throw new Error("Coin metadata missing from scan result");
              }
              
              currentSnapshot = await buildCoinSnapshot({
                scanResult,
                rpcUrl,
              });
            } else {
              // Scan FA token
              scanResult = await scanFAToken(target, { rpc_url: rpcUrl });
              
              // Build snapshot
              currentSnapshot = await buildFASnapshot({
                scanResult,
                rpcUrl,
              });
            }
          }
          
          // STEP 4: Compute diff
          const ignoreSupply = options.ignoreSupply || false;
          const diff = diffSnapshots(prevSnapshot, currentSnapshot, { ignoreSupply });
          
          // STEP 5: Apply severity rules
          const ruledDiff = applySeverityRules(diff, prevSnapshot, currentSnapshot);
          
          // STEP 6: Output (restore console functions before output)
          console.log = origLog;
          console.warn = origWarn;
          
          const baselineCreated = !prevSnapshotPresent && !prevReadError;
          
          // Debug fields for SSA_DEBUG_DIFF=1
          const debugDiff = process.env.SSA_DEBUG_DIFF === "1";
          const debugFields: Record<string, unknown> = {};
          if (debugDiff) {
            if (prevSnapshot && "objectOwner" in prevSnapshot.identity) {
              debugFields.debugPrevOwner = prevSnapshot.identity.objectOwner;
            }
            if ("objectOwner" in currentSnapshot.identity) {
              debugFields.debugCurrOwner = currentSnapshot.identity.objectOwner;
            }
            if (prevSnapshot && "objectOwner" in prevSnapshot.identity && "objectOwner" in currentSnapshot.identity) {
              debugFields.debugOwnerChanged = prevSnapshot.identity.objectOwner !== currentSnapshot.identity.objectOwner;
            }
          }
          
          if (jsonOutput) {
            const output: Record<string, unknown> = {
              snapshotPath,
              changed: ruledDiff.changed,
              changes: ruledDiff.changes,
              currentSnapshotIdentity: currentSnapshot.identity,
              prevSnapshotPresent,
              prevReadError,
              baselineCreated,
            };
            
            // Add test harness mode fields if applicable
            if (testHarnessMode) {
              output.currSnapshotPath = currSnapshotPath;
              output.prevSnapshotPath = prevSnapshotPath;
            }
            
            // Add debug fields if enabled
            if (debugDiff) {
              Object.assign(output, debugFields);
            }
            
            // Output single-line JSON (no pretty printing) - PowerShell-friendly
            console.log(JSON.stringify(output));
          } else {
            if (baselineCreated) {
              console.log("=== Baseline Created ===");
              console.log(`Snapshot saved to: ${snapshotPath}`);
              if (tokenType === "coin") {
                const coinId = currentSnapshot.identity as CoinIdentity;
                console.log(`Coin: ${coinId.coinType}`);
              } else {
                const faId = currentSnapshot.identity as FAIdentity;
                console.log(`FA: ${faId.faAddress}`);
              }
              console.log("No previous snapshot found. This is the baseline.");
            } else {
              console.log(formatHuman(ruledDiff, currentSnapshot));
            }
          }
          
          // STEP 7: Persist snapshot LAST (after diff and output)
          // CRITICAL: This must happen AFTER diff to ensure we're diffing against
          // the on-disk version, not a version we just wrote.
          // SKIP in test harness mode (don't overwrite state files)
          if (!testHarnessMode) {
            if (process.env.SSA_DEBUG_DIFF === "1") {
              console.error(`[WATCH DEBUG] Writing current snapshot to ${snapshotPath} (AFTER diff)`);
              if ("objectOwner" in currentSnapshot.identity) {
                console.error(`[WATCH DEBUG] Current snapshot objectOwner: ${currentSnapshot.identity.objectOwner}`);
              }
            }
            writeJsonAtomic(snapshotPath, currentSnapshot);
          } else {
            if (process.env.SSA_DEBUG_DIFF === "1") {
              console.error(`[WATCH DEBUG] Test harness mode: skipping snapshot write`);
            }
          }
        } catch (error) {
          // Restore console functions on error
          console.log = origLog;
          console.warn = origWarn;
          throw error;
        }
      };
      
      // Run once or loop
      if (once) {
        await runWatch();
      } else {
        // Loop with interval
        while (true) {
          await runWatch();
          await new Promise((resolve) => setTimeout(resolve, loopMs));
        }
      }
    } catch (error) {
      console.error("Watch failed:", error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

// Monitor command (Level 4: Ping-based drift monitoring)
program
  .command("monitor")
  .description("Level 4: Ping-based drift monitoring with deep scan escalation")
  .option("--targets <file>", "Path to targets JSON file")
  .option("--rpc <url>", "RPC URL (overrides config file)")
  .option("--rpc2 <url>", "Secondary RPC URL (overrides config file)")
  .option("--max-targets-per-run <number>", "Maximum targets per run (default: 50)", "50")
  .option("--max-deep-scans-per-run <number>", "Maximum deep scans per run (default: 3)", "3")
  .option("--timeout-ms <number>", "Timeout per ping (default: 20000)", "20000")
  .option("--deep-timeout-ms <number>", "Timeout per deep scan (default: 60000)", "60000")
  .option("--state-dir <dir>", "State directory (default: state)", "state")
  .option("--tmp-dir <dir>", "Temporary directory for deep scan outputs (default: tmp)", "tmp")
  .option("--with-suprascan", "Enable SupraScan in deep scans (default: false)", false)
  .option("--prefer-v2", "Prefer v2 endpoint for deep scans (default: false)", false)
  .option("--tx-sample <number>", "Number of transactions to sample in deep scans (default: 0 = disabled)", "0")
  .option("--concurrency <number>", "Targets processed concurrently (default: 1)", "1")
  .option("--loop", "Run in loop mode (default: false)", false)
  .option("--interval-ms <number>", "Loop interval in milliseconds (default: 300000)", "300000")
  .action(async (options) => {
    try {
      const targets: MonitorTarget[] = [];
      
      // Load targets from file if provided
      if (options.targets) {
        const config = readJsonFile<{ targets: MonitorTarget[]; rpc?: string; rpc2?: string }>(options.targets);
        if (!config || !config.targets || !Array.isArray(config.targets)) {
          console.error(`Error: Invalid targets file: ${options.targets}`);
          process.exitCode = 1;
          return;
        }
        targets.push(...config.targets);
      }

      await runMonitor({
        configPath: options.targets,
        rpc: options.rpc,
        rpc2: options.rpc2,
        targets: targets.length > 0 ? targets : undefined,
        maxTargetsPerRun: parseInt(options.maxTargetsPerRun, 10),
        maxDeepScansPerRun: parseInt(options.maxDeepScansPerRun, 10),
        timeoutMs: parseInt(options.timeoutMs, 10),
        deepTimeoutMs: parseInt(options.deepTimeoutMs, 10),
        stateDir: options.stateDir,
        tmpDir: options.tmpDir,
        withSupraScan: options.withSupraScan === true,
        preferV2: options.preferV2 === true,
        txSample: parseInt(options.txSample, 10) || undefined,
        concurrency: parseInt(options.concurrency, 10),
        loop: options.loop === true,
        intervalMs: parseInt(options.intervalMs, 10),
      });

      // Handle loop mode
      if (options.loop) {
        const intervalMs = parseInt(options.intervalMs, 10) || 300000;
        while (true) {
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
          await runMonitor({
            configPath: options.targets,
            rpc: options.rpc,
            rpc2: options.rpc2,
            targets: targets.length > 0 ? targets : undefined,
            maxTargetsPerRun: parseInt(options.maxTargetsPerRun, 10),
            maxDeepScansPerRun: parseInt(options.maxDeepScansPerRun, 10),
            timeoutMs: parseInt(options.timeoutMs, 10),
            deepTimeoutMs: parseInt(options.deepTimeoutMs, 10),
            stateDir: options.stateDir,
            tmpDir: options.tmpDir,
            withSupraScan: options.withSupraScan === true,
            preferV2: options.preferV2 === true,
            txSample: parseInt(options.txSample, 10) || undefined,
            concurrency: parseInt(options.concurrency, 10),
            loop: false, // Don't nest loops
            intervalMs,
          });
        }
      }
    } catch (error) {
      console.error("Monitor failed:", error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    }
  });

// Backward compatibility: if no subcommand, treat as module scan
program.action(async (options) => {
  // Check if required options are present
  if (options.address && options.module) {
    // Old-style invocation - run module scan
    const moduleId: ModuleId = {
      address: options.address.trim(),
      module_name: options.module.trim(),
    };

    const validation = validateModuleId(moduleId);
    if (!validation.valid) {
      console.error(`Error: ${validation.error}`);
      process.exitCode = 1;
      return;
    }

    const rpcUrl = options.rpc || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
    const scanLevel = (options.level as ScanLevel) || "quick";

    console.log(`Scanning ${moduleId.address}::${moduleId.module_name}...`);
    console.log(`Scan level: ${scanLevel}`);
    console.log(`RPC URL: ${rpcUrl}`);
    console.log("");

    const result = await runScan(moduleId, {
      scan_level: scanLevel,
      rpc_url: rpcUrl,
      artifact_path: options.artifact,
      artifact_dir: options.artifactDir,
    });

    // Print summary (same as module command)
    console.log("=== Scan Summary ===");
    console.log(`Request ID: ${result.request_id}`);
    console.log(`Verdict: ${result.summary.verdict.toUpperCase()}`);
    console.log(`Risk Score: ${result.summary.risk_score}/100`);
    console.log(`Severity Counts:`);
    console.log(`  Critical: ${result.summary.severity_counts.critical}`);
    console.log(`  High: ${result.summary.severity_counts.high}`);
    console.log(`  Medium: ${result.summary.severity_counts.medium}`);
    console.log(`  Low: ${result.summary.severity_counts.low}`);
    console.log(`  Info: ${result.summary.severity_counts.info}`);
    console.log(`Total Findings: ${result.findings.length}`);
    console.log("");

    if (options.out) {
      writeFileSync(options.out, JSON.stringify(result, null, 2), "utf-8");
      console.log(`Full results written to: ${options.out}`);
    }
  } else {
    // No subcommand and no required options - show help
    program.help();
  }
});

program.parse();

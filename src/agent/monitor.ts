/**
 * Level 4 Monitor: Ping-based drift detection with deep scan escalation
 */

import { buildFAPingSnapshot, buildCoinPingSnapshot, diffPingSnapshots, type PingSnapshot } from "./ping.js";
import { readJsonFile, writeJsonAtomic, pingSnapshotPathForFA, pingSnapshotPathForCoin } from "./storage.js";
import { verifySurface } from "./verify.js";
import { join } from "path";
import { ensureDir } from "./storage.js";
import { getIsoTimestamp } from "../utils/time.js";

export interface MonitorTarget {
  kind: "fa" | "coin";
  id: string;
}

export interface MonitorConfig {
  rpc: string;
  rpc2?: string;
  targets: MonitorTarget[];
}

export interface MonitorOptions {
  configPath?: string;
  rpc?: string;
  rpc2?: string;
  targets?: MonitorTarget[];
  maxTargetsPerRun?: number;
  maxDeepScansPerRun?: number;
  timeoutMs?: number;
  deepTimeoutMs?: number;
  stateDir?: string;
  tmpDir?: string;
  withSupraScan?: boolean;
  preferV2?: boolean;
  txSample?: number;
  concurrency?: number;
  loop?: boolean;
  intervalMs?: number;
}

export interface MonitorResult {
  target: MonitorTarget;
  pingSuccess: boolean;
  pingSnapshot: PingSnapshot | null;
  diff: {
    changed: boolean;
    changes: Array<{
      field: string;
      type: string;
      before?: any;
      after?: any;
      delta?: string;
    }>;
  };
  deepScanTriggered: boolean;
  deepScanResult?: {
    success: boolean;
    outputPath?: string;
    error?: string;
  };
  queued: boolean;
  error?: string;
}

/**
 * Shorten ID for display (first 8 chars for FA, first 20 for coin)
 */
function shortenId(kind: "fa" | "coin", id: string): string {
  if (kind === "fa") {
    return id.substring(0, 10); // 0x + 8 chars
  }
  // Coin: show first 20 chars
  if (id.length <= 20) return id;
  return id.substring(0, 20) + "...";
}

/**
 * Format fingerprint for display (first 8 chars)
 */
function shortenFingerprint(fp: string): string {
  return fp.substring(0, 8);
}

/**
 * Run monitor for a single target
 */
async function monitorTarget(
  target: MonitorTarget,
  prevSnapshot: PingSnapshot | null,
  options: Required<Pick<MonitorOptions, "rpc" | "timeoutMs" | "stateDir">> &
    Pick<MonitorOptions, "rpc2" | "withSupraScan" | "preferV2" | "txSample">
): Promise<{
  result: MonitorResult;
  snapshot: PingSnapshot | null;
}> {
  const result: MonitorResult = {
    target,
    pingSuccess: false,
    pingSnapshot: null,
    diff: { changed: false, changes: [] },
    deepScanTriggered: false,
    queued: false,
  };

  try {
    // Build ping snapshot
    const snapshot =
      target.kind === "fa"
        ? await buildFAPingSnapshot(target.id, options.rpc, options.rpc2, options.timeoutMs)
        : await buildCoinPingSnapshot(target.id, options.rpc, options.rpc2, options.timeoutMs);

    if (!snapshot) {
      result.error = "Ping failed: could not build snapshot";
      return { result, snapshot: null };
    }

    result.pingSuccess = true;
    result.pingSnapshot = snapshot;

    // Save ping snapshot
    const snapshotPath =
      target.kind === "fa"
        ? pingSnapshotPathForFA(options.stateDir, target.id)
        : pingSnapshotPathForCoin(options.stateDir, target.id);
    writeJsonAtomic(snapshotPath, snapshot);

    // Diff with previous
    const diff = diffPingSnapshots(prevSnapshot, snapshot);
    result.diff = diff;

    return { result, snapshot };
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
    return { result, snapshot: null };
  }
}

/**
 * Run deep scan for a target (escalation)
 */
async function runDeepScan(
  target: MonitorTarget,
  options: Required<Pick<MonitorOptions, "rpc" | "deepTimeoutMs" | "tmpDir">> &
    Pick<MonitorOptions, "rpc2" | "withSupraScan" | "preferV2" | "txSample">
): Promise<{ success: boolean; outputPath?: string; error?: string }> {
  try {
    const timestamp = getIsoTimestamp().replace(/[:.]/g, "_").substring(0, 19); // YYYY-MM-DDTHHMMSS
    const shortId = target.kind === "fa" ? target.id.substring(0, 16) : target.id.replace(/[^a-zA-Z0-9]/g, "_").substring(0, 30);
    const outputPath = join(options.tmpDir, `deep_${target.kind}_${shortId}_${timestamp}.json`);

    ensureDir(options.tmpDir);

    const report = await verifySurface(
      target,
      {
        rpcUrl: options.rpc,
        rpc2Url: options.rpc2,
        mode: "fast", // Use fast mode for deep scans from ping
        withSupraScan: options.withSupraScan || false,
        timeoutMs: options.deepTimeoutMs,
        retries: 2,
        skipTx: options.txSample === undefined || options.txSample === 0,
        txLimit: options.txSample,
        preferV2: options.preferV2,
        suprascanDump: false,
      }
    );

    writeJsonAtomic(outputPath, report);

    return {
      success: report.status === "OK",
      outputPath,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Main monitor runner
 */
export async function runMonitor(options: MonitorOptions): Promise<MonitorResult[]> {
  // Load config
  let config: MonitorConfig;
  if (options.configPath) {
    const loaded = readJsonFile<MonitorConfig>(options.configPath);
    if (!loaded) {
      throw new Error(`Failed to load config from ${options.configPath}`);
    }
    config = loaded;
  } else if (options.targets && options.targets.length > 0) {
    config = {
      rpc: options.rpc || process.env.SUPRA_RPC_URL || "https://rpc.supra.com",
      rpc2: options.rpc2,
      targets: options.targets,
    };
  } else {
    throw new Error("Either --targets <file> or --targets <array> must be provided");
  }

  // Override with CLI flags
  const rpc = options.rpc || config.rpc || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
  const rpc2 = options.rpc2 || config.rpc2;
  const stateDir = options.stateDir || "state";
  const tmpDir = options.tmpDir || "tmp";
  const maxTargets = options.maxTargetsPerRun || 50;
  const maxDeepScans = options.maxDeepScansPerRun || 3;
  const timeoutMs = options.timeoutMs || 20000;
  const deepTimeoutMs = options.deepTimeoutMs || 60000;
  const concurrency = options.concurrency || 1;

  // Ensure directories exist
  ensureDir(stateDir);
  ensureDir(tmpDir);

  // Apply max targets limit
  const targets = config.targets.slice(0, maxTargets);
  if (config.targets.length > maxTargets) {
    console.log(`[MONITOR] Limited targets to ${maxTargets} (${config.targets.length} requested)`);
  }

  const results: MonitorResult[] = [];
  let deepScanCount = 0;

  // Process targets sequentially (safer for resource limits)
  for (const target of targets) {
    // Load previous snapshot
    const prevSnapshotPath =
      target.kind === "fa"
        ? pingSnapshotPathForFA(stateDir, target.id)
        : pingSnapshotPathForCoin(stateDir, target.id);
    const prevSnapshot = readJsonFile<PingSnapshot>(prevSnapshotPath);

    // Monitor target - this builds snapshot, saves it, and diffs with previous
    const { result, snapshot } = await monitorTarget(
      target,
      prevSnapshot,
      {
        rpc,
        rpc2,
        timeoutMs,
        stateDir,
        withSupraScan: options.withSupraScan,
        preferV2: options.preferV2,
        txSample: options.txSample,
      }
    );

    results.push(result);

    // Print ping result
    if (!result.pingSuccess) {
      const short = shortenId(target.kind, target.id);
      console.log(`${target.kind.toUpperCase()} ${short} | PING FAILED | ${result.error || "unknown error"}`);
      continue;
    }

    // Check if this is a baseline (no previous snapshot)
    const isBaseline = !prevSnapshot;

    if (!result.diff.changed) {
      // Stable or baseline - print compact line
      const short = shortenId(target.kind, target.id);
      const fp = result.pingSnapshot ? shortenFingerprint(result.pingSnapshot.fingerprint) : "unknown";
      if (isBaseline) {
        console.log(`${target.kind.toUpperCase()} ${short} | PING baseline | fp=${fp}`);
      } else {
        console.log(`${target.kind.toUpperCase()} ${short} | PING stable | fp=${fp}`);
      }
    } else {
      // Drift detected - extract changed field names for output
      const changedFields = result.diff.changes.map(c => c.field).join(",");
      const short = shortenId(target.kind, target.id);
      
      if (deepScanCount >= maxDeepScans) {
        // Queue it - snapshot already saved by monitorTarget
        result.queued = true;
        console.log(`${target.kind.toUpperCase()} ${short} | PING CHANGED (${changedFields}) | deep=QUEUED`);
      } else {
        // Escalate to deep scan
        console.log(`${target.kind.toUpperCase()} ${short} | PING CHANGED (${changedFields}) | escalate=DEEP`);
        
        const deepResult = await runDeepScan(target, {
          rpc,
          rpc2,
          deepTimeoutMs,
          tmpDir,
          withSupraScan: options.withSupraScan,
          preferV2: options.preferV2,
          txSample: options.txSample,
        });

        result.deepScanTriggered = true;
        result.deepScanResult = deepResult;
        deepScanCount++;

        if (deepResult.success && deepResult.outputPath) {
          console.log(`${target.kind.toUpperCase()} ${short} | DEEP OK | out=${deepResult.outputPath}`);
        } else {
          console.log(`${target.kind.toUpperCase()} ${short} | DEEP FAIL | ${deepResult.error || "unknown error"}`);
        }
      }
    }
  }

  return results;
}


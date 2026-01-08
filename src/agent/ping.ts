/**
 * Level 4: Ping Mode - Low-cost drift monitoring
 * Minimal RPC calls to detect changes, escalate to deep scan on drift
 */

import { getIsoTimestamp } from "../utils/time.js";
import { sha256Hex } from "../utils/moduleHash.js";
import { stableJson } from "../utils/moduleHash.js";
import { fetchAccountResourcesV3 } from "../rpc/supraResourcesV3.js";
import { analyzeFaResources, type FaResourceCapabilities } from "../analyzers/fa/analyzeFaResources.js";
import { analyzeCoinResources, type CoinCapabilities } from "../analyzers/coin/analyzeCoinResources.js";
import { getModuleArtifact } from "../rpc/getModuleArtifact.js";
import { hashModuleArtifact } from "../utils/moduleHash.js";
import { parseCoinType } from "../core/coinScanner.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import { fetchAccountModulesV3 } from "../rpc/supraAccountsV3.js";
import { normalizeModuleId } from "../utils/moduleHash.js";

export interface PingSnapshot {
  meta: {
    ts: string; // ISO timestamp
    rpc: string;
    rpc2?: string;
    version: string; // "1.0"
    kind: "fa" | "coin";
  };
  identity: {
    kind: "fa" | "coin";
    id: string;
  };
  drift_keys: PingDriftKeys;
  fingerprint: string; // SHA256 hash of canonical JSON of drift_keys
}

export interface PingDriftKeys {
  // FA-specific
  owner?: string | null;
  supplyCurrent?: string;
  supplyMax?: string | null;
  hooks?: Array<{ module_address: string; module_name: string; function_name: string }>;
  hookModuleHashes?: Record<string, string | null>; // moduleId -> codeHash
  capabilities?: {
    mint?: boolean;
    burn?: boolean;
    transfer?: boolean;
    depositHook?: boolean;
    withdrawHook?: boolean;
    derivedBalanceHook?: boolean;
  };
  // Coin-specific
  decimals?: number | null;
  coinCapabilities?: {
    mint?: boolean;
    burn?: boolean;
    freeze?: boolean;
    transferRestrictions?: boolean;
  };
  publisherModuleHashes?: Record<string, string | null>; // moduleId -> codeHash
}

export interface PingDiffResult {
  changed: boolean;
  changes: Array<{
    field: string;
    type: "added" | "removed" | "modified" | "reordered";
    before?: any;
    after?: any;
    delta?: string; // For numeric changes
  }>;
  prevFingerprint?: string;
  currFingerprint: string;
}

/**
 * Compute fingerprint from drift keys (canonical JSON + SHA256)
 */
function computeFingerprint(driftKeys: PingDriftKeys): string {
  const canonical = stableJson(driftKeys);
  return sha256Hex(canonical);
}

/**
 * Build ping snapshot for FA
 */
export async function buildFAPingSnapshot(
  faAddress: string,
  rpcUrl: string,
  rpc2Url?: string,
  timeoutMs: number = 20000
): Promise<PingSnapshot | null> {
  const rpcOptions: RpcClientOptions = {
    rpcUrl,
    timeout: timeoutMs,
    retries: 1, // Minimal retries for ping mode
    retryDelay: 500,
  };

  try {
    // Fetch FA resources (single call)
    const resourcesResult = await fetchAccountResourcesV3(faAddress, rpcOptions);
    if (resourcesResult.error || !resourcesResult.resources || resourcesResult.resources.length === 0) {
      return null; // Failed to fetch
    }

    const resourcesJson = JSON.stringify(resourcesResult.resources);
    const analysis = analyzeFaResources(resourcesJson);

    // Build drift keys
    const driftKeys: PingDriftKeys = {
      owner: analysis.caps.owner || null,
      supplyCurrent: analysis.caps.supplyCurrent || undefined,
      supplyMax: analysis.caps.supplyMax || null,
      hooks: analysis.caps.hookModules || [],
      hookModuleHashes: {},
      capabilities: {
        mint: analysis.caps.hasMintRef,
        burn: analysis.caps.hasBurnRef,
        transfer: analysis.caps.hasTransferRef,
        depositHook: analysis.caps.hasDepositHook,
        withdrawHook: analysis.caps.hasWithdrawHook,
        derivedBalanceHook: analysis.caps.hasDerivedBalanceHook,
      },
    };

    // Fetch hook module hashes (best-effort, non-blocking)
    if (analysis.caps.hookModules && analysis.caps.hookModules.length > 0) {
      const hashPromises = analysis.caps.hookModules.map(async (hook) => {
        const moduleId = `${hook.module_address}::${hook.module_name}`;
        try {
          const artifact = await getModuleArtifact(
            rpcUrl,
            hook.module_address,
            hook.module_name,
            rpcOptions
          );
          const hashResult = hashModuleArtifact(artifact);
          return {
            moduleId: normalizeModuleId(moduleId),
            hash: hashResult?.hash || null,
          };
        } catch {
          return { moduleId: normalizeModuleId(moduleId), hash: null };
        }
      });

      const hashResults = await Promise.allSettled(hashPromises);
      for (const result of hashResults) {
        if (result.status === "fulfilled") {
          driftKeys.hookModuleHashes![result.value.moduleId] = result.value.hash;
        }
      }
    }

    const fingerprint = computeFingerprint(driftKeys);

    return {
      meta: {
        ts: getIsoTimestamp(),
        rpc: rpcUrl,
        rpc2: rpc2Url,
        version: "1.0",
        kind: "fa",
      },
      identity: {
        kind: "fa",
        id: faAddress.toLowerCase(),
      },
      drift_keys: driftKeys,
      fingerprint,
    };
  } catch (error) {
    return null; // Failed to build snapshot
  }
}

/**
 * Build ping snapshot for Coin
 */
export async function buildCoinPingSnapshot(
  coinType: string,
  rpcUrl: string,
  rpc2Url?: string,
  timeoutMs: number = 20000
): Promise<PingSnapshot | null> {
  const parsed = parseCoinType(coinType);
  if (!parsed) {
    return null;
  }

  const rpcOptions: RpcClientOptions = {
    rpcUrl,
    timeout: timeoutMs,
    retries: 1,
    retryDelay: 500,
  };

  try {
    // Fetch coin publisher resources (single call)
    const resourcesResult = await fetchAccountResourcesV3(parsed.publisherAddress, rpcOptions);
    if (resourcesResult.error || !resourcesResult.resources || resourcesResult.resources.length === 0) {
      return null;
    }

    const resourcesJson = JSON.stringify(resourcesResult.resources);
    const analysis = analyzeCoinResources(resourcesJson, coinType);

    // Build drift keys
    const driftKeys: PingDriftKeys = {
      supplyCurrent: analysis.caps.supplyCurrentBase || undefined,
      decimals: analysis.caps.decimals || null,
      coinCapabilities: {
        mint: analysis.caps.hasMintCap,
        burn: analysis.caps.hasBurnCap,
        freeze: analysis.caps.hasFreezeCap,
        transferRestrictions: analysis.caps.hasTransferRestrictions,
      },
      publisherModuleHashes: {},
    };

    // Ensure coin-defining module is included in publisherModuleHashes
    const coinDefiningModuleId = normalizeModuleId(`${parsed.publisherAddress}::${parsed.moduleName}`);
    try {
      // Always fetch the coin-defining module hash
      const coinModuleArtifact = await getModuleArtifact(
        rpcUrl,
        parsed.publisherAddress,
        parsed.moduleName,
        rpcOptions
      );
      const coinModuleHash = hashModuleArtifact(coinModuleArtifact);
      if (coinModuleHash) {
        driftKeys.publisherModuleHashes![coinDefiningModuleId] = coinModuleHash.hash;
      }
    } catch {
      // Non-fatal: continue without hash
    }

    // Also fetch other publisher modules and their hashes
    try {
      const modulesResult = await fetchAccountModulesV3(parsed.publisherAddress, rpcOptions);
      if (modulesResult.modules && modulesResult.modules.length > 0) {
        // Fetch hashes for all modules (not just first one - fix the bug)
        const hashPromises = modulesResult.modules.map(async (mod) => {
          if (!mod.name) return null;
          const moduleId = normalizeModuleId(`${parsed.publisherAddress}::${mod.name}`);
          // Skip if we already have this module (coin-defining one)
          if (moduleId === coinDefiningModuleId) return null;
          try {
            const artifact = await getModuleArtifact(
              rpcUrl,
              parsed.publisherAddress,
              mod.name,
              rpcOptions
            );
            const hashResult = hashModuleArtifact(artifact);
            return {
              moduleId,
              hash: hashResult?.hash || null,
            };
          } catch {
            return { moduleId, hash: null };
          }
        });

        const hashResults = await Promise.allSettled(hashPromises);
        for (const result of hashResults) {
          if (result.status === "fulfilled" && result.value) {
            driftKeys.publisherModuleHashes![result.value.moduleId] = result.value.hash;
          }
        }
      }
    } catch {
      // Non-fatal: continue without additional module hashes
    }

    const fingerprint = computeFingerprint(driftKeys);

    return {
      meta: {
        ts: getIsoTimestamp(),
        rpc: rpcUrl,
        rpc2: rpc2Url,
        version: "1.0",
        kind: "coin",
      },
      identity: {
        kind: "coin",
        id: coinType,
      },
      drift_keys: driftKeys,
      fingerprint,
    };
  } catch (error) {
    return null;
  }
}

/**
 * Diff two ping snapshots
 */
export function diffPingSnapshots(
  prev: PingSnapshot | null,
  curr: PingSnapshot
): PingDiffResult {
  if (!prev) {
    // First snapshot - no changes detected (new target, baseline)
    return {
      changed: false,
      changes: [],
      currFingerprint: curr.fingerprint,
    };
  }

  // Compare drift_keys directly (ignore meta.ts and fingerprint in comparison)
  // Fingerprint comparison is just for quick early exit, but we still do full diff

  const changes: PingDiffResult["changes"] = [];
  const prevKeys = prev.drift_keys;
  const currKeys = curr.drift_keys;

  // Compare owner (FA only)
  if (prev.identity.kind === "fa" && curr.identity.kind === "fa") {
    if (prevKeys.owner !== currKeys.owner) {
      changes.push({
        field: "owner",
        type: "modified",
        before: prevKeys.owner,
        after: currKeys.owner,
      });
    }
  }

  // Compare supply
  if (prevKeys.supplyCurrent !== currKeys.supplyCurrent) {
    const prevSupply = prevKeys.supplyCurrent ? BigInt(prevKeys.supplyCurrent) : null;
    const currSupply = currKeys.supplyCurrent ? BigInt(currKeys.supplyCurrent) : null;
    let delta: string | undefined;
    if (prevSupply !== null && currSupply !== null) {
      const diff = currSupply - prevSupply;
      delta = diff.toString();
    }
    changes.push({
      field: "supplyCurrent",
      type: "modified",
      before: prevKeys.supplyCurrent,
      after: currKeys.supplyCurrent,
      delta,
    });
  }

  // Compare supplyMax (FA only)
  if (prevKeys.supplyMax !== currKeys.supplyMax) {
    changes.push({
      field: "supplyMax",
      type: "modified",
      before: prevKeys.supplyMax,
      after: currKeys.supplyMax,
    });
  }

  // Compare hooks (FA only)
  if (prev.identity.kind === "fa" && curr.identity.kind === "fa") {
    const prevHooks = prevKeys.hooks || [];
    const currHooks = currKeys.hooks || [];
    
    // Normalize hook lists for comparison
    const prevHookSet = new Set(prevHooks.map(h => `${h.module_address}::${h.module_name}::${h.function_name}`));
    const currHookSet = new Set(currHooks.map(h => `${h.module_address}::${h.module_name}::${h.function_name}`));

    // Check for additions
    for (const hook of currHooks) {
      const hookStr = `${hook.module_address}::${hook.module_name}::${hook.function_name}`;
      if (!prevHookSet.has(hookStr)) {
        changes.push({
          field: "hooks",
          type: "added",
          after: hook,
        });
      }
    }

    // Check for removals
    for (const hook of prevHooks) {
      const hookStr = `${hook.module_address}::${hook.module_name}::${hook.function_name}`;
      if (!currHookSet.has(hookStr)) {
        changes.push({
          field: "hooks",
          type: "removed",
          before: hook,
        });
      }
    }
  }

  // Compare hook module hashes (FA only)
  const prevHookHashes = prevKeys.hookModuleHashes || {};
  const currHookHashes = currKeys.hookModuleHashes || {};
  const allHookModuleIds = new Set([
    ...Object.keys(prevHookHashes),
    ...Object.keys(currHookHashes),
  ]);

  for (const moduleId of allHookModuleIds) {
    const prevHash = prevHookHashes[moduleId];
    const currHash = currHookHashes[moduleId];
    if (prevHash !== currHash) {
      if (prevHash === undefined) {
        changes.push({
          field: `hookModuleHash.${moduleId}`,
          type: "added",
          after: currHash,
        });
      } else if (currHash === undefined) {
        changes.push({
          field: `hookModuleHash.${moduleId}`,
          type: "removed",
          before: prevHash,
        });
      } else {
        changes.push({
          field: `hookModuleHash.${moduleId}`,
          type: "modified",
          before: prevHash,
          after: currHash,
        });
      }
    }
  }

  // Compare publisher module hashes (Coin only)
  const prevPubHashes = prevKeys.publisherModuleHashes || {};
  const currPubHashes = currKeys.publisherModuleHashes || {};
  const allPubModuleIds = new Set([
    ...Object.keys(prevPubHashes),
    ...Object.keys(currPubHashes),
  ]);

  for (const moduleId of allPubModuleIds) {
    const prevHash = prevPubHashes[moduleId];
    const currHash = currPubHashes[moduleId];
    if (prevHash !== currHash) {
      if (prevHash === undefined) {
        changes.push({
          field: `publisherModuleHash.${moduleId}`,
          type: "added",
          after: currHash,
        });
      } else if (currHash === undefined) {
        changes.push({
          field: `publisherModuleHash.${moduleId}`,
          type: "removed",
          before: prevHash,
        });
      } else {
        changes.push({
          field: `publisherModuleHash.${moduleId}`,
          type: "modified",
          before: prevHash,
          after: currHash,
        });
      }
    }
  }

  // Compare capabilities (FA only)
  const prevCaps = prevKeys.capabilities || {};
  const currCaps = currKeys.capabilities || {};
  const capFields = ["mint", "burn", "transfer", "depositHook", "withdrawHook", "derivedBalanceHook"] as const;
  for (const field of capFields) {
    const prevVal = (prevCaps as any)[field];
    const currVal = (currCaps as any)[field];
    if (prevVal !== currVal) {
      changes.push({
        field: `capabilities.${field}`,
        type: "modified",
        before: prevVal,
        after: currVal,
      });
    }
  }

  // Compare coin capabilities (Coin only)
  const prevCoinCaps = prevKeys.coinCapabilities || {};
  const currCoinCaps = currKeys.coinCapabilities || {};
  const coinCapFields = ["mint", "burn", "freeze", "transferRestrictions"] as const;
  for (const field of coinCapFields) {
    const prevVal = (prevCoinCaps as any)[field];
    const currVal = (currCoinCaps as any)[field];
    if (prevVal !== currVal) {
      changes.push({
        field: `coinCapabilities.${field}`,
        type: "modified",
        before: prevVal,
        after: currVal,
      });
    }
  }

  return {
    changed: changes.length > 0,
    changes,
    prevFingerprint: prev.fingerprint,
    currFingerprint: curr.fingerprint,
  };
}


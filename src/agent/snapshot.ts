/**
 * Level 3 Agent/Watcher Mode Snapshot Builders
 * Build snapshots from ScanResult and Level-2 analysis
 */

import type { ScanResult } from "../core/types.js";
import type {
  CoinSnapshot,
  FASnapshot,
  SnapshotMeta,
  CoinIdentity,
  FAIdentity,
  SupplyData,
  CoinCapabilities,
  FACapabilities,
  ControlSurface,
  FAControlSurface,
  ModuleInfo,
  Coverage,
  FindingSummary,
} from "./types.js";
import { surfaceHashFromFnNames, overallHashFromMap } from "./hash.js";
import { analyzeCoinSurface } from "../analyzers/coin/analyzeCoinSurface.js";
import { analyzeCoinResources } from "../analyzers/coin/analyzeCoinResources.js";
import { analyzeFaSurface } from "../analyzers/fa/analyzeFaSurface.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";
import { fetchAccountResourcesV3 } from "../rpc/supraResourcesV3.js";
import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import {
  createEmptyEvidenceBundle,
  addSupplyParityCheck,
  addModuleCountParityCheck,
  addOwnerParityCheck,
  type EvidenceBundle,
} from "./evidence.js";

const ADDRESS_DETAIL_QUERY = `
  query AddressDetail(
    $address: String,
    $page: Int,
    $offset: Int,
    $userWalletAddress: String,
    $blockchainEnvironment: BlockchainEnvironment,
    $isAddressName: Boolean
  ) {
    addressDetail(
      address: $address,
      page: $page,
      offset: $offset,
      userWalletAddress: $userWalletAddress,
      blockchainEnvironment: $blockchainEnvironment,
      isAddressName: $isAddressName
    ) {
      isError
      errorType
      addressDetailSupra {
        resources
      }
    }
  }
`;

/**
 * Get scanner version from package.json or git hash
 */
async function getScannerVersion(): Promise<string> {
  try {
    const moduleImport = await import("module");
    const createRequire = (moduleImport as any).createRequire || (moduleImport.default as any)?.createRequire;
    const { fileURLToPath } = await import("url");
    const { dirname, join } = await import("path");
    const require = createRequire(import.meta.url);
    const packageJson = require(join(dirname(fileURLToPath(import.meta.url)), "../../package.json"));
    return packageJson.version || "0.1.0";
  } catch {
    return "0.1.0";
  }
}

/**
 * Build coin snapshot from scan result
 */
export async function buildCoinSnapshot(params: {
  scanResult: ScanResult;
  rpcUrl: string;
  scannerVersion?: string;
}): Promise<CoinSnapshot> {
  const { scanResult, rpcUrl, scannerVersion } = params;
  const version = scannerVersion || (await getScannerVersion());
  
  const coinMeta = scanResult.meta.coin_metadata;
  if (!coinMeta) {
    throw new Error("Coin metadata missing from scan result");
  }
  
  // Parse coin type to extract components
  const coinType = coinMeta.coinType;
  const parts = coinType.split("::");
  const publisherAddress = parts[0] || coinMeta.publisherAddress || "unknown";
  const moduleName = parts[1] || coinMeta.moduleName || "unknown";
  const symbol = coinMeta.symbol || parts[2] || "UNKNOWN";
  
  // Fetch resources for Level-1 and Level-2 analysis
  let resourceAnalysis: ReturnType<typeof analyzeCoinResources> | null = null;
  let surfaceAnalysis: Awaited<ReturnType<typeof analyzeCoinSurface>> | null = null;
  
  try {
    // Fetch resources from publisher address
    const resourcesResponse = await fetchAccountResourcesV3(publisherAddress, { rpcUrl });
    if (resourcesResponse.resources && Array.isArray(resourcesResponse.resources)) {
      const resourcesStr = JSON.stringify(resourcesResponse.resources);
      resourceAnalysis = analyzeCoinResources(resourcesStr, coinType);
      
      // Run Level-2 analysis
      if (resourceAnalysis) {
        surfaceAnalysis = await analyzeCoinSurface(
          resourceAnalysis.caps,
          publisherAddress,
          moduleName,
          rpcUrl,
          resourceAnalysis.resourceTypes,
          undefined,
          coinType,
          resourceAnalysis.supplyNormalizationFailed
        );
      }
    }
  } catch (error) {
    // Continue with defaults if resource fetch fails
    console.warn(`[Snapshot] Failed to fetch resources for coin: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Build identity
  const identity: CoinIdentity = {
    coinType,
    publisherAddress,
    moduleName,
    symbol,
  };
  
  // Build supply data
  const supply: SupplyData = {
    supplyCurrentBase: resourceAnalysis?.caps.supplyCurrentBase || coinMeta.totalSupply?.toString() || null,
    decimals: resourceAnalysis?.caps.decimals ?? coinMeta.decimals ?? null,
    supplyCurrentFormatted: resourceAnalysis?.caps.supplyCurrentFormatted || null,
    supplyMaxBase: resourceAnalysis?.caps.supplyMaxBase || null,
  };
  
  // Build capabilities
  const capabilities: CoinCapabilities = resourceAnalysis
    ? {
        hasMintCap: resourceAnalysis.caps.hasMintCap,
        hasBurnCap: resourceAnalysis.caps.hasBurnCap,
        hasFreezeCap: resourceAnalysis.caps.hasFreezeCap,
        hasTransferRestrictions: resourceAnalysis.caps.hasTransferRestrictions,
      }
    : {
        hasMintCap: false,
        hasBurnCap: false,
        hasFreezeCap: false,
        hasTransferRestrictions: false,
      };
  
  // Build control surface
  const control_surface: import("./types.js").CoinControlSurface = {
    relevantModules: [],
    modules: {},
    modulePins: [], // Always include, even if empty
  };
  
  if (surfaceAnalysis) {
    // Extract relevant modules from surface analysis
    const relevantModules = surfaceAnalysis.modulesAnalyzed.filter((m) => {
      const normalizedAddress = m.module_address.toLowerCase();
      return normalizedAddress === publisherAddress.toLowerCase();
    });
    
    control_surface.relevantModules = relevantModules.map(
      (m) => m.module_name ? `${m.module_address}::${m.module_name}` : m.module_address
    );
    
    // Build module info map
    for (const mod of relevantModules) {
      const moduleId = mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address;
      const entryFns = mod.exposed_entry_functions || [];
      const exposedFns = mod.exposed_functions || [];
      
      control_surface.modules[moduleId] = {
        moduleId,
        abi_fetched: mod.abi_fetched || false,
        entry_fn_names: entryFns,
        exposed_fn_names: exposedFns,
      };
    }
    
    // Add module pins (always include, even if empty)
    if (surfaceAnalysis.modulePins) {
      control_surface.modulePins = surfaceAnalysis.modulePins;
    }
  }
  
  // Build coverage
  const coverage: Coverage = surfaceAnalysis
    ? {
        coverage: surfaceAnalysis.coverage.status,
        reasons: surfaceAnalysis.coverage.reasons || [],
      }
    : {
        coverage: "partial",
        reasons: ["Level-2 analysis not available"],
      };
  
  // Build findings summary
  const findings: FindingSummary[] = scanResult.findings.map((f) => ({
    id: f.id,
    severity: f.severity as "info" | "medium" | "high" | "critical",
    title: f.title,
  }));
  
  // Build hashes
  const moduleSurfaceHash: Record<string, string> = {};
  for (const [moduleId, moduleInfo] of Object.entries(control_surface.modules)) {
    const allFns = [...moduleInfo.entry_fn_names, ...moduleInfo.exposed_fn_names];
    moduleSurfaceHash[moduleId] = surfaceHashFromFnNames(allFns);
  }
  const overallSurfaceHash = overallHashFromMap(moduleSurfaceHash);
  
  // Build meta
  const meta: SnapshotMeta = {
    schema_version: "3.0",
    timestamp_iso: scanResult.timestamp_iso,
    rpc_url: rpcUrl,
    scanner_version: version,
  };
  
  // Build evidence bundle (Level 3 multi-source verification)
  const evidence: EvidenceBundle = createEmptyEvidenceBundle();
  evidence.sourcesUsed.push("rpc_v3"); // We used RPC v3 for resources
  // Add supply parity check if we have both RPC and SupraScan data
  // (For now, we only have RPC data, so parity checks will be marked as unknown)
  addSupplyParityCheck(evidence, supply.supplyCurrentBase || null, coinMeta.totalSupply?.toString() || null);
  // Module count parity would require RPC v1 call (not implemented in snapshot builder yet)

  return {
    meta,
    identity,
    supply,
    capabilities,
    control_surface,
    coverage,
    findings,
    hashes: {
      moduleSurfaceHash,
      overallSurfaceHash,
      modulePinsHash: surfaceAnalysis?.modulePinsHash,
    },
    privileges: surfaceAnalysis?.privileges,
    invariants: surfaceAnalysis?.invariants,
    evidence,
  };
}

/**
 * Build FA snapshot from scan result
 */
export async function buildFASnapshot(params: {
  scanResult: ScanResult;
  rpcUrl: string;
  scannerVersion?: string;
}): Promise<FASnapshot> {
  const { scanResult, rpcUrl, scannerVersion } = params;
  const version = scannerVersion || (await getScannerVersion());
  
  const faMeta = scanResult.meta.fa_metadata;
  if (!faMeta) {
    throw new Error("FA metadata missing from scan result");
  }
  
  const faAddress = faMeta.address;
  
  // Fetch resources for Level-1 and Level-2 analysis
  let resourceAnalysis: ReturnType<typeof analyzeFaResources> | null = null;
  let surfaceAnalysis: Awaited<ReturnType<typeof analyzeFaSurface>> | null = null;
  let resourceTypes: string[] = [];
  
  try {
    // Fetch resources via SupraScan GraphQL
    const data = await suprascanGraphql<{
      addressDetail: {
        isError: boolean;
        errorType: string | null;
        addressDetailSupra: { resources: string | null } | null;
      };
    }>(
      ADDRESS_DETAIL_QUERY,
      {
        address: faAddress,
        blockchainEnvironment: "mainnet",
        isAddressName: false,
      },
      { env: "mainnet" }
    );
    
    if (data.addressDetail?.addressDetailSupra?.resources) {
      const resourcesStr = data.addressDetail.addressDetailSupra.resources;
      resourceAnalysis = analyzeFaResources(resourcesStr);
      
      // Extract resource types
      try {
        const resources = JSON.parse(resourcesStr);
        if (Array.isArray(resources)) {
          resourceTypes = resources.map((r: any) => r?.type).filter(Boolean);
        }
      } catch {
        // Ignore parse errors
      }
      
      // Run Level-2 analysis
      if (resourceAnalysis) {
        const ownerAddress = resourceAnalysis.caps.owner || undefined;
        surfaceAnalysis = await analyzeFaSurface(
          resourceAnalysis.caps,
          rpcUrl,
          ownerAddress,
          ownerAddress,
          resourceTypes,
          undefined,
          resourceAnalysis.parsedCount
        );
      }
    }
  } catch (error) {
    // Continue with defaults if resource fetch fails
    console.warn(`[Snapshot] Failed to fetch resources for FA: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Build identity
  const identity: FAIdentity = {
    faAddress,
    objectOwner: resourceAnalysis?.caps.owner || null,
  };
  
  // Build supply data
  const supply: SupplyData = {
    supplyCurrentBase: resourceAnalysis?.caps.supplyCurrent || faMeta.totalSupply?.toString() || null,
    supplyMaxBase: resourceAnalysis?.caps.supplyMax || null,
    decimals: faMeta.decimals ?? null,
  };
  
  // Build capabilities
  const capabilities: FACapabilities = resourceAnalysis
    ? {
        hasMintRef: resourceAnalysis.caps.hasMintRef,
        hasBurnRef: resourceAnalysis.caps.hasBurnRef,
        hasTransferRef: resourceAnalysis.caps.hasTransferRef,
        hasDepositHook: resourceAnalysis.caps.hasDepositHook,
        hasWithdrawHook: resourceAnalysis.caps.hasWithdrawHook,
        hasDerivedBalanceHook: resourceAnalysis.caps.hasDerivedBalanceHook,
      }
    : {
        hasMintRef: false,
        hasBurnRef: false,
        hasTransferRef: false,
        hasDepositHook: false,
        hasWithdrawHook: false,
        hasDerivedBalanceHook: false,
      };
  
  // Build control surface
  const control_surface: FAControlSurface = {
    relevantModules: [],
    modules: {},
    hookModules: resourceAnalysis?.caps.hookModules || [],
    hooks: resourceAnalysis?.caps.hooks ? (() => {
      // Add risk classification to hooks
      const hooks: any = {};
      if (resourceAnalysis.caps.hooks.deposit_hook) {
        hooks.deposit_hook = { ...resourceAnalysis.caps.hooks.deposit_hook, risk: "medium" };
      }
      if (resourceAnalysis.caps.hooks.withdraw_hook) {
        hooks.withdraw_hook = { ...resourceAnalysis.caps.hooks.withdraw_hook, risk: "high" };
      }
      if (resourceAnalysis.caps.hooks.transfer_hook) {
        hooks.transfer_hook = { ...resourceAnalysis.caps.hooks.transfer_hook, risk: "high" };
      }
      if (resourceAnalysis.caps.hooks.pre_transfer_hook) {
        hooks.pre_transfer_hook = { ...resourceAnalysis.caps.hooks.pre_transfer_hook, risk: "high" };
      }
      if (resourceAnalysis.caps.hooks.post_transfer_hook) {
        hooks.post_transfer_hook = { ...resourceAnalysis.caps.hooks.post_transfer_hook, risk: "medium" };
      }
      if (resourceAnalysis.caps.hooks.derived_balance_hook) {
        hooks.derived_balance_hook = { ...resourceAnalysis.caps.hooks.derived_balance_hook, risk: "low" };
      }
      return Object.keys(hooks).length > 0 ? hooks : undefined;
    })() : undefined,
    hookModulePins: [], // Always include, even if empty
    ownerModulesCount: 0,
  };
  
  if (surfaceAnalysis) {
    // Extract relevant modules (hook + owner modules, exclude system)
    const relevantModules = surfaceAnalysis.modulesAnalyzed.filter((m) => {
      const normalizedAddress = m.module_address.toLowerCase();
      return normalizedAddress !== "0x1" && normalizedAddress !== "0x3";
    });
    
    control_surface.relevantModules = relevantModules.map(
      (m) => m.module_name ? `${m.module_address}::${m.module_name}` : m.module_address
    );
    
    // Count owner modules
    const ownerModules = relevantModules.filter((m) => m.source === "fa_owner_modules");
    control_surface.ownerModulesCount = ownerModules.length;
    
    // Build module info map
    for (const mod of relevantModules) {
      const moduleId = mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address;
      const entryFns = mod.exposed_entry_functions || [];
      
      control_surface.modules[moduleId] = {
        moduleId,
        abi_fetched: mod.abi_fetched || false,
        entry_fn_names: entryFns,
        exposed_fn_names: [], // FA uses entry functions primarily
      };
    }
  }
  
  // Build coverage
  const coverage: Coverage = surfaceAnalysis
    ? {
        coverage: surfaceAnalysis.coverage.status,
        reasons: surfaceAnalysis.coverage.reasons || [],
      }
    : {
        coverage: "partial",
        reasons: ["Level-2 analysis not available"],
      };
  
  // Build findings summary
  const findings: FindingSummary[] = scanResult.findings.map((f) => ({
    id: f.id,
    severity: f.severity as "info" | "medium" | "high" | "critical",
    title: f.title,
  }));
  
  // Add hook module pins to control surface (always include, even if empty)
  if (surfaceAnalysis?.hookModulePins) {
    control_surface.hookModulePins = surfaceAnalysis.hookModulePins;
  }
  // If no pins from analysis but we have hookModules, ensure empty array is present
  // (already initialized above)
  
  // Build hashes
  const moduleSurfaceHash: Record<string, string> = {};
  for (const [moduleId, moduleInfo] of Object.entries(control_surface.modules)) {
    const allFns = [...moduleInfo.entry_fn_names, ...moduleInfo.exposed_fn_names];
    moduleSurfaceHash[moduleId] = surfaceHashFromFnNames(allFns);
  }
  const overallSurfaceHash = overallHashFromMap(moduleSurfaceHash);
  
  // Build meta
  const meta: SnapshotMeta = {
    schema_version: "3.0",
    timestamp_iso: scanResult.timestamp_iso,
    rpc_url: rpcUrl,
    scanner_version: version,
  };
  
  // Build evidence bundle (Level 3 multi-source verification)
  const evidence: EvidenceBundle = createEmptyEvidenceBundle();
  evidence.sourcesUsed.push("rpc_v3"); // We used RPC v3 for module ABIs
  evidence.sourcesUsed.push("suprascan"); // We used SupraScan GraphQL for resources
  // Add supply parity check
  addSupplyParityCheck(evidence, supply.supplyCurrentBase || null, faMeta.totalSupply?.toString() || null);
  // Add owner parity check (owner comes from resources, not metadata)
  addOwnerParityCheck(evidence, identity.objectOwner || null, identity.objectOwner || null);

  return {
    meta,
    identity,
    supply,
    capabilities,
    control_surface,
    coverage,
    findings,
    hashes: {
      moduleSurfaceHash,
      overallSurfaceHash,
      hookModulesSurfaceHash: surfaceAnalysis?.hookModulesSurfaceHash,
    },
    privileges: surfaceAnalysis?.privileges,
    invariants: surfaceAnalysis?.invariants,
    evidence,
  };
}


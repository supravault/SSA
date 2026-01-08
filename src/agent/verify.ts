// src/agent/verify.ts
// Level 3 Agent Mode: Multi-source verification and corroboration

import type { EvidenceSource } from "./evidence.js";
import type { IndexerParityRecord, IndexerParityStatus, RiskSynthesis } from "./types.js";
import { sampleRecentTxBehavior, buildPinnedEntryFunctionsMap, BehaviorEvidence } from "./txBehavior.js";
import { synthesizeRisk } from "./risk.js";
import { fetchAccountResourcesV3 } from "../rpc/supraResourcesV3.js";
import { fetchResourcesV1 } from "../rpc/supraResourcesV1.js";
import { suprascanGraphql, fetchAddressDetailSupra } from "../adapters/suprascanGraphql.js";
import { fetchSupraScanFAEvidence, type SupraScanProviderResponse } from "../providers/suprascan.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";
import { analyzeCoinResources } from "../analyzers/coin/analyzeCoinResources.js";
import { parseCoinType } from "../core/coinScanner.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import { getModuleArtifact } from "../rpc/getModuleArtifact.js";
import { hashModuleArtifact, normalizeModuleId } from "../utils/moduleHash.js";

export type ClaimType =
  | "OWNER"
  | "SUPPLY"
  | "HOOKS"
  | "CAPS"
  | "MODULES"
  | "ABI_PRESENCE"
  | "HOOK_MODULE_HASHES"
  | "MODULE_HASHES"
  | "INDEXER_PARITY"
  | "CREATOR";
export type ClaimStatus = "CONFIRMED" | "CONFLICT" | "PARTIAL" | "UNAVAILABLE";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";
export type EvidenceTier = "view_only" | "multi_rpc_confirmed" | "multi_rpc_plus_indexer" | "multi_source_confirmed";

export interface HookModule {
  module_address: string;
  module_name: string;
  function_name: string;
}

export interface ModuleHashPin {
  moduleId: string;
  codeHash: string | null;
  hashBasis: "bytecode" | "abi" | "none";
  fetchedFrom: string;
  role?: string; // For COIN only
}

export interface MiniSurface {
  owner?: string;
  supplyCurrentBase?: string;
  supplyMaxBase?: string; // FA only (best-effort)
  decimals?: number;
  hookModules?: HookModule[];
  capabilities?: Record<string, boolean>;
  moduleInventory?: string[]; // module IDs
  abiPresence?: Array<{
    moduleId: string;
    hasAbi: boolean;
    entryFns?: number;
    exposedFns?: number;
  }>;
  hookModuleHashes?: ModuleHashPin[]; // FA only
  moduleHashes?: ModuleHashPin[]; // COIN only
  rawHints?: {
    resourceTypes?: string[];
    moduleCount?: number;
  };
}

export interface ClaimConfirmation {
  source: EvidenceSource;
  ok: boolean;
  value: any;
  rawHint?: string;
  error?: string;
}

export interface Claim {
  claimType: ClaimType;
  value: any;
  confirmations: ClaimConfirmation[];
  status: ClaimStatus;
  confidence: Confidence;
}

export interface Discrepancy {
  claimType: ClaimType;
  sources: EvidenceSource[];
  values: Record<EvidenceSource, any>;
  detail: string;
}

export interface ProviderResult {
  source: EvidenceSource;
  ok: boolean;
  error?: string;
  hint?: string;
}

export interface VerificationReport {
  target: {
    kind: "fa" | "coin";
    id: string;
  };
  timestamp_iso: string;
  rpc_url: string;
  mode: "fast" | "strict";
  sources_attempted: EvidenceSource[];
  sources_succeeded: EvidenceSource[];
  provider_results: ProviderResult[];
  claims: Claim[];
  overallEvidenceTier: EvidenceTier;
  discrepancies: Discrepancy[];
  // Additive fields for FA SupraScan support + parity summary (do not break existing keys)
  suprascan_fa?: {
    status: IndexerParityStatus | "partial_ok";
    ok: boolean;
    urlUsed?: string;
    evidence?: {
      owner?: string | null;
      supply?: string | null;
      hooks?: HookModule[];
      hookModuleHashes?: Array<{
        moduleId: string;
        codeHash: string | null;
        hashBasis: "bytecode" | "abi" | "none";
        source: "suprascan";
      }>;
      creatorAddress?: string | null;
      details?: {
        name?: string;
        symbol?: string;
        holders?: number;
        verified?: boolean;
        iconUrl?: string;
      };
    };
    reason?: string;
    diagnostics?: {
      httpStatus?: number;
      topLevelKeys?: string[];
      jsonPreview?: string;
      rawPath?: string;
    };
  };
  parity?: {
    owner?: "match" | "mismatch" | "unknown";
    supply?: "match" | "mismatch" | "unknown";
    supplyMax?: "match" | "mismatch" | "unknown";
    hooks?: "match" | "mismatch" | "unknown";
  };
  /** Typed evidence record for FA indexer parity (explains why indexer is or isn't available) */
  indexer_parity?: IndexerParityRecord;
  /** Level 3 behavior evidence from transaction sampling */
  behavior?: BehaviorEvidence;
  /** Risk synthesis - agent-grade signals and verdict */
  risk?: RiskSynthesis;
  status?: "CONFLICT" | "OK" | "INVALID_ARGS";
  verdict?: string;
}

/**
 * Validate RPC URL - reject placeholders and malformed URLs
 */
export function validateRpcUrl(url: string, sourceName: string): { valid: boolean; error?: string } {
  if (!url || typeof url !== "string") {
    return { valid: false, error: "invalid rpc url" };
  }
  
  // Check for placeholder characters
  if (url.includes("<") || url.includes(">")) {
    return { valid: false, error: "invalid rpc url" };
  }
  
  // Try to parse as URL
  try {
    const parsed = new URL(url);
    // Must be http or https
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, error: "invalid rpc url" };
    }
    // Must have hostname
    if (!parsed.hostname || parsed.hostname.length === 0) {
      return { valid: false, error: "invalid rpc url" };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: "invalid rpc url" };
  }
}

/**
 * Normalize address to lowercase hex
 */
export function normalizeAddress(addr: string | null | undefined): string | null {
  if (!addr) return null;
  const normalized = addr.toLowerCase().trim();
  return normalized.startsWith("0x") ? normalized : `0x${normalized}`;
}

/**
 * Normalize supply value to base units string
 */
export function normalizeSupply(
  value: any,
  decimals?: number | null
): string | null {
  if (value === null || value === undefined) return null;
  
  // If already a string of digits, return as-is
  if (typeof value === "string" && /^\d+$/.test(value)) {
    return value;
  }
  
  // If number, convert to string
  if (typeof value === "number") {
    return String(Math.floor(value));
  }
  
  // Try to extract from nested structure
  if (typeof value === "object") {
    // Try common paths
    if (value.value !== undefined) {
      return normalizeSupply(value.value, decimals);
    }
    if (value.magnitude !== undefined) {
      return normalizeSupply(value.magnitude, decimals);
    }
    if (value.current?.value !== undefined) {
      return normalizeSupply(value.current.value, decimals);
    }
  }
  
  return null;
}

/**
 * Normalize hook modules array (sort by module_address, module_name, function_name)
 */
export function normalizeHookModules(hooks: HookModule[] | undefined): HookModule[] {
  if (!hooks || !Array.isArray(hooks)) return [];
  
  return [...hooks].sort((a, b) => {
    const aStr = `${a.module_address}::${a.module_name}::${a.function_name}`;
    const bStr = `${b.module_address}::${b.module_name}::${b.function_name}`;
    return aStr.localeCompare(bStr);
  });
}

/**
 * Stamp fetchedFrom field in confirmation values to match the confirmation source
 * Recursively processes arrays and objects to ensure provenance is correct
 */
function stampFetchedFrom(value: any, source: string): any {
  if (Array.isArray(value)) {
    return value.map(v => stampFetchedFrom(v, source));
  }
  if (value && typeof value === "object") {
    // Do NOT mutate original
    const out: any = { ...value };
    // Always override if present OR if this is one of our hash pin objects
    // (has codeHash/moduleId/hashBasis/role etc)
    if ("fetchedFrom" in out || "codeHash" in out || "moduleId" in out || "hashBasis" in out) {
      out.fetchedFrom = source;
    }
    // Also recursively stamp nested objects and arrays if any (safe)
    for (const k of Object.keys(out)) {
      const vv = out[k];
      if (vv && typeof vv === "object") {
        out[k] = stampFetchedFrom(vv, source);
      }
    }
    return out;
  }
  return value;
}

/**
 * Canonicalize value for comparison by removing volatile/evidence-only fields
 * Used for cross-source comparisons to ignore provenance differences
 */
function canonicalizeForCompare(value: any): any {
  if (Array.isArray(value)) {
    // Canonicalize each element and sort deterministically
    const canonicalized = value.map(v => canonicalizeForCompare(v));
    // Sort by moduleId (or module_address+module_name) then codeHash
    return canonicalized.sort((a, b) => {
      const aId = a?.moduleId || (a?.module_address && a?.module_name ? `${a.module_address}::${a.module_name}` : "");
      const bId = b?.moduleId || (b?.module_address && b?.module_name ? `${b.module_address}::${b.module_name}` : "");
      const idCmp = aId.localeCompare(bId);
      if (idCmp !== 0) return idCmp;
      const aHash = a?.codeHash || "";
      const bHash = b?.codeHash || "";
      return aHash.localeCompare(bHash);
    });
  }
  if (value && typeof value === "object") {
    const out: any = {};
    // Only include semantic fields, exclude volatile fields
    for (const k of Object.keys(value)) {
      if (k === "fetchedFrom" || k === "rawHint" || k === "timestamp" || k === "timestamp_iso") {
        continue; // Skip volatile/evidence-only fields
      }
      out[k] = canonicalizeForCompare(value[k]);
    }
    // Sort keys for deterministic output
    const sortedKeys = Object.keys(out).sort();
    const sorted: any = {};
    for (const k of sortedKeys) {
      sorted[k] = out[k];
    }
    return sorted;
  }
  return value;
}

/**
 * Stable stringify with canonicalization for comparison
 * Removes volatile fields and sorts keys/arrays for deterministic comparison
 */
function stableStringifyCanonical(value: any): string {
  const canonical = canonicalizeForCompare(value);
  return JSON.stringify(canonical);
}

/**
 * Compute hook module hashes for FA tokens
 */
export async function computeHookModuleHashes(
  hookModules: HookModule[] | undefined,
  rpcUrl: string,
  rpcOptions?: Partial<RpcClientOptions>
): Promise<ModuleHashPin[]> {
  if (!hookModules || hookModules.length === 0) {
    return [];
  }

  const uniqueModules = new Map<string, { module_address: string; module_name: string }>();
  
  // Collect unique hook modules
  for (const hook of hookModules) {
    const key = `${hook.module_address}::${hook.module_name}`;
    if (!uniqueModules.has(key)) {
      uniqueModules.set(key, {
        module_address: hook.module_address,
        module_name: hook.module_name,
      });
    }
  }

  const pins: ModuleHashPin[] = [];
  const opts: RpcClientOptions = {
    rpcUrl,
    timeout: rpcOptions?.timeout || 8000,
    retries: rpcOptions?.retries || 1,
    retryDelay: rpcOptions?.retryDelay || 500,
  };

  // Fetch artifacts and compute hashes
  for (const { module_address, module_name } of uniqueModules.values()) {
    try {
      const artifact = await getModuleArtifact(rpcUrl, module_address, module_name, opts);
      const hashResult = hashModuleArtifact(artifact);
      
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      pins.push({
        moduleId,
        codeHash: hashResult?.hash || null,
        hashBasis: hashResult?.basis || "none",
        fetchedFrom: artifact.fetchedFrom,
      });
    } catch (error) {
      // If fetch fails, still add entry with null hash
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      pins.push({
        moduleId,
        codeHash: null,
        hashBasis: "none",
        fetchedFrom: "unknown",
      });
    }
  }

  // Sort by moduleId for deterministic output
  return pins.sort((a, b) => a.moduleId.localeCompare(b.moduleId));
}

/**
 * Compute module hashes for COIN tokens
 */
export async function computeCoinModuleHashes(
  coinType: string,
  rpcUrl: string,
  rpcOptions?: Partial<RpcClientOptions>
): Promise<ModuleHashPin[]> {
  try {
    const parsed = parseCoinType(coinType);
    const moduleId = normalizeModuleId(`${parsed.publisherAddress}::${parsed.moduleName}`);
    
    const opts: RpcClientOptions = {
      rpcUrl,
      timeout: rpcOptions?.timeout || 8000,
      retries: rpcOptions?.retries || 1,
      retryDelay: rpcOptions?.retryDelay || 500,
    };

    try {
      const artifact = await getModuleArtifact(rpcUrl, parsed.publisherAddress, parsed.moduleName, opts);
      const hashResult = hashModuleArtifact(artifact);
      
      return [{
        moduleId,
        codeHash: hashResult?.hash || null,
        hashBasis: hashResult?.basis || "none",
        fetchedFrom: artifact.fetchedFrom,
        role: "coin_defining",
      }];
    } catch (error) {
      // If fetch fails, still return entry with null hash
      return [{
        moduleId,
        codeHash: null,
        hashBasis: "none",
        fetchedFrom: "unknown",
        role: "coin_defining",
      }];
    }
  } catch (error) {
    // If parsing fails, return empty
    return [];
  }
}

/**
 * Extract mini surface from FA resources (v3)
 */
export async function providerRpcV3ResourcesFA(
  faAddress: string,
  options: RpcClientOptions
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    const resources = await fetchAccountResourcesV3(faAddress, options);
    if (!resources.resources || resources.resources.length === 0) {
      return {
        surface: null,
        error: "empty response",
        hint: "RPC v3 returned no resources",
      };
    }
    
    try {
      const resourcesJson = JSON.stringify(resources.resources);
      const analysis = analyzeFaResources(resourcesJson);
      
      const hookModules: HookModule[] = [];
      if (analysis.caps.hookModules) {
        for (const h of analysis.caps.hookModules) {
          hookModules.push({
            module_address: h.module_address,
            module_name: h.module_name,
            function_name: h.function_name,
          });
        }
      }
      
      const capabilities: Record<string, boolean> = {
        hasMintRef: analysis.caps.hasMintRef,
        hasBurnRef: analysis.caps.hasBurnRef,
        hasTransferRef: analysis.caps.hasTransferRef,
        hasDepositHook: analysis.caps.hasDepositHook,
        hasWithdrawHook: analysis.caps.hasWithdrawHook,
        hasDerivedBalanceHook: analysis.caps.hasDerivedBalanceHook,
      };
      
      const resourceTypes = resources.resources.map((r: any) => r.type || "").filter(Boolean);
      
      // Compute hook module hashes
      const hookModuleHashes = await computeHookModuleHashes(hookModules, options.rpcUrl, options);
      
      return {
        surface: {
          owner: normalizeAddress(analysis.caps.owner) || undefined,
          supplyCurrentBase: normalizeSupply(analysis.caps.supplyCurrent) || undefined,
          supplyMaxBase: normalizeSupply(analysis.caps.supplyMax) || undefined,
          decimals: undefined, // FA decimals from metadata, not resources
          hookModules: normalizeHookModules(hookModules),
          capabilities,
          hookModuleHashes,
          rawHints: {
            resourceTypes,
          },
        },
        hint: "RPC v3 resources",
      };
    } catch (parseError) {
      return {
        surface: null,
        error: parseError instanceof Error ? parseError.message : "Resource parsing failed",
        hint: "RPC v3 resources parse error",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "RPC v3 timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "RPC v3 fetch failed",
    };
  }
}

/**
 * Extract mini surface from COIN resources (v3)
 */
export async function providerRpcV3ResourcesCoin(
  coinType: string,
  options: RpcClientOptions
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    const parsed = parseCoinType(coinType);
    const resources = await fetchAccountResourcesV3(parsed.publisherAddress, options);
    if (!resources.resources || resources.resources.length === 0) {
      return {
        surface: null,
        error: "empty response",
        hint: "RPC v3 returned no resources",
      };
    }
    
    try {
      const resourcesJson = JSON.stringify(resources.resources);
      const analysis = analyzeCoinResources(resourcesJson, coinType);
      
      const capabilities: Record<string, boolean> = {
        hasMintCap: analysis.caps.hasMintCap,
        hasBurnCap: analysis.caps.hasBurnCap,
        hasFreezeCap: analysis.caps.hasFreezeCap,
        hasTransferRestrictions: analysis.caps.hasTransferRestrictions,
      };
      
      const resourceTypes = resources.resources.map((r: any) => r.type || "").filter(Boolean);
      
      // Compute module hashes for coin-defining module
      const moduleHashes = await computeCoinModuleHashes(coinType, options.rpcUrl, options);
      
      return {
        surface: {
          supplyCurrentBase: normalizeSupply(analysis.caps.supplyCurrentBase, analysis.caps.decimals) || undefined,
          decimals: analysis.caps.decimals ?? undefined,
          capabilities,
          moduleHashes,
          rawHints: {
            resourceTypes,
          },
        },
        hint: "RPC v3 resources",
      };
    } catch (parseError) {
      return {
        surface: null,
        error: parseError instanceof Error ? parseError.message : "Resource parsing failed",
        hint: "RPC v3 resources parse error",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "RPC v3 timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "RPC v3 fetch failed",
    };
  }
}

/**
 * Extract mini surface from FA resources (v1)
 */
export async function providerRpcV1ResourcesFA(
  faAddress: string,
  rpcUrl: string
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    const resources = await fetchResourcesV1(rpcUrl, faAddress);
    if (!resources.resources || resources.resources.length === 0) {
      return {
        surface: null,
        error: "empty response",
        hint: "RPC v1 returned no resources",
      };
    }
    
    try {
      const resourcesJson = JSON.stringify(resources.resources);
      const analysis = analyzeFaResources(resourcesJson);
      
      const hookModules: HookModule[] = [];
      if (analysis.caps.hookModules) {
        for (const h of analysis.caps.hookModules) {
          hookModules.push({
            module_address: h.module_address,
            module_name: h.module_name,
            function_name: h.function_name,
          });
        }
      }
      
      const capabilities: Record<string, boolean> = {
        hasMintRef: analysis.caps.hasMintRef,
        hasBurnRef: analysis.caps.hasBurnRef,
        hasTransferRef: analysis.caps.hasTransferRef,
        hasDepositHook: analysis.caps.hasDepositHook,
        hasWithdrawHook: analysis.caps.hasWithdrawHook,
        hasDerivedBalanceHook: analysis.caps.hasDerivedBalanceHook,
      };
      
      // Compute hook module hashes
      const hookModuleHashes = await computeHookModuleHashes(hookModules, rpcUrl, {
        timeout: 8000,
        retries: 1,
        retryDelay: 500,
      });
      
      return {
        surface: {
          owner: normalizeAddress(analysis.caps.owner) || undefined,
          supplyCurrentBase: normalizeSupply(analysis.caps.supplyCurrent) || undefined,
          supplyMaxBase: normalizeSupply(analysis.caps.supplyMax) || undefined,
          hookModules: normalizeHookModules(hookModules),
          capabilities,
          hookModuleHashes,
        },
        hint: "RPC v1 resources",
      };
    } catch (parseError) {
      return {
        surface: null,
        error: parseError instanceof Error ? parseError.message : "Resource parsing failed",
        hint: "RPC v1 resources parse error",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "RPC v1 timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "RPC v1 fetch failed",
    };
  }
}

/**
 * Extract mini surface from COIN resources (v1)
 */
export async function providerRpcV1ResourcesCoin(
  coinType: string,
  rpcUrl: string
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    const parsed = parseCoinType(coinType);
    const resources = await fetchResourcesV1(rpcUrl, parsed.publisherAddress);
    if (!resources.resources || resources.resources.length === 0) {
      return {
        surface: null,
        error: "empty response",
        hint: "RPC v1 returned no resources",
      };
    }
    
    try {
      const resourcesJson = JSON.stringify(resources.resources);
      const analysis = analyzeCoinResources(resourcesJson, coinType);
      
      const capabilities: Record<string, boolean> = {
        hasMintCap: analysis.caps.hasMintCap,
        hasBurnCap: analysis.caps.hasBurnCap,
        hasFreezeCap: analysis.caps.hasFreezeCap,
        hasTransferRestrictions: analysis.caps.hasTransferRestrictions,
      };
      
      // Compute module hashes for coin-defining module
      const moduleHashes = await computeCoinModuleHashes(coinType, rpcUrl, {
        timeout: 8000,
        retries: 1,
        retryDelay: 500,
      });
      
      return {
        surface: {
          supplyCurrentBase: normalizeSupply(analysis.caps.supplyCurrentBase, analysis.caps.decimals) || undefined,
          decimals: analysis.caps.decimals ?? undefined,
          capabilities,
          moduleHashes,
        },
        hint: "RPC v1 resources",
      };
    } catch (parseError) {
      return {
        surface: null,
        error: parseError instanceof Error ? parseError.message : "Resource parsing failed",
        hint: "RPC v1 resources parse error",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "RPC v1 timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "RPC v1 fetch failed",
    };
  }
}

/**
 * Extract mini surface from SupraScan GraphQL (FA)
 * Uses getFaDetails query for owner/supply, falls back to addressDetail for resources
 */
export async function providerSupraScanGraphQLFA(
  faAddress: string,
  timeoutMs: number = 8000
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    // Try getFaDetails first (has totalSupply, decimals, creatorAddress)
    const { fetchFaDetailsFromSupraScan } = await import("../rpc/supraScanGraphql.js");
    const faDetails = await fetchFaDetailsFromSupraScan(faAddress, "mainnet");
    
    if (faDetails) {
      // getFaDetails provides: totalSupply, decimals, creatorAddress (not owner directly)
      const supplyBase = normalizeSupply(faDetails.totalSupply, faDetails.decimals);
      let supplyMaxBase: string | null = null;
      
      // Also try addressDetail for resources (owner, hooks, capabilities)
      let owner: string | null = null;
      let hookModules: HookModule[] = [];
      let capabilities: Record<string, boolean> = {};
      
      try {
        const addressDetail = await fetchAddressDetailSupra(faAddress, "mainnet", { timeoutMs });
        if (addressDetail?.addressDetailSupra?.resources) {
          try {
            const analysis = analyzeFaResources(addressDetail.addressDetailSupra.resources);
            owner = normalizeAddress(analysis.caps.owner || addressDetail.addressDetailSupra.ownerAddress);
            supplyMaxBase = normalizeSupply(analysis.caps.supplyMax) || null;
            
            if (analysis.caps.hookModules) {
              for (const h of analysis.caps.hookModules) {
                hookModules.push({
                  module_address: h.module_address,
                  module_name: h.module_name,
                  function_name: h.function_name,
                });
              }
            }
            
            capabilities = {
              hasMintRef: analysis.caps.hasMintRef,
              hasBurnRef: analysis.caps.hasBurnRef,
              hasTransferRef: analysis.caps.hasTransferRef,
              hasDepositHook: analysis.caps.hasDepositHook,
              hasWithdrawHook: analysis.caps.hasWithdrawHook,
              hasDerivedBalanceHook: analysis.caps.hasDerivedBalanceHook,
            };
          } catch (parseError) {
            // Resources parse failed, but we still have supply from getFaDetails
          }
        } else if (addressDetail?.addressDetailSupra?.ownerAddress) {
          owner = normalizeAddress(addressDetail.addressDetailSupra.ownerAddress);
        }
      } catch {
        // addressDetail failed, but we still have supply from getFaDetails
      }
      
      // If we have at least supply or owner, return success
      if (supplyBase || owner) {
        return {
          surface: {
            owner: owner || undefined,
            supplyCurrentBase: supplyBase || undefined,
            supplyMaxBase: supplyMaxBase || undefined,
            decimals: faDetails.decimals ?? undefined,
            hookModules: normalizeHookModules(hookModules),
            capabilities: Object.keys(capabilities).length > 0 ? capabilities : undefined,
          },
          hint: "getFaDetails + addressDetail",
        };
      }
      
      // If getFaDetails returned but no useful fields, return error
      return {
        surface: null,
        error: "unsupported",
        hint: "getFaDetails returned but no supply/owner",
      };
    }
    
    // getFaDetails failed, try addressDetail as fallback
    try {
      const addressDetail = await fetchAddressDetailSupra(faAddress, "mainnet", { timeoutMs });
      if (!addressDetail) {
        return { surface: null, error: "unsupported", hint: "addressDetail returned empty" };
      }
      if (addressDetail.isError) {
        return {
          surface: null,
          error: addressDetail.errorType || "SupraScan addressDetail error",
          hint: "addressDetail query",
        };
      }
      
      if (!addressDetail.addressDetailSupra) {
        return {
          surface: null,
          error: "unsupported",
          hint: "addressDetailSupra missing",
        };
      }
      
      const detail = addressDetail.addressDetailSupra;
      
      // Parse resources if available
      let owner: string | null = null;
      let supplyCurrentBase: string | null = null;
      let supplyMaxBase: string | null = null;
      let hookModules: HookModule[] = [];
      let capabilities: Record<string, boolean> = {};
      
      if (detail.resources) {
        try {
          const analysis = analyzeFaResources(detail.resources);
          owner = normalizeAddress(analysis.caps.owner || detail.ownerAddress);
          supplyCurrentBase = normalizeSupply(analysis.caps.supplyCurrent || detail.totalSupply, detail.decimals);
          supplyMaxBase = normalizeSupply(analysis.caps.supplyMax) || null;
          
          if (analysis.caps.hookModules) {
            for (const h of analysis.caps.hookModules) {
              hookModules.push({
                module_address: h.module_address,
                module_name: h.module_name,
                function_name: h.function_name,
              });
            }
          }
          
          capabilities = {
            hasMintRef: analysis.caps.hasMintRef,
            hasBurnRef: analysis.caps.hasBurnRef,
            hasTransferRef: analysis.caps.hasTransferRef,
            hasDepositHook: analysis.caps.hasDepositHook,
            hasWithdrawHook: analysis.caps.hasWithdrawHook,
            hasDerivedBalanceHook: analysis.caps.hasDerivedBalanceHook,
          };
        } catch {
          // Fallback to direct fields
          owner = normalizeAddress(detail.ownerAddress);
          supplyCurrentBase = normalizeSupply(detail.totalSupply, detail.decimals);
        }
      } else {
        // Use direct fields if resources not available
        owner = normalizeAddress(detail.ownerAddress);
        supplyCurrentBase = normalizeSupply(detail.totalSupply, detail.decimals);
      }
      
      if (!owner && !supplyCurrentBase) {
        return {
          surface: null,
          error: "unsupported",
          hint: "addressDetail returned but no owner/supply",
        };
      }
      
      return {
        surface: {
          owner: owner || undefined,
          supplyCurrentBase: supplyCurrentBase || undefined,
          supplyMaxBase: supplyMaxBase || undefined,
          decimals: detail.decimals ?? undefined,
          hookModules: normalizeHookModules(hookModules),
          capabilities: Object.keys(capabilities).length > 0 ? capabilities : undefined,
        },
        hint: "addressDetail",
      };
    } catch (addressError) {
      const errorMsg = addressError instanceof Error ? addressError.message : String(addressError);
      if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
        return {
          surface: null,
          error: "timeout",
          hint: "SupraScan GraphQL timeout",
        };
      }
      return {
        surface: null,
        error: errorMsg,
        hint: "addressDetail query failed",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "SupraScan GraphQL timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "SupraScan GraphQL fetch failed",
    };
  }
}

/**
 * Extract mini surface from SupraScan GraphQL (COIN)
 */
export async function providerSupraScanGraphQLCoin(
  coinType: string,
  timeoutMs: number = 8000
): Promise<{ surface: MiniSurface | null; error?: string; hint?: string }> {
  try {
    const parsed = parseCoinType(coinType);
    
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
    
    const data = await suprascanGraphql<{
      addressDetail: {
        isError: boolean;
        errorType: string | null;
        addressDetailSupra: {
          resources: string | null;
        } | null;
      };
    }>(
      ADDRESS_DETAIL_QUERY,
      {
        address: parsed.publisherAddress,
        blockchainEnvironment: "mainnet",
        isAddressName: false,
      },
      {
        env: "mainnet",
        timeoutMs,
      }
    );
    
    if (data.addressDetail?.isError) {
      return {
        surface: null,
        error: data.addressDetail.errorType || "SupraScan addressDetail error",
        hint: "addressDetail query",
      };
    }
    
    if (!data.addressDetail?.addressDetailSupra?.resources) {
      return {
        surface: null,
        error: "SupraScan COIN unsupported (no resources found)",
        hint: "addressDetail returned empty resources",
      };
    }
    
    try {
      const resourcesJson = data.addressDetail.addressDetailSupra.resources;
      const analysis = analyzeCoinResources(resourcesJson, coinType);
      
      const capabilities: Record<string, boolean> = {
        hasMintCap: analysis.caps.hasMintCap,
        hasBurnCap: analysis.caps.hasBurnCap,
        hasFreezeCap: analysis.caps.hasFreezeCap,
        hasTransferRestrictions: analysis.caps.hasTransferRestrictions,
      };
      
      const supplyBase = normalizeSupply(analysis.caps.supplyCurrentBase, analysis.caps.decimals);
      
      return {
        surface: {
          supplyCurrentBase: supplyBase || undefined,
          decimals: analysis.caps.decimals ?? undefined,
          capabilities,
        },
        hint: "addressDetail resources",
      };
    } catch (parseError) {
      return {
        surface: null,
        error: parseError instanceof Error ? parseError.message : "Resource parsing failed",
        hint: "addressDetail resources parse error",
      };
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("timeout") || errorMsg.includes("aborted")) {
      return {
        surface: null,
        error: "timeout",
        hint: "SupraScan GraphQL timeout",
      };
    }
    return {
      surface: null,
      error: errorMsg,
      hint: "SupraScan GraphQL fetch failed",
    };
  }
}

/**
 * Corroborate claims from multiple sources
 */
export function corroborateClaims(
  v3: MiniSurface | null,
  v1: MiniSurface | null,
  suprascan: MiniSurface | null,
  v3_2: MiniSurface | null,
  targetKind: "fa" | "coin"
): {
  claims: Claim[];
  discrepancies: Discrepancy[];
  overallTier: EvidenceTier;
  status?: "CONFLICT" | "OK";
} {
  const claims: Claim[] = [];
  const discrepancies: Discrepancy[] = [];
  let hasConflict = false;
  let sourcesSucceeded = 0;
  
  if (v3) sourcesSucceeded++;
  if (v1) sourcesSucceeded++;
  if (suprascan) sourcesSucceeded++;
  if (v3_2) sourcesSucceeded++;
  
  // OWNER claim (FA only)
  if (targetKind === "fa") {
    const ownerV3 = v3?.owner;
    const ownerV1 = v1?.owner;
    const ownerScan = suprascan?.owner;
    const ownerV3_2 = v3_2?.owner;
    
    const confirmations: ClaimConfirmation[] = [];
    if (ownerV3 !== undefined) {
      confirmations.push({ source: "rpc_v3", ok: true, value: ownerV3, rawHint: "ObjectCore" });
    }
    if (ownerV1 !== undefined) {
      confirmations.push({ source: "rpc_v1", ok: true, value: ownerV1, rawHint: "ObjectCore" });
    }
    if (ownerScan !== undefined) {
      confirmations.push({ source: "suprascan", ok: true, value: ownerScan, rawHint: "GraphQL" });
    }
    if (ownerV3_2 !== undefined) {
      confirmations.push({ source: "rpc_v3_2", ok: true, value: ownerV3_2, rawHint: "ObjectCore" });
    }
    
    let status: ClaimStatus = "UNAVAILABLE";
    let confidence: Confidence = "LOW";
    
    if (confirmations.length === 0) {
      status = "UNAVAILABLE";
    } else if (confirmations.length >= 2) {
      const values = confirmations.map(c => c.value).filter(v => v !== null);
      const uniqueValues = new Set(values);
      if (uniqueValues.size === 1) {
        status = "CONFIRMED";
        confidence = "HIGH";
      } else {
        status = "CONFLICT";
        confidence = "HIGH";
        hasConflict = true;
        discrepancies.push({
          claimType: "OWNER",
          sources: confirmations.map(c => c.source),
          values: Object.fromEntries(confirmations.map(c => [c.source, c.value])) as any,
          detail: `Owner mismatch: ${values.join(" vs ")}`,
        });
      }
    } else {
      status = "PARTIAL";
      confidence = "MEDIUM";
    }
    
    claims.push({
      claimType: "OWNER",
      value: ownerV3 || ownerV1 || ownerScan || ownerV3_2 || null,
      confirmations,
      status,
      confidence,
    });
  }
  
  // SUPPLY claim
  const supplyV3 = v3?.supplyCurrentBase;
  const supplyV1 = v1?.supplyCurrentBase;
  // Get supply from SupraScan (from suprascan MiniSurface - will be updated later if from getFaDetails)
  const supplyScan = suprascan?.supplyCurrentBase;
  const supplyV3_2 = v3_2?.supplyCurrentBase;
  
  const supplyConfirmations: ClaimConfirmation[] = [];
  if (supplyV3 !== undefined) {
    supplyConfirmations.push({ source: "rpc_v3", ok: true, value: supplyV3, rawHint: "ConcurrentSupply/CoinInfo" });
  }
  if (supplyV1 !== undefined) {
    supplyConfirmations.push({ source: "rpc_v1", ok: true, value: supplyV1, rawHint: "ConcurrentSupply/CoinInfo" });
  }
  if (supplyScan !== undefined) {
    // Default hint - will be updated later if we know it's from getFaDetails
    supplyConfirmations.push({ source: "suprascan", ok: true, value: supplyScan, rawHint: "GraphQL" });
  }
  if (supplyV3_2 !== undefined) {
    supplyConfirmations.push({ source: "rpc_v3_2", ok: true, value: supplyV3_2, rawHint: "ConcurrentSupply/CoinInfo" });
  }
  
  let supplyStatus: ClaimStatus = "UNAVAILABLE";
  let supplyConfidence: Confidence = "LOW";
  
  if (supplyConfirmations.length === 0) {
    supplyStatus = "UNAVAILABLE";
  } else if (supplyConfirmations.length >= 2) {
    const values = supplyConfirmations.map(c => c.value).filter(v => v !== null);
    const uniqueValues = new Set(values);
    if (uniqueValues.size === 1) {
      supplyStatus = "CONFIRMED";
      supplyConfidence = "HIGH";
    } else {
      supplyStatus = "CONFLICT";
      supplyConfidence = "HIGH";
      hasConflict = true;
      discrepancies.push({
        claimType: "SUPPLY",
        sources: supplyConfirmations.map(c => c.source),
        values: Object.fromEntries(supplyConfirmations.map(c => [c.source, c.value])) as any,
        detail: `Supply mismatch: ${values.join(" vs ")}`,
      });
    }
  } else {
    supplyStatus = "PARTIAL";
    supplyConfidence = "MEDIUM";
  }
  
  claims.push({
    claimType: "SUPPLY",
    value: supplyV3 || supplyV1 || supplyScan || supplyV3_2 || null,
    confirmations: supplyConfirmations,
    status: supplyStatus,
    confidence: supplyConfidence,
  });
  
  // CREATOR/ISSUER claim will be added later after SupraScan provider response is available
  
  // HOOKS claim (FA only)
  if (targetKind === "fa") {
    const hooksV3 = normalizeHookModules(v3?.hookModules);
    const hooksV1 = normalizeHookModules(v1?.hookModules);
    const hooksScan = normalizeHookModules(suprascan?.hookModules);
    const hooksV3_2 = normalizeHookModules(v3_2?.hookModules);
    
    const hooksConfirmations: ClaimConfirmation[] = [];
    if (hooksV3.length > 0 || v3?.hookModules !== undefined) {
      hooksConfirmations.push({
        source: "rpc_v3",
        ok: true,
        value: hooksV3,
        rawHint: "DispatchFunctionStore",
      });
    }
    if (hooksV1.length > 0 || v1?.hookModules !== undefined) {
      hooksConfirmations.push({
        source: "rpc_v1",
        ok: true,
        value: hooksV1,
        rawHint: "DispatchFunctionStore",
      });
    }
    if (hooksScan.length > 0 || suprascan?.hookModules !== undefined) {
      hooksConfirmations.push({
        source: "suprascan",
        ok: true,
        value: hooksScan,
        rawHint: "GraphQL",
      });
    }
    if (hooksV3_2.length > 0 || v3_2?.hookModules !== undefined) {
      hooksConfirmations.push({
        source: "rpc_v3_2",
        ok: true,
        value: hooksV3_2,
        rawHint: "DispatchFunctionStore",
      });
    }
    
    let hooksStatus: ClaimStatus = "UNAVAILABLE";
    let hooksConfidence: Confidence = "LOW";
    
    if (hooksConfirmations.length === 0) {
      hooksStatus = "UNAVAILABLE";
    } else if (hooksConfirmations.length >= 2) {
      // Generic rule: if >=2 confirmations with identical normalized values, CONFIRMED HIGH
      const values = hooksConfirmations.map(c => stableStringifyCanonical(c.value || [])).filter(v => v !== "[]" && v !== "null");
      const uniqueValues = new Set(values);
      if (uniqueValues.size === 1) {
        hooksStatus = "CONFIRMED";
        hooksConfidence = "HIGH";
      } else {
        hooksStatus = "PARTIAL"; // Hooks may differ slightly, not critical conflict
        hooksConfidence = "MEDIUM";
      }
    } else {
      hooksStatus = "PARTIAL";
      hooksConfidence = "MEDIUM";
    }
    
    claims.push({
      claimType: "HOOKS",
      value: hooksV3.length > 0 ? hooksV3 : hooksV1.length > 0 ? hooksV1 : hooksV3_2.length > 0 ? hooksV3_2 : hooksScan,
      confirmations: hooksConfirmations,
      status: hooksStatus,
      confidence: hooksConfidence,
    });

    // INDEXER_PARITY claim (FA only, additive)
    // Compares RPC (v3) vs SupraScan for hooks parity; graceful if unsupported
    if (suprascan?.hookModules !== undefined || v3?.hookModules !== undefined) {
      const parityConfirmations: ClaimConfirmation[] = [];
      if (v3?.hookModules !== undefined) {
        parityConfirmations.push({
          source: "rpc_v3",
          ok: true,
          value: normalizeHookModules(v3.hookModules),
          rawHint: "DispatchFunctionStore",
        });
      }
      if (suprascan?.hookModules !== undefined) {
        parityConfirmations.push({
          source: "suprascan",
          ok: true,
          value: normalizeHookModules(suprascan.hookModules),
          rawHint: "GraphQL",
        });
      }

      let parityStatus: ClaimStatus = "UNAVAILABLE";
      let parityConfidence: Confidence = "LOW";

      if (parityConfirmations.length === 0) {
        parityStatus = "UNAVAILABLE";
      } else if (parityConfirmations.length >= 2) {
        const values = parityConfirmations.map(c => stableStringifyCanonical(c.value || [])).filter(v => v !== "[]" && v !== "null");
        const uniqueValues = new Set(values);
        if (uniqueValues.size === 1) {
          parityStatus = "CONFIRMED";
          parityConfidence = "HIGH";
        } else {
          // Hooks differing between indexer and RPC is a signal but not necessarily a hard conflict
          parityStatus = "CONFLICT";
          parityConfidence = "HIGH";
          hasConflict = true;
          discrepancies.push({
            claimType: "INDEXER_PARITY" as ClaimType,
            sources: parityConfirmations.map(c => c.source),
            values: Object.fromEntries(parityConfirmations.map(c => [c.source, c.value])) as any,
            detail: "FA hooks differ between RPC and indexer",
          });
        }
      } else {
        parityStatus = "PARTIAL";
        parityConfidence = "MEDIUM";
      }

      claims.push({
        claimType: "INDEXER_PARITY" as ClaimType,
        value: {
          // Will be updated later if SupraScan provider response indicates partial evidence
          hooksParity: parityConfirmations.length >= 2
            ? (parityStatus === "CONFIRMED" ? "match" : "mismatch")
            : "insufficient",
        },
        confirmations: parityConfirmations,
        status: parityStatus,
        confidence: parityConfidence,
      });
    }
  }
  
  // CAPABILITIES claim
  const capsV3 = v3?.capabilities;
  const capsV1 = v1?.capabilities;
  const capsScan = suprascan?.capabilities;
  const capsV3_2 = v3_2?.capabilities;
  
  // Normalize capabilities: sort keys for stable comparison
  const normalizeCaps = (caps: Record<string, boolean> | undefined): string => {
    if (!caps) return "{}";
    const sorted = Object.keys(caps).sort();
    const normalized: Record<string, boolean> = {};
    for (const key of sorted) {
      normalized[key] = caps[key];
    }
    return JSON.stringify(normalized);
  };
  
  const capsConfirmations: ClaimConfirmation[] = [];
  if (capsV3) {
    capsConfirmations.push({ source: "rpc_v3", ok: true, value: capsV3, rawHint: "ManagedFungibleAsset/CoinInfo" });
  }
  if (capsV1) {
    capsConfirmations.push({ source: "rpc_v1", ok: true, value: capsV1, rawHint: "ManagedFungibleAsset/CoinInfo" });
  }
  if (capsScan) {
    capsConfirmations.push({ source: "suprascan", ok: true, value: capsScan, rawHint: "GraphQL" });
  }
  if (capsV3_2) {
    capsConfirmations.push({ source: "rpc_v3_2", ok: true, value: capsV3_2, rawHint: "ManagedFungibleAsset/CoinInfo" });
  }
  
  let capsStatus: ClaimStatus = "UNAVAILABLE";
  let capsConfidence: Confidence = "LOW";
  
  if (capsConfirmations.length === 0) {
    capsStatus = "UNAVAILABLE";
  } else if (capsConfirmations.length >= 2) {
    // Generic rule: if >=2 confirmations with identical normalized values, CONFIRMED HIGH
    const values = capsConfirmations.map(c => normalizeCaps(c.value)).filter(v => v !== "{}");
    const uniqueValues = new Set(values);
    if (uniqueValues.size === 1) {
      capsStatus = "CONFIRMED";
      capsConfidence = "HIGH";
    } else {
      capsStatus = "PARTIAL";
      capsConfidence = "MEDIUM";
    }
  } else {
    capsStatus = "PARTIAL";
    capsConfidence = "MEDIUM";
  }
  
  claims.push({
    claimType: "CAPS",
    value: capsV3 || capsV1 || capsScan || capsV3_2 || {},
    confirmations: capsConfirmations,
    status: capsStatus,
    confidence: capsConfidence,
  });
  
  // HOOK_MODULE_HASHES claim (FA only)
  if (targetKind === "fa") {
    const hashesV3 = v3?.hookModuleHashes || [];
    const hashesV1 = v1?.hookModuleHashes || [];
    const hashesV3_2 = v3_2?.hookModuleHashes || [];
    // SupraScan doesn't support module hashes for FA
    
    const hashConfirmations: ClaimConfirmation[] = [];
    if (hashesV3.length > 0 || v3?.hookModuleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v3",
        ok: true,
        value: stampFetchedFrom(hashesV3, "rpc_v3"),
        rawHint: "module bytecode/ABI",
      });
    }
    if (hashesV1.length > 0 || v1?.hookModuleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v1",
        ok: true,
        value: stampFetchedFrom(hashesV1, "rpc_v1"),
        rawHint: "module bytecode/ABI",
      });
    }
    if (hashesV3_2.length > 0 || v3_2?.hookModuleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v3_2",
        ok: true,
        value: stampFetchedFrom(hashesV3_2, "rpc_v3_2"),
        rawHint: "module bytecode/ABI",
      });
    }
    
    let hashStatus: ClaimStatus = "UNAVAILABLE";
    let hashConfidence: Confidence = "LOW";
    
    if (hashConfirmations.length === 0) {
      // Omit claim if no sources returned hashes
    } else if (hashConfirmations.length >= 2) {
      // Compare hashes using canonicalized values (ignores fetchedFrom differences)
      const values = hashConfirmations
        .map(c => stableStringifyCanonical(c.value || []))
        .filter(v => v !== "[]" && v !== "null");
      const uniqueValues = new Set(values);
      
      if (uniqueValues.size === 1) {
        hashStatus = "CONFIRMED";
        hashConfidence = "HIGH";
      } else {
        hashStatus = "CONFLICT";
        hashConfidence = "HIGH";
        hasConflict = true;
        discrepancies.push({
          claimType: "HOOK_MODULE_HASHES",
          sources: hashConfirmations.map(c => c.source),
          values: Object.fromEntries(hashConfirmations.map(c => [c.source, c.value])) as any,
          detail: `Hook module hash mismatch across RPCs`,
        });
      }
    } else {
      hashStatus = "PARTIAL";
      hashConfidence = "MEDIUM";
    }
    
    // Only add claim if we have at least one source
    if (hashConfirmations.length > 0) {
      claims.push({
        claimType: "HOOK_MODULE_HASHES",
        value: hashesV3.length > 0 ? hashesV3 : hashesV1.length > 0 ? hashesV1 : hashesV3_2,
        confirmations: hashConfirmations,
        status: hashStatus,
        confidence: hashConfidence,
      });
    }
  }
  
  // MODULE_HASHES claim (COIN only)
  if (targetKind === "coin") {
    const hashesV3 = v3?.moduleHashes || [];
    const hashesV1 = v1?.moduleHashes || [];
    const hashesV3_2 = v3_2?.moduleHashes || [];
    // SupraScan doesn't support module hashes for COIN
    
    const hashConfirmations: ClaimConfirmation[] = [];
    if (hashesV3.length > 0 || v3?.moduleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v3",
        ok: true,
        value: stampFetchedFrom(hashesV3, "rpc_v3"),
        rawHint: "module bytecode/ABI",
      });
    }
    if (hashesV1.length > 0 || v1?.moduleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v1",
        ok: true,
        value: stampFetchedFrom(hashesV1, "rpc_v1"),
        rawHint: "module bytecode/ABI",
      });
    }
    if (hashesV3_2.length > 0 || v3_2?.moduleHashes !== undefined) {
      hashConfirmations.push({
        source: "rpc_v3_2",
        ok: true,
        value: stampFetchedFrom(hashesV3_2, "rpc_v3_2"),
        rawHint: "module bytecode/ABI",
      });
    }
    
    let hashStatus: ClaimStatus = "UNAVAILABLE";
    let hashConfidence: Confidence = "LOW";
    
    if (hashConfirmations.length === 0) {
      // Omit claim if no sources returned hashes
    } else if (hashConfirmations.length >= 2) {
      // Compare hashes using canonicalized values (ignores fetchedFrom differences)
      const values = hashConfirmations
        .map(c => stableStringifyCanonical(c.value || []))
        .filter(v => v !== "[]" && v !== "null");
      const uniqueValues = new Set(values);
      
      if (uniqueValues.size === 1) {
        hashStatus = "CONFIRMED";
        hashConfidence = "HIGH";
      } else {
        hashStatus = "CONFLICT";
        hashConfidence = "HIGH";
        hasConflict = true;
        discrepancies.push({
          claimType: "MODULE_HASHES",
          sources: hashConfirmations.map(c => c.source),
          values: Object.fromEntries(hashConfirmations.map(c => [c.source, c.value])) as any,
          detail: `Module hash mismatch across RPCs`,
        });
      }
    } else {
      hashStatus = "PARTIAL";
      hashConfidence = "MEDIUM";
    }
    
    // Only add claim if we have at least one source
    if (hashConfirmations.length > 0) {
      claims.push({
        claimType: "MODULE_HASHES",
        value: hashesV3.length > 0 ? hashesV3 : hashesV1.length > 0 ? hashesV1 : hashesV3_2,
        confirmations: hashConfirmations,
        status: hashStatus,
        confidence: hashConfidence,
      });
    }
  }
  
  // Determine overall evidence tier
  // Check if we have claims that are CONFIRMED via multi-RPC (≥2 RPC sources agree)
  const rpcConfirmedClaims = claims.filter(claim => {
    if (claim.status !== "CONFIRMED" || claim.confidence !== "HIGH") {
      return false;
    }
    // Check if this claim has confirmations from at least 2 RPC sources
    const rpcSources = claim.confirmations.filter(c => 
      c.source === "rpc_v3" || c.source === "rpc_v1" || c.source === "rpc_v3_2"
    );
    return rpcSources.length >= 2;
  });
  
  // Check if we have any claims that could be confirmed by RPCs (have RPC sources)
  const claimsWithRpcSources = claims.filter(claim => {
    const rpcSources = claim.confirmations.filter(c => 
      c.source === "rpc_v3" || c.source === "rpc_v1" || c.source === "rpc_v3_2"
    );
    return rpcSources.length > 0;
  });
  
  // If all RPC-confirmed claims are confirmed, set multi_rpc_confirmed
  const allRpcClaimsConfirmed = claimsWithRpcSources.length > 0 && 
    claimsWithRpcSources.every(claim => claim.status === "CONFIRMED" && claim.confidence === "HIGH");
  
  let overallTier: EvidenceTier = "view_only";
  if (sourcesSucceeded >= 2) {
    // Multi-RPC confirmed: rpc_v3 + rpc_v1 OR rpc_v3 + rpc_v3_2
    if ((v3 && v1) || (v3 && v3_2)) {
      overallTier = "multi_rpc_confirmed";
    }
    // Multi-RPC plus indexer: at least one RPC source + indexer (suprascan)
    // Only upgrade to this if we already have multi_rpc_confirmed
    if (suprascan && (v3 || v1 || v3_2) && overallTier === "multi_rpc_confirmed") {
      overallTier = "multi_rpc_plus_indexer";
    }
    // Multi-source confirmed: rpc_v3 + rpc_v3_2 + suprascan (all successful)
    // Note: This will be upgraded later if conditions are met
  }
  
  // If we have multi-RPC confirmed claims but tier is still view_only, upgrade it
  // This handles cases where sources succeeded but the tier logic above didn't catch it
  // OR if all RPC-confirmed claims are confirmed
  if ((rpcConfirmedClaims.length > 0 || allRpcClaimsConfirmed) && overallTier === "view_only") {
    overallTier = "multi_rpc_confirmed";
  }
  
  return {
    claims,
    discrepancies,
    overallTier,
    status: hasConflict ? "CONFLICT" : "OK",
  };
}

/**
 * Main verification function
 */
export async function verifySurface(
  target: { kind: "fa" | "coin"; id: string },
  opts: {
    rpcUrl: string;
    rpc2Url?: string;
    mode: "fast" | "strict" | "agent";
    withSupraScan: boolean;
    timeoutMs: number;
    retries: number;
    /** Maximum number of transactions to sample for behavior evidence (default: 20) */
    txLimit?: number;
    /** Skip transaction behavior sampling entirely */
    skipTx?: boolean;
    /** Additional addresses to probe for transactions (FA only) */
    behaviorProbeAddresses?: string[];
    /** Prefer v2 endpoint for account transaction sampling */
    preferV2?: boolean;
    /** Dump raw SupraScan responses to file for debugging (default: true when withSupraScan) */
    suprascanDump?: boolean;
  }
): Promise<VerificationReport> {
  const sourcesAttempted: EvidenceSource[] = ["rpc_v3", "rpc_v1"];
  if (opts.rpc2Url) {
    sourcesAttempted.push("rpc_v3_2");
  }
  if (opts.withSupraScan) {
    sourcesAttempted.push("suprascan");
  }
  
  const sourcesSucceeded: EvidenceSource[] = [];
  const providerResults: ProviderResult[] = [];
  let hasInvalidArgs = false;
  
  // Validate RPC URLs before any network calls
  const rpcUrlValidation = validateRpcUrl(opts.rpcUrl, "rpc");
  if (!rpcUrlValidation.valid) {
    providerResults.push({
      source: "rpc_v3",
      ok: false,
      error: rpcUrlValidation.error || "invalid rpc url",
      hint: "rpc contains placeholder or malformed URL",
    });
    // Also mark rpc_v1 as invalid since it uses the same URL
    providerResults.push({
      source: "rpc_v1",
      ok: false,
      error: rpcUrlValidation.error || "invalid rpc url",
      hint: "rpc contains placeholder or malformed URL",
    });
    hasInvalidArgs = true;
  }
  
  if (opts.rpc2Url) {
    const rpc2UrlValidation = validateRpcUrl(opts.rpc2Url, "rpc2");
    if (!rpc2UrlValidation.valid) {
      providerResults.push({
        source: "rpc_v3_2",
        ok: false,
        error: rpc2UrlValidation.error || "invalid rpc url",
        hint: "rpc2 contains placeholder or malformed URL",
      });
      hasInvalidArgs = true;
    }
  }
  
  // If invalid args, return early with INVALID_ARGS status
  if (hasInvalidArgs) {
    // Ensure all attempted sources have provider results
    const existingSources = new Set(providerResults.map(p => p.source));
    for (const source of sourcesAttempted) {
      if (!existingSources.has(source)) {
        providerResults.push({ source, ok: false, error: "skipped", hint: "invalid rpc url" });
      }
    }
    
    // Sort provider results for deterministic output
    providerResults.sort((a, b) => {
      const order: Record<string, number> = { rpc_v3: 1, rpc_v1: 2, rpc_v3_2: 3, suprascan: 4 };
      return (order[a.source] || 999) - (order[b.source] || 999);
    });
    
    return {
      target,
      timestamp_iso: new Date().toISOString(),
      rpc_url: opts.rpcUrl,
      mode: opts.mode === "agent" ? "strict" : opts.mode, // Map agent to strict internally
      sources_attempted: sourcesAttempted,
      sources_succeeded: [],
      provider_results: providerResults,
      claims: [],
      overallEvidenceTier: "view_only",
      discrepancies: [],
      status: "INVALID_ARGS",
      verdict: "FAIL_InvalidArgs",
    };
  }
  
  let v3: MiniSurface | null = null;
  let v1: MiniSurface | null = null;
  let suprascan: MiniSurface | null = null;
  let v3_2: MiniSurface | null = null;
  
  const rpcOptions: RpcClientOptions = {
    rpcUrl: opts.rpcUrl,
    timeout: opts.timeoutMs,
    retries: opts.retries,
  };
  
  // Fetch v3
  let v3Result: { surface: MiniSurface | null; error?: string; hint?: string };
  try {
    if (target.kind === "fa") {
      v3Result = await providerRpcV3ResourcesFA(target.id, rpcOptions);
    } else {
      v3Result = await providerRpcV3ResourcesCoin(target.id, rpcOptions);
    }
    v3 = v3Result.surface;
    if (v3) {
      sourcesSucceeded.push("rpc_v3");
      providerResults.push({ source: "rpc_v3", ok: true, hint: v3Result.hint });
    } else {
      providerResults.push({ source: "rpc_v3", ok: false, error: v3Result.error, hint: v3Result.hint });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    providerResults.push({ source: "rpc_v3", ok: false, error: errorMsg, hint: "exception" });
  }
  
  // Fetch v1
  let v1Result: { surface: MiniSurface | null; error?: string; hint?: string };
  try {
    if (target.kind === "fa") {
      v1Result = await providerRpcV1ResourcesFA(target.id, opts.rpcUrl);
    } else {
      v1Result = await providerRpcV1ResourcesCoin(target.id, opts.rpcUrl);
    }
    v1 = v1Result.surface;
    if (v1) {
      sourcesSucceeded.push("rpc_v1");
      providerResults.push({ source: "rpc_v1", ok: true, hint: v1Result.hint });
    } else {
      providerResults.push({ source: "rpc_v1", ok: false, error: v1Result.error, hint: v1Result.hint });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    providerResults.push({ source: "rpc_v1", ok: false, error: errorMsg, hint: "exception" });
  }
  
  // Fetch v3_2 (rpc2) if provided
  if (opts.rpc2Url) {
    const rpc2Options: RpcClientOptions = {
      rpcUrl: opts.rpc2Url,
      timeout: opts.timeoutMs,
      retries: opts.retries,
    };
    let v3_2Result: { surface: MiniSurface | null; error?: string; hint?: string };
    try {
      if (target.kind === "fa") {
        v3_2Result = await providerRpcV3ResourcesFA(target.id, rpc2Options);
      } else {
        v3_2Result = await providerRpcV3ResourcesCoin(target.id, rpc2Options);
      }
      v3_2 = v3_2Result.surface;
      if (v3_2) {
        sourcesSucceeded.push("rpc_v3_2");
        providerResults.push({ source: "rpc_v3_2", ok: true, hint: "RPC v3 resources (rpc2)" });
      } else {
        providerResults.push({ source: "rpc_v3_2", ok: false, error: v3_2Result.error, hint: v3_2Result.hint || "RPC v3 resources (rpc2)" });
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      providerResults.push({ source: "rpc_v3_2", ok: false, error: errorMsg, hint: "exception" });
    }
  }
  
  // Fetch SupraScan (optional)
  // For FA: use new provider for detailed parity; for Coin: use existing provider
  let suprascanProviderResponse: { ok: boolean; urlUsed: string; evidence?: any; error?: string } | undefined;
  if (opts.withSupraScan) {
    if (target.kind === "fa") {
      // Use new SupraScan provider for FA with retries
      try {
        suprascanProviderResponse = await fetchSupraScanFAEvidence(
          target.id, 
          opts.timeoutMs, 
          opts.retries,
          opts.suprascanDump !== false // Default to true when withSupraScan is true
        );
        if (suprascanProviderResponse.ok && suprascanProviderResponse.evidence) {
          // Build MiniSurface from evidence for compatibility with existing code
          const evidence = suprascanProviderResponse.evidence;
          suprascan = {
            owner: evidence.owner || undefined,
            supplyCurrentBase: evidence.supply || undefined,
            hookModules: evidence.hooks || undefined,
            hookModuleHashes: evidence.hookModuleHashes?.map((h: { moduleId: string; codeHash: string | null; hashBasis: "bytecode" | "abi" | "none" }) => ({
              moduleId: h.moduleId,
              codeHash: h.codeHash,
              hashBasis: h.hashBasis,
              fetchedFrom: "suprascan",
            })) || undefined,
          };
          sourcesSucceeded.push("suprascan");
          providerResults.push({ source: "suprascan", ok: true, hint: "SupraScan FA evidence" });
        } else {
          providerResults.push({ source: "suprascan", ok: false, error: suprascanProviderResponse.error, hint: "SupraScan FA provider" });
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        providerResults.push({ source: "suprascan", ok: false, error: errorMsg, hint: "exception" });
      }
    } else {
      // For Coin, use existing provider
      let scanResult: { surface: MiniSurface | null; error?: string; hint?: string };
      try {
        scanResult = await providerSupraScanGraphQLCoin(target.id, opts.timeoutMs);
        suprascan = scanResult.surface;
        if (suprascan) {
          sourcesSucceeded.push("suprascan");
          providerResults.push({ source: "suprascan", ok: true, hint: scanResult.hint });
        } else {
          providerResults.push({ source: "suprascan", ok: false, error: scanResult.error, hint: scanResult.hint });
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        providerResults.push({ source: "suprascan", ok: false, error: errorMsg, hint: "exception" });
      }
    }
  }
  
  // Ensure all attempted sources have provider results (even if skipped/failed)
  const existingSources = new Set(providerResults.map(p => p.source));
  for (const source of sourcesAttempted) {
    if (!existingSources.has(source)) {
      providerResults.push({ source, ok: false, error: "skipped", hint: "not attempted" });
    }
  }
  
  // Corroborate claims
  const { claims, discrepancies, overallTier, status } = corroborateClaims(
    v3,
    v1,
    suprascan,
    v3_2,
    target.kind
  );

  // FA SupraScan support + parity summary (additive fields, no breaking changes)
  // Always include suprascan_fa and indexer_parity for FA targets to explicitly explain indexer availability
  let suprascanFa: VerificationReport["suprascan_fa"] | undefined;
  let parity: VerificationReport["parity"] | undefined;
  let indexerParity: IndexerParityRecord | undefined;
  
  if (target.kind === "fa") {
    if (!opts.withSupraScan) {
      // SupraScan was not requested - explicitly document this
      suprascanFa = { 
        status: "not_requested", 
        ok: false,
        reason: "SupraScan indexer not requested (use --with-suprascan true)" 
      };
      indexerParity = {
        status: "not_requested",
        reason: "SupraScan indexer was not requested. Run with --with-suprascan true to enable indexer parity checks.",
        evidenceTierImpact: "multi_rpc",
        details: {
          ownerParity: "n/a",
          supplyParity: "n/a",
          hooksParity: "n/a",
          hookHashParity: "n/a",
        },
      };
    } else {
      const suprascanResult = providerResults.find((p) => p.source === "suprascan");
      if (suprascanProviderResponse?.ok && suprascanProviderResponse.evidence) {
        // SupraScan returned evidence successfully (may be partial)
        const providerStatus = (suprascanProviderResponse as SupraScanProviderResponse).status || "supported";
        // Map partial_ok to partial for status (partial_ok is only in provider response)
        const faStatus: IndexerParityStatus | "partial_ok" = providerStatus === "partial_ok" ? "partial_ok" : providerStatus === "partial" ? "partial" : "supported";
        // Build detailed reason message explaining which fields were returned/missing
        const evidence = suprascanProviderResponse.evidence;
        const hasOwner = evidence.owner !== undefined && evidence.owner !== null;
        const hasSupply = evidence.supply !== undefined && evidence.supply !== null;
        const hasHooks = evidence.hooks !== undefined && evidence.hooks !== null && (evidence.hooks as any[]).length > 0;
        const hasHookHashes = evidence.hookModuleHashes !== undefined && evidence.hookModuleHashes !== null && (evidence.hookModuleHashes as any[]).length > 0;
        
        const fieldsReturned: string[] = [];
        const fieldsMissing: string[] = [];
        if (hasOwner) fieldsReturned.push("owner");
        else fieldsMissing.push("owner");
        if (hasSupply) fieldsReturned.push("supply");
        else fieldsMissing.push("supply");
        if (hasHooks) fieldsReturned.push("hooks");
        else fieldsMissing.push("hooks");
        if (hasHookHashes) fieldsReturned.push("hook hashes");
        else fieldsMissing.push("hook hashes");
        
        let suprascanReason: string;
        if (providerStatus === "partial_ok" || providerStatus === "partial") {
          if (fieldsReturned.length > 0) {
            suprascanReason = `Partial evidence: returned ${fieldsReturned.join(", ")}${fieldsMissing.length > 0 ? `; missing ${fieldsMissing.join(", ")}` : ""}`;
          } else {
            suprascanReason = "Partial evidence (no fields returned)";
          }
        } else {
          if (fieldsReturned.length > 0) {
            suprascanReason = `Complete evidence: returned ${fieldsReturned.join(", ")}`;
          } else {
            suprascanReason = "SupraScan indexer returned FA evidence for corroboration.";
          }
        }
        
        suprascanFa = {
          status: faStatus as IndexerParityStatus | "partial_ok",
          ok: true,
          urlUsed: suprascanProviderResponse.urlUsed,
          evidence: suprascanProviderResponse.evidence,
          reason: suprascanReason || "",
        };
        
        // Update supply confirmation rawHint if it's from getFaDetails (after claims are built)
        if (providerStatus === "partial_ok" && suprascanProviderResponse.evidence.supply) {
          const supplyClaim = claims.find(c => c.claimType === "SUPPLY");
          if (supplyClaim) {
            const scanConfirmation = supplyClaim.confirmations.find(c => c.source === "suprascan");
            if (scanConfirmation) {
              scanConfirmation.rawHint = "getFaDetails.totalSupply";
            }
          }
        }
        
        // Add CREATOR/ISSUER claim (informational, from SupraScan getFaDetails.creatorAddress)
        if (suprascanProviderResponse.evidence.creatorAddress) {
          const creatorAddress = normalizeAddress(suprascanProviderResponse.evidence.creatorAddress);
          if (creatorAddress) {
            claims.push({
              claimType: "CREATOR",
              value: creatorAddress,
              confirmations: [{
                source: "suprascan",
                ok: true,
                value: creatorAddress,
                rawHint: "getFaDetails.creatorAddress",
              }],
              status: "PARTIAL",
              confidence: "MEDIUM",
            });
          }
        }
        
        // Update INDEXER_PARITY claim value to reflect SupraScan partial evidence status
        const indexerParityClaim = claims.find(c => c.claimType === "INDEXER_PARITY");
        if (indexerParityClaim) {
          const hasHooks = suprascanProviderResponse.evidence.hooks !== undefined && suprascanProviderResponse.evidence.hooks !== null && (suprascanProviderResponse.evidence.hooks as any[]).length > 0;
          const hasOwner = suprascanProviderResponse.evidence.owner !== undefined && suprascanProviderResponse.evidence.owner !== null;
          const hasSupply = suprascanProviderResponse.evidence.supply !== undefined && suprascanProviderResponse.evidence.supply !== null;
          
          // Determine hooksParity: "unsupported" if SupraScan doesn't expose hooks (partial evidence or not available)
          let hooksParityValue: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported";
          if (!hasHooks && (providerStatus === "partial_ok" || providerStatus === "partial")) {
            // SupraScan returns partial evidence and doesn't expose hooks
            hooksParityValue = "unsupported";
          } else {
            // Use existing value from claim (may be "match", "mismatch", or "insufficient")
            hooksParityValue = indexerParityClaim.value?.hooksParity || "insufficient";
          }
          
          // Determine ownerParity: "unsupported" if SupraScan doesn't expose owner
          let ownerParityValue: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" = "unknown";
          if (!hasOwner && (providerStatus === "partial_ok" || providerStatus === "partial")) {
            // SupraScan returns partial evidence and doesn't expose owner
            ownerParityValue = "unsupported";
          } else if (hasOwner && v3?.owner) {
            const v3Owner = normalizeAddress(v3.owner);
            const scanOwner = normalizeAddress(suprascanProviderResponse.evidence.owner);
            if (v3Owner && scanOwner) {
              ownerParityValue = v3Owner === scanOwner ? "match" : "mismatch";
            }
          }
          
          // Determine supplyParity: "match" or "mismatch" if both available
          let supplyParityValue: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" = "unknown";
          if (hasSupply && v3?.supplyCurrentBase) {
            supplyParityValue = v3.supplyCurrentBase === suprascanProviderResponse.evidence.supply ? "match" : "mismatch";
          } else if (!hasSupply) {
            supplyParityValue = "insufficient";
          }
          
          // Update INDEXER_PARITY claim value with all parities
          indexerParityClaim.value = {
            ownerParity: ownerParityValue,
            supplyParity: supplyParityValue,
            hooksParity: hooksParityValue,
          };
        }
        
        // Compute detailed parity: RPC v3 vs SupraScan
        const mismatches: Array<{ field: "owner" | "supply" | "hooks" | "hookHash"; rpcValue: any; suprascanValue: any; reason: string }> = [];
        
        // Owner parity
        let ownerParity: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" = "unknown";
        if (v3?.owner && suprascanProviderResponse.evidence.owner) {
          const v3Owner = normalizeAddress(v3.owner);
          const scanOwner = normalizeAddress(suprascanProviderResponse.evidence.owner);
          if (v3Owner && scanOwner) {
            ownerParity = v3Owner === scanOwner ? "match" : "mismatch";
            if (ownerParity === "mismatch") {
              mismatches.push({
                field: "owner",
                rpcValue: v3Owner,
                suprascanValue: scanOwner,
                reason: `Owner mismatch: RPC=${v3Owner}, SupraScan=${scanOwner}`,
              });
            }
          }
        } else if (!suprascanProviderResponse.evidence.owner) {
          // SupraScan doesn't expose owner (only creatorAddress from getFaDetails)
          ownerParity = "unsupported";
        } else if (!v3?.owner && !suprascanProviderResponse.evidence.owner) {
          ownerParity = "insufficient";
        }

        // Supply parity
        let supplyParity: "match" | "mismatch" | "unknown" | "insufficient" = "unknown";
        if (v3?.supplyCurrentBase && suprascanProviderResponse.evidence.supply) {
          supplyParity = v3.supplyCurrentBase === suprascanProviderResponse.evidence.supply ? "match" : "mismatch";
          if (supplyParity === "mismatch") {
            mismatches.push({
              field: "supply",
              rpcValue: v3.supplyCurrentBase,
              suprascanValue: suprascanProviderResponse.evidence.supply,
              reason: `Supply mismatch: RPC=${v3.supplyCurrentBase}, SupraScan=${suprascanProviderResponse.evidence.supply}`,
            });
          }
        } else if (!v3?.supplyCurrentBase && !suprascanProviderResponse.evidence.supply) {
          supplyParity = "insufficient";
        }

        // Hooks parity (set equality)
        let hooksParity: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" = "unknown";
        if (v3?.hookModules && suprascanProviderResponse.evidence.hooks) {
          const v3Hooks = normalizeHookModules(v3.hookModules);
          const scanHooks = normalizeHookModules(suprascanProviderResponse.evidence.hooks);
          hooksParity = stableStringifyCanonical(v3Hooks) === stableStringifyCanonical(scanHooks) ? "match" : "mismatch";
          if (hooksParity === "mismatch") {
            mismatches.push({
              field: "hooks",
              rpcValue: v3Hooks,
              suprascanValue: scanHooks,
              reason: `Hooks mismatch: RPC has ${v3Hooks.length} hooks, SupraScan has ${scanHooks.length} hooks`,
            });
          }
        } else if (!suprascanProviderResponse.evidence.hooks) {
          // SupraScan doesn't expose hooks (getFaDetails doesn't have dispatch hooks)
          hooksParity = "unsupported";
        } else if (!v3?.hookModules && !suprascanProviderResponse.evidence.hooks) {
          hooksParity = "insufficient";
        }

        // Hook hash parity
        let hookHashParity: "match" | "mismatch" | "unknown" | "insufficient" = "unknown";
        if (v3?.hookModuleHashes && suprascanProviderResponse.evidence.hookModuleHashes) {
          const v3Hashes = (v3.hookModuleHashes || []).sort((a: ModuleHashPin, b: ModuleHashPin) => a.moduleId.localeCompare(b.moduleId));
          const scanHashes = (suprascanProviderResponse.evidence.hookModuleHashes || []).sort((a: { moduleId: string }, b: { moduleId: string }) => a.moduleId.localeCompare(b.moduleId));
          
          if (v3Hashes.length > 0 && scanHashes.length > 0) {
            // Compare hashes by moduleId
            const v3HashMap = new Map<string, string | null>(v3Hashes.map((h: { moduleId: string; codeHash: string | null }) => [h.moduleId, h.codeHash] as [string, string | null]));
            const scanHashMap = new Map<string, string | null>(scanHashes.map((h: { moduleId: string; codeHash: string | null }) => [h.moduleId, h.codeHash] as [string, string | null]));
            
            let allMatch = true;
            const v3ModuleIds: string[] = Array.from(v3HashMap.keys());
            const scanModuleIds: string[] = Array.from(scanHashMap.keys());
            const allModuleIds = new Set<string>([...v3ModuleIds, ...scanModuleIds]);
            
            for (const moduleId of allModuleIds) {
              const v3Hash = v3HashMap.get(moduleId) ?? null;
              const scanHash = scanHashMap.get(moduleId) ?? null;
              if (v3Hash !== scanHash) {
                allMatch = false;
                mismatches.push({
                  field: "hookHash",
                  rpcValue: { moduleId, codeHash: v3Hash },
                  suprascanValue: { moduleId, codeHash: scanHash },
                  reason: `Hook module hash mismatch for ${moduleId}: RPC=${v3Hash ?? "null"}, SupraScan=${scanHash ?? "null"}`,
                });
              }
            }
            
            hookHashParity = allMatch ? "match" : "mismatch";
          } else {
            hookHashParity = "insufficient";
          }
        } else if (!v3?.hookModuleHashes && !suprascanProviderResponse.evidence.hookModuleHashes) {
          hookHashParity = "insufficient";
        }

        // Build parity summary (for backward compatibility)
        // Map "unsupported" to "unknown" for backward compatibility
        parity = {
          owner: ownerParity === "match" ? "match" : ownerParity === "mismatch" ? "mismatch" : "unknown",
          supply: supplyParity === "match" ? "match" : supplyParity === "mismatch" ? "mismatch" : "unknown",
          hooks: hooksParity === "match" ? "match" : hooksParity === "mismatch" ? "mismatch" : "unknown",
        };
        
        // Determine which fields were actually compared (only match/mismatch, not unsupported/insufficient/unknown)
        const fieldsCompared: ("owner" | "supply" | "supplyMax" | "hooks")[] = [];
        if (ownerParity === "match" || ownerParity === "mismatch") fieldsCompared.push("owner");
        if (supplyParity === "match" || supplyParity === "mismatch") fieldsCompared.push("supply");
        if (hooksParity === "match" || hooksParity === "mismatch") fieldsCompared.push("hooks");
        
        // Determine evidence tier impact: if we have supply match, it's still useful even if partial
        const hasAnyMatch = ownerParity === "match" || supplyParity === "match" || hooksParity === "match";
        const evidenceTierImpact = hasAnyMatch ? "multi_rpc_plus_indexer" : "multi_rpc";
        
        // Status: "partial" if only partial evidence (supply only), "supported" if full evidence
        const scanProviderStatus = (suprascanProviderResponse as SupraScanProviderResponse).status;
        const indexerParityStatus: IndexerParityStatus = scanProviderStatus === "partial_ok" || scanProviderStatus === "partial" ? "partial" : "supported";
        
        // Normalize missing parity fields to "n/a" for safe handling (only undefined/null, preserve "unknown")
        const normalizedDetails = {
          ownerParity: (ownerParity === undefined || ownerParity === null) ? "n/a" as const : ownerParity,
          supplyParity: (supplyParity === undefined || supplyParity === null) ? "n/a" as const : supplyParity,
          hooksParity: (hooksParity === undefined || hooksParity === null) ? "n/a" as const : hooksParity,
          hookHashParity: (hookHashParity === undefined || hookHashParity === null) ? "n/a" as const : hookHashParity,
        };
        
        indexerParity = {
          status: indexerParityStatus,
          reason: scanProviderStatus === "partial_ok" 
            ? "SupraScan indexer returned partial evidence (supply from getFaDetails). Owner and hooks not available."
            : "SupraScan indexer returned FA data for corroboration.",
          fieldsCompared: fieldsCompared.length > 0 ? fieldsCompared : undefined,
          evidenceTierImpact,
          details: normalizedDetails,
          mismatches: mismatches.length > 0 ? mismatches : undefined,
        };
      } else if (suprascanProviderResponse && !suprascanProviderResponse.ok) {
        // Check for unsupported_schema status (schema mismatch)
        if ((suprascanProviderResponse as SupraScanProviderResponse).status === "unsupported_schema") {
          const response = suprascanProviderResponse as SupraScanProviderResponse;
          const reason = response.error || "SupraScan schema mismatch - HTTP 200 but no mappable fields";
          suprascanFa = {
            status: "unsupported_schema" as IndexerParityStatus,
            ok: false,
            urlUsed: response.urlUsed,
            reason: reason || "",
            diagnostics: response.diagnostics,
          };
          indexerParity = {
            status: "unsupported" as IndexerParityStatus,
            reason: `SupraScan indexer schema mismatch: ${reason}. Evidence tier limited to multi_rpc.`,
            evidenceTierImpact: "multi_rpc",
            details: {
              ownerParity: "n/a",
              supplyParity: "n/a",
              hooksParity: "n/a",
              hookHashParity: "n/a",
            },
          };
        } else {
          const response = suprascanProviderResponse as SupraScanProviderResponse;
          // Check if it's a non-schema unsupported case (shouldn't happen with new provider, but handle for safety)
          if (response.error?.includes("unsupported") && response.status !== "unsupported_schema") {
            // SupraScan does not support this FA object (legacy case)
            const reason = response.error || "SupraScan does not have data for this FA object";
            suprascanFa = {
              status: "unsupported" as IndexerParityStatus,
              ok: false,
              urlUsed: response.urlUsed,
              reason: reason || "",
              diagnostics: response.diagnostics,
            };
            indexerParity = {
              status: "unsupported" as IndexerParityStatus,
              reason: `SupraScan indexer does not support this FA object: ${reason}. Evidence tier limited to multi_rpc.`,
              evidenceTierImpact: "multi_rpc",
              details: {
                ownerParity: "n/a",
                supplyParity: "n/a",
                hooksParity: "n/a",
                hookHashParity: "n/a",
              },
            };
          } else {
            // SupraScan returned an error (network/parse errors)
            const reason = response?.error || suprascanResult?.error || suprascanResult?.hint || "Unknown error";
            suprascanFa = {
              status: "error" as IndexerParityStatus,
              ok: false,
              urlUsed: response?.urlUsed,
              reason: reason || "",
              diagnostics: response?.diagnostics,
            };
            indexerParity = {
              status: "error" as IndexerParityStatus,
              reason: `SupraScan indexer query failed: ${reason}. Evidence tier limited to multi_rpc.`,
              evidenceTierImpact: "multi_rpc",
              details: {
                ownerParity: "n/a",
                supplyParity: "n/a",
                hooksParity: "n/a",
                hookHashParity: "n/a",
              },
            };
          }
        }
      } else {
        // No response or unknown state
        const response = suprascanProviderResponse as SupraScanProviderResponse | undefined;
        const reason = response?.error || suprascanResult?.error || suprascanResult?.hint || "Unknown error";
        suprascanFa = {
          status: "error" as IndexerParityStatus,
          ok: false,
          urlUsed: response?.urlUsed,
          reason: reason || "",
          diagnostics: response?.diagnostics,
        };
        indexerParity = {
          status: "error",
          reason: `SupraScan indexer query failed: ${reason}. Evidence tier limited to multi_rpc.`,
          evidenceTierImpact: "multi_rpc",
          details: {
            ownerParity: "n/a",
            supplyParity: "n/a",
            hooksParity: "n/a",
            hookHashParity: "n/a",
          },
        };
      }
    }
  }
  
  // Sort provider results for deterministic output
  providerResults.sort((a, b) => {
    const order: Record<string, number> = { rpc_v3: 1, rpc_v1: 2, rpc_v3_2: 3, suprascan: 4 };
    return (order[a.source] || 999) - (order[b.source] || 999);
  });
  
  // Determine final evidence tier - upgrade to multi_source_confirmed when we have rpc + rpc2 + suprascan
  let finalEvidenceTier = overallTier;
  if (target.kind === "fa") {
    if (indexerParity && indexerParity.evidenceTierImpact === "multi_rpc") {
      // Ensure we don't claim multi_rpc_plus_indexer when indexer is unavailable
      if (finalEvidenceTier === "multi_rpc_plus_indexer") {
        finalEvidenceTier = "multi_rpc_confirmed";
      }
    } else if (opts.withSupraScan && suprascanProviderResponse?.ok && v3 && v3_2) {
      // Upgrade to multi_source_confirmed when we have rpc + rpc2 + suprascan all successful
      if (finalEvidenceTier === "multi_rpc_plus_indexer" || finalEvidenceTier === "multi_rpc_confirmed") {
        finalEvidenceTier = "multi_source_confirmed";
      }
    }
  }
  
  // Level 3 Behavior Evidence: Sample recent transactions (unless skipped)
  let behaviorEvidence: BehaviorEvidence | undefined;
  if (!opts.skipTx) {
    try {
      // Build pinned entry functions map from v3 surface data
      const pinnedEntryFunctions = buildPinnedEntryFunctionsMap(
        v3?.abiPresence,
        v3?.hookModules
      );
      
      // Determine if ABI is opaque (no modules with ABI or all have 0 functions)
      const abiOpaque = !v3?.abiPresence || v3.abiPresence.length === 0 ||
        v3.abiPresence.every(m => !m.hasAbi || (m.entryFns === 0 && m.exposedFns === 0));
      
      // Collect module addresses for transaction sampling
      const moduleAddresses: string[] = [];
      if (target.kind === "fa" && v3?.hookModules) {
        for (const hook of v3.hookModules) {
          if (hook.module_address && !moduleAddresses.includes(hook.module_address.toLowerCase())) {
            moduleAddresses.push(hook.module_address.toLowerCase());
          }
        }
      }
      
      // For FA tokens, use owner address as primary tx address
      const ownerAddress = target.kind === "fa" ? (v3?.owner || v1?.owner) : undefined;
      
      // Build behavior probe addresses for FA: owner + hook modules + probe addresses
      let behaviorProbeAddresses: string[] | undefined;
      if (target.kind === "fa") {
        const probeSet = new Set<string>();
        
        // Add owner
        if (ownerAddress) {
          probeSet.add(ownerAddress.toLowerCase());
        }
        
        // Add hook module addresses
        for (const addr of moduleAddresses) {
          probeSet.add(addr.toLowerCase());
        }
        
        // Add probe addresses from opts (already normalized)
        if (opts.behaviorProbeAddresses) {
          for (const addr of opts.behaviorProbeAddresses) {
            const normalized = addr.trim().toLowerCase();
            if (normalized.startsWith("0x")) {
              probeSet.add(normalized);
            }
          }
        }
        
        behaviorProbeAddresses = Array.from(probeSet);
      }
      
      behaviorEvidence = await sampleRecentTxBehavior({
        faAddress: target.kind === "fa" ? target.id : undefined,
        coinType: target.kind === "coin" ? target.id : undefined,
        ownerAddress,
        moduleAddresses,
        probeAddresses: behaviorProbeAddresses,
        limit: opts.txLimit ?? 20,
        timeoutMs: opts.timeoutMs,
        pinnedEntryFunctions,
        abiOpaque,
        rpcUrl: opts.rpcUrl,
        preferV2: opts.preferV2 ?? false,
      });
    } catch (error) {
      // Don't fail verification - just mark behavior as unavailable
      const errorMsg = error instanceof Error ? error.message : String(error);
      behaviorEvidence = {
        status: "unavailable",
        tx_count: 0,
        invoked_entries: [],
        phantom_entries: [],
        opaque_active: false,
        sampled_at: new Date().toISOString(),
        error: `Behavior sampling failed: ${errorMsg}`,
      };
    }
  }
  
  // Synthesize risk signals and verdict
  const riskSynthesis = synthesizeRisk({
    target,
    overallEvidenceTier: finalEvidenceTier,
    status,
    discrepancies,
    claims,
    suprascan_fa: suprascanFa,
    parity,
    indexer_parity: indexerParity,
    behavior: behaviorEvidence,
    // Surface scan data could be passed here if available from snapshot
    // For now, we derive what we can from the verification data
    surfaceScan: {
      hasOpaqueAbi: v3?.abiPresence?.every(m => !m.hasAbi || (m.entryFns === 0 && m.exposedFns === 0)) ?? false,
      hookControlled: (v3?.hookModules?.length ?? 0) > 0,
    },
  });
  
  const report: VerificationReport = {
    target,
    timestamp_iso: new Date().toISOString(),
    rpc_url: opts.rpcUrl,
    mode: opts.mode === "agent" ? "strict" : opts.mode, // Map agent to strict for report type
    sources_attempted: sourcesAttempted,
    sources_succeeded: sourcesSucceeded,
    provider_results: providerResults,
    claims,
    overallEvidenceTier: finalEvidenceTier,
    discrepancies,
    ...(suprascanFa ? { suprascan_fa: suprascanFa } : {}),
    ...(parity ? { parity } : {}),
    ...(indexerParity ? { indexer_parity: indexerParity } : {}),
    ...(behaviorEvidence ? { behavior: behaviorEvidence } : {}),
    risk: riskSynthesis,
    status,
    verdict: status === "CONFLICT" ? "FAIL_Corroboration" : undefined,
  };
  
  return report;
}


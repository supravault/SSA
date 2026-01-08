// src/analyzers/coin/analyzeCoinSurface.ts

import { fetchAccountModuleV3 } from "../../rpc/supraAccountsV3.js";
import { extractEntryFunctions, extractExposedFunctions } from "../../rpc/supra.js";
import type { RpcClientOptions } from "../../rpc/supraRpcClient.js";
import { buildCoinModuleInventory } from "../shared/moduleInventory.js";
import { classifyEntryFunctions } from "../shared/functionClassification.js";
import type { CoinCapabilities } from "./analyzeCoinResources.js";
import {
  extractPrivilegesFromAbi,
  mergePrivilegeReports,
  createEmptyPrivilegeReport,
  type PrivilegeReport,
} from "../shared/privilegeModel.js";
import {
  createEmptyInvariantReport,
  calculateOverallInvariantStatus,
  COIN_INVARIANTS,
  type InvariantReport,
  type InvariantItem,
} from "../shared/invariants.js";
import { getModuleArtifact } from "../../rpc/getModuleArtifact.js";
import { hashModuleArtifact, normalizeModuleId, aggregateModulePinsHash } from "../../utils/moduleHash.js";

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence?: any;
  recommendation?: string;
}

export interface ModuleAnalysis {
  module_address: string;
  module_name?: string;
  source: string;
  abi_fetched: boolean;
  abi_error?: string;
  exposed_entry_functions: string[];
  exposed_functions: string[];
  classified_functions: {
    mint: string[];
    burn: string[];
    admin: string[];
    freeze: string[];
    hookConfig: string[];
  };
}

export interface ModulePin {
  module_address: string;
  module_name: string;
  moduleId: string;
  codeHash: string | null;
  hashBasis: "bytecode" | "abi" | "none";
  fetchedFrom: "rpc_v3" | "rpc_v1" | "unknown";
  role?: "coin_defining" | "rpc_v3_list" | "publisher_module";
}

export interface CoinSurfaceAnalysis {
  findings: Finding[];
  modulesAnalyzed: ModuleAnalysis[];
  coverage: {
    status: "complete" | "partial";
    reasons: string[];
  };
  moduleInventory?: import("../shared/moduleInventory.js").ModuleInventory;
  privileges?: PrivilegeReport;
  invariants?: InvariantReport;
  modulePins?: ModulePin[];
  modulePinsHash?: string;
}

/**
 * Analyze legacy coin surface area: Level 2 privilege & invariants
 * Converts capability PRESENCE into capability REACHABILITY
 */
export async function analyzeCoinSurface(
  caps: CoinCapabilities,
  publisherAddress: string,
  definingModuleName: string,
  rpcUrl: string,
  resourceTypes?: string[],
  rpcOptions?: Partial<RpcClientOptions>,
  coinType?: string,
  supplyNormalizationFailed?: boolean
): Promise<CoinSurfaceAnalysis> {
  const findings: Finding[] = [];
  const rpcOpts: RpcClientOptions = {
    rpcUrl,
    timeout: 10000,
    retries: 2,
    retryDelay: 500,
    ...rpcOptions,
  };

  // Build module inventory
  const inventory = await buildCoinModuleInventory(publisherAddress, definingModuleName, resourceTypes, rpcOpts);
  
  // Add coverage reason if supply normalization failed
  if (supplyNormalizationFailed) {
    inventory.coverage.reasons.push("Unable to normalize legacy supply value from resource shape");
    if (inventory.coverage.status === "complete") {
      inventory.coverage.status = "partial";
    }
  }

  // Analyze each module (we'll filter to relevant later)
  const modulesAnalyzed: ModuleAnalysis[] = [];
  const normalizedPublisherAddress = publisherAddress.toLowerCase();
  
  // Filter to only relevant modules: defining module + modules from publisher address
  const relevantModules = inventory.modules.filter((m) => {
    const normalizedAddress = m.module_address.toLowerCase();
    return normalizedAddress === normalizedPublisherAddress;
  });

  for (const module of relevantModules) {
    let abi_fetched = false;
    let abi_error: string | undefined;
    let exposed_entry_functions: string[] = [];
    let exposed_functions: string[] = [];
    
    const isDefiningModule = module.module_name === definingModuleName && module.module_address.toLowerCase() === normalizedPublisherAddress;
    const debugEnabled = process.env.LEGACY_ABI_DEBUG === "1";

    if (module.module_name) {
      try {
        const moduleResult = await fetchAccountModuleV3(module.module_address, module.module_name, rpcOpts);

        if (moduleResult.module?.abi) {
          abi_fetched = true;
          const abi: any = moduleResult.module.abi;
          
          // Debug output for defining module only
          if (isDefiningModule && debugEnabled) {
            console.error(`[DEBUG] ABI keys for ${module.module_name}: ${Object.keys(abi).join(", ")}`);
            if (abi.exposed_functions) {
              console.error(`[DEBUG] abi.exposed_functions found: ${Array.isArray(abi.exposed_functions) ? abi.exposed_functions.length : "not array"}`);
            }
            if (abi.functions) {
              console.error(`[DEBUG] abi.functions found: ${Array.isArray(abi.functions) ? abi.functions.length : "not array"}`);
            }
            if (abi.abi && typeof abi.abi === "object") {
              console.error(`[DEBUG] abi.abi keys: ${Object.keys(abi.abi).join(", ")}`);
            }
          }
          
          // Extract entry functions
          exposed_entry_functions = extractEntryFunctions(abi);
          
          // Extract exposed functions with schema-flexible extraction
          exposed_functions = extractExposedFunctions(abi);
          
          if (isDefiningModule && debugEnabled) {
            console.error(`[DEBUG] Final exposed_functions count: ${exposed_functions.length}`);
            if (exposed_functions.length > 0) {
              console.error(`[DEBUG] Sample functions: ${exposed_functions.slice(0, 5).join(", ")}`);
            }
          }
        } else if (moduleResult.error) {
          abi_error = `RPC error: ${moduleResult.error.message || String(moduleResult.error)}`;
        } else {
          abi_error = "Module ABI not found in RPC response";
        }
      } catch (err) {
        abi_error = err instanceof Error ? err.message : String(err);
      }
    } else {
      abi_error = "Module name unknown, cannot fetch ABI";
    }

    // Classify based on union of entry_functions and exposed_functions
    const allExposedFunctions = [...new Set([...exposed_entry_functions, ...exposed_functions])];
    const classified = classifyEntryFunctions(allExposedFunctions);

    modulesAnalyzed.push({
      module_address: module.module_address,
      module_name: module.module_name,
      source: module.source,
      abi_fetched,
      abi_error,
      exposed_entry_functions,
      exposed_functions,
      classified_functions: classified,
    });
  }

  // Rule: COIN-OPAQUE-ABI-001 - Opaque module ABIs (only for relevant modules)
  // Filter to only relevant modules (from defining module or publisher address)
  const relevantModulesAnalyzed = modulesAnalyzed.filter((m) => {
    const normalizedAddress = m.module_address.toLowerCase();
    const normalizedPublisher = publisherAddress.toLowerCase();
    return normalizedAddress === normalizedPublisher;
  });
  
  const opaqueModules = relevantModulesAnalyzed.filter((m) => !m.abi_fetched);
  if (opaqueModules.length > 0) {
    findings.push({
      id: "COIN-OPAQUE-ABI-001",
      severity: "MEDIUM",
      title: "Relevant module ABI unavailable",
      detail: `${opaqueModules.length} relevant module(s) have unavailable ABIs or empty exposed_functions. Cannot verify entry function reachability.`,
      evidence: {
        opaque_modules: opaqueModules.map((m) => ({
          address: m.module_address,
          name: m.module_name || "(unknown)",
          source: m.source,
          error: m.abi_error,
        })),
      },
      recommendation:
        "Verify modules are publicly accessible and ABIs are available. Opaque modules may hide privileged functions.",
    });
  }

  // Rule: COIN-OPAQUE-ABI-001 (variant) - Opaque ABI with transfer restrictions
  // If hasTransferRestrictions AND ABI fetched BUT no exposed/entry functions
  // Note: This is a specific variant of COIN-OPAQUE-ABI-001 for transfer restrictions
  if (caps.hasTransferRestrictions) {
    const definingModule = relevantModulesAnalyzed.find((m) => {
      const normalizedAddress = m.module_address.toLowerCase();
      return normalizedAddress === publisherAddress.toLowerCase() && m.module_name === definingModuleName;
    });
    
    if (definingModule && definingModule.abi_fetched) {
      const totalFunctions = definingModule.exposed_entry_functions.length + definingModule.exposed_functions.length;
      if (totalFunctions === 0) {
        findings.push({
          id: "COIN-OPAQUE-ABI-001",
          severity: "MEDIUM",
          title: "Opaque ABI: no exposed functions while transfer restrictions detected",
          detail: "Transfer restrictions are present in resources, but the defining module ABI has zero exposed/entry functions. Cannot verify restriction logic without bytecode analysis.",
          evidence: {
            hasTransferRestrictions: true,
            module_address: definingModule.module_address,
            module_name: definingModule.module_name || "(unknown)",
            abi_fetched: true,
            exposed_entry_functions: definingModule.exposed_entry_functions.length,
            exposed_functions: definingModule.exposed_functions.length,
          },
          recommendation: "Review module bytecode or source code to verify transfer restriction implementation. Opaque ABIs may hide restriction bypass vulnerabilities.",
        });
      }
    }
  }

  // Rule: COIN-MINT-REACH-001 - Mint reachability (only check relevant modules)
  if (caps.hasMintCap) {
    const mintFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of relevantModulesAnalyzed) {
      // Check union of entry_functions and exposed_functions for mint patterns
      const allFunctions = [...new Set([...mod.exposed_entry_functions, ...mod.exposed_functions])];
      const allClassified = classifyEntryFunctions(allFunctions);
      for (const fn of allClassified.mint) {
        mintFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (mintFunctions.length > 0) {
      findings.push({
        id: "COIN-MINT-REACH-001",
        severity: "HIGH",
        title: "MintCap present AND mint-like entry function reachable",
        detail: `MintCap exists in resources AND ${mintFunctions.length} mint-like entry function(s) found in exposed modules. Supply can be increased via public entry functions.`,
        evidence: {
          hasMintCap: true,
          mintFunctions,
        },
        recommendation: "Review mint authority controls. If public minting is not intended, restrict access or remove MintCap.",
      });
    }
  }

  // Rule: COIN-BURN-REACH-001 - Burn reachability (only check relevant modules)
  if (caps.hasBurnCap) {
    const burnFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of relevantModulesAnalyzed) {
      const allFunctions = [...new Set([...mod.exposed_entry_functions, ...mod.exposed_functions])];
      const allClassified = classifyEntryFunctions(allFunctions);
      for (const fn of allClassified.burn) {
        burnFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (burnFunctions.length > 0) {
      findings.push({
        id: "COIN-BURN-REACH-001",
        severity: "MEDIUM",
        title: "BurnCap present AND burn-like entry function reachable",
        detail: `BurnCap exists in resources AND ${burnFunctions.length} burn-like entry function(s) found.`,
        evidence: {
          hasBurnCap: true,
          burnFunctions,
        },
        recommendation: "Review burn authority controls and ensure burn operations are properly gated.",
      });
    }
  }

  // Rule: COIN-FREEZE-REACH-001 - Freeze/restrict reachability (only check relevant modules)
  if (caps.hasFreezeCap || caps.hasTransferRestrictions) {
    const freezeFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of relevantModulesAnalyzed) {
      const allFunctions = [...new Set([...mod.exposed_entry_functions, ...mod.exposed_functions])];
      const allClassified = classifyEntryFunctions(allFunctions);
      for (const fn of allClassified.freeze) {
        freezeFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (freezeFunctions.length > 0) {
      findings.push({
        id: "COIN-FREEZE-REACH-001",
        severity: "HIGH",
        title: "FreezeCap/restrictions present AND freeze/pause/denylist entry functions reachable",
        detail: `FreezeCap or transfer restrictions exist AND ${freezeFunctions.length} freeze/pause/denylist entry function(s) found. Token transfers may be frozen or restricted.`,
        evidence: {
          hasFreezeCap: caps.hasFreezeCap,
          hasTransferRestrictions: caps.hasTransferRestrictions,
          freezeFunctions,
        },
        recommendation: "Review freeze/restriction authority. Unauthorized freezes could lock user funds.",
      });
    }
  }

  // Rule: COIN-ADMIN-ROTATE-001 - Admin/owner rotation reachability (only check relevant modules)
  if (caps.owner || caps.admin) {
    const adminFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of relevantModulesAnalyzed) {
      const allFunctions = [...new Set([...mod.exposed_entry_functions, ...mod.exposed_functions])];
      const allClassified = classifyEntryFunctions(allFunctions);
      for (const fn of allClassified.admin) {
        adminFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (adminFunctions.length > 0) {
      findings.push({
        id: "COIN-ADMIN-ROTATE-001",
        severity: "HIGH",
        title: "Owner/admin present AND admin/owner rotation entry functions reachable",
        detail: `Coin has owner/admin (${caps.owner || caps.admin}) AND ${adminFunctions.length} admin/owner rotation entry function(s) found. Ownership or administrative privileges may be transferable.`,
        evidence: {
          owner: caps.owner,
          admin: caps.admin,
          adminFunctions,
        },
        recommendation: "Review ownership transfer controls. Unauthorized ownership changes could compromise token security.",
      });
    }
  }

  // Rule: COIN-MODULE-COVERAGE-001 - Module coverage partial
  if (inventory.coverage.status === "partial") {
    findings.push({
      id: "COIN-MODULE-COVERAGE-001",
      severity: "MEDIUM",
      title: "Module inventory coverage is partial",
      detail: `Module inventory coverage is partial. ${inventory.coverage.reasons.length} issue(s) detected.`,
      evidence: {
        coverage_reasons: inventory.coverage.reasons,
        modules_total: inventory.modules.length,
        modules_with_names: inventory.modules.filter((m) => m.module_name).length,
      },
      recommendation: "Review coverage gaps. Some modules may be missing from analysis, potentially hiding privileged functions.",
    });
  }

  // Rule: COIN-OPAQUE-CONTROL-001 - Opaque control surface (coverage warning)
  // Trigger if: supply > 0 AND no caps AND (no relevant modules OR all modules have empty exposed_functions OR coverage is partial/opaque)
  const hasAnyCap = caps.hasMintCap || caps.hasBurnCap || caps.hasFreezeCap || caps.hasTransferRestrictions;
  
  // Check if supplyCurrentBase exists and is > 0 (should already be parsed as string by extractNumericValue)
  let hasSupply = false;
  if (caps.supplyCurrentBase) {
    try {
      // supplyCurrentBase should already be a string from extractNumericValue, but double-check
      const supplyStr = typeof caps.supplyCurrentBase === "string" ? caps.supplyCurrentBase : String(caps.supplyCurrentBase);
      const parsed = parseFloat(supplyStr);
      if (!isNaN(parsed) && parsed > 0) {
        hasSupply = true;
      }
    } catch {
      // If parsing fails, check if string contains non-zero digits
      const supplyStr = String(caps.supplyCurrentBase);
      if (/[1-9]/.test(supplyStr)) {
        hasSupply = true;
      }
    }
  }
  
  // Check coverage conditions: no relevant modules OR all modules have empty exposed_functions OR coverage is partial
  const hasRelevantModules = relevantModulesAnalyzed.length > 0;
  const allModulesEmpty = hasRelevantModules && relevantModulesAnalyzed.every((m) => {
    const totalFunctions = m.exposed_entry_functions.length + m.exposed_functions.length;
    return totalFunctions === 0;
  });
  const coverageOpaque = inventory.coverage.status === "partial" && (
    inventory.coverage.reasons.some((r) => r.includes("opaque") || r.includes("ABI") || r.includes("unknown names"))
  );
  
  const coverageEmpty = !hasRelevantModules || allModulesEmpty || coverageOpaque;
  
  if (hasSupply && !hasAnyCap && coverageEmpty) {
    findings.push({
      id: "COIN-OPAQUE-CONTROL-001",
      severity: "MEDIUM",
      title: "Legacy coin has circulating supply but no detectable control surface",
      detail: "Legacy coin has circulating supply but no detectable control surface under current heuristics. Control paths may exist via non-matched module patterns or opaque/empty ABI. This is NOT proof of immutability.",
      evidence: {
        coinType: coinType || `${publisherAddress}::${definingModuleName}`,
        supplyCurrentBase: caps.supplyCurrentBase,
        supplyCurrentFormatted: caps.supplyCurrentFormatted || null,
        decimals: caps.decimals || null,
        admin: caps.admin || null,
        coverage_status: inventory.coverage.status,
        coverage_reasons: inventory.coverage.reasons,
        relevantModulesCount: relevantModulesAnalyzed.length,
        hasMintCap: caps.hasMintCap,
        hasBurnCap: caps.hasBurnCap,
        hasFreezeCap: caps.hasFreezeCap,
        hasTransferRestrictions: caps.hasTransferRestrictions,
      },
      recommendation: "Investigate alternative control mechanisms. Supply may be managed via non-standard patterns, upgradeable modules, or external contracts not captured by current analysis.",
    });
  }

  // Extract privileges from all relevant modules
  const privilegeReports: PrivilegeReport[] = [];
  let hasOpaqueControl = false;

  for (const mod of relevantModulesAnalyzed) {
    const moduleId = mod.module_name
      ? `${mod.module_address}::${mod.module_name}`
      : mod.module_address;

    if (!mod.abi_fetched || (mod.exposed_entry_functions.length === 0 && mod.exposed_functions.length === 0)) {
      hasOpaqueControl = true;
      continue;
    }

    // Extract privileges from ABI (we don't have the raw ABI here, but we have the function lists)
    const privileges = extractPrivilegesFromAbi(
      {}, // ABI not available, but function names are sufficient
      moduleId,
      mod.exposed_entry_functions,
      mod.exposed_functions
    );

    if (privileges.length > 0) {
      const report = createEmptyPrivilegeReport();
      report.all = privileges;
      for (const priv of privileges) {
        report.byClass[priv.class].push(priv);
      }
      privilegeReports.push(report);
    }
  }

  // Merge all privilege reports
  const privileges = privilegeReports.length > 0
    ? mergePrivilegeReports(privilegeReports)
    : createEmptyPrivilegeReport();
  privileges.hasOpaqueControl = hasOpaqueControl || relevantModulesAnalyzed.length === 0;

  // Build invariant report
  const invariantItems: InvariantItem[] = [];

  // COIN_SUPPLY_KNOWN
  if (caps.supplyCurrentBase) {
    try {
      const supplyStr = typeof caps.supplyCurrentBase === "string" ? caps.supplyCurrentBase : String(caps.supplyCurrentBase);
      const parsed = parseFloat(supplyStr);
      if (!isNaN(parsed)) {
        invariantItems.push({
          id: COIN_INVARIANTS.SUPPLY_KNOWN,
          status: "ok",
          title: "Coin supply is known",
          detail: `Current supply: ${caps.supplyCurrentFormatted || caps.supplyCurrentBase}`,
        });
      } else {
        invariantItems.push({
          id: COIN_INVARIANTS.SUPPLY_KNOWN,
          status: "warning",
          title: "Coin supply parsing uncertain",
          detail: "Supply value exists but could not be parsed as numeric",
        });
      }
    } catch {
      invariantItems.push({
        id: COIN_INVARIANTS.SUPPLY_KNOWN,
        status: "unknown",
        title: "Coin supply status unknown",
        detail: "Supply value could not be evaluated",
      });
    }
  } else {
    invariantItems.push({
      id: COIN_INVARIANTS.SUPPLY_KNOWN,
      status: "unknown",
      title: "Coin supply not found",
      detail: "No supply information available in resources",
    });
  }

  // COIN_MINT_CAP_PRESENT
  invariantItems.push({
    id: COIN_INVARIANTS.MINT_CAP_PRESENT,
    status: caps.hasMintCap ? "ok" : "warning",
    title: caps.hasMintCap ? "MintCap present" : "MintCap not found",
    detail: caps.hasMintCap
      ? "MintCap capability exists in resources"
      : "No MintCap capability detected. Supply may be immutable or controlled elsewhere.",
  });

  // COIN_MINT_REACHABLE_WITH_CAP
  if (caps.hasMintCap) {
    const mintReachable = relevantModulesAnalyzed.some((m) => {
      const allFunctions = [...new Set([...m.exposed_entry_functions, ...m.exposed_functions])];
      const classified = classifyEntryFunctions(allFunctions);
      return classified.mint.length > 0;
    });
    invariantItems.push({
      id: COIN_INVARIANTS.MINT_REACHABLE_WITH_CAP,
      status: mintReachable ? "ok" : "warning",
      title: mintReachable
        ? "Mint function reachable with MintCap"
        : "MintCap present but no reachable mint function",
      detail: mintReachable
        ? "MintCap exists and mint-like functions are reachable"
        : "MintCap exists but no public mint functions found. Minting may require private keys or external contracts.",
    });
  } else {
    invariantItems.push({
      id: COIN_INVARIANTS.MINT_REACHABLE_WITH_CAP,
      status: "unknown",
      title: "Mint reachability not applicable",
      detail: "No MintCap present",
    });
  }

  // COIN_FREEZE_REACHABLE
  if (caps.hasFreezeCap || caps.hasTransferRestrictions) {
    const freezeReachable = relevantModulesAnalyzed.some((m) => {
      const allFunctions = [...new Set([...m.exposed_entry_functions, ...m.exposed_functions])];
      const classified = classifyEntryFunctions(allFunctions);
      return classified.freeze.length > 0;
    });
    invariantItems.push({
      id: COIN_INVARIANTS.FREEZE_REACHABLE,
      status: freezeReachable ? "ok" : "warning",
      title: freezeReachable
        ? "Freeze function reachable"
        : "FreezeCap/restrictions present but no reachable freeze function",
      detail: freezeReachable
        ? "Freeze capabilities exist and freeze-like functions are reachable"
        : "Freeze capabilities exist but no public freeze functions found.",
    });
  } else {
    invariantItems.push({
      id: COIN_INVARIANTS.FREEZE_REACHABLE,
      status: "unknown",
      title: "Freeze reachability not applicable",
      detail: "No FreezeCap or transfer restrictions present",
    });
  }

  const invariants: InvariantReport = {
    items: invariantItems,
    overall: calculateOverallInvariantStatus(invariantItems),
  };

  // Compute module hashes for pinning (at least for defining module and relevant modules)
  const modulePins: ModulePin[] = [];
  const uniqueModules = new Map<string, { module_address: string; module_name: string; role: "coin_defining" | "rpc_v3_list" | "publisher_module" }>();
  
  // Add defining module
  uniqueModules.set(`${publisherAddress}::${definingModuleName}`, {
    module_address: publisherAddress,
    module_name: definingModuleName,
    role: "coin_defining",
  });
  
  // Add relevant modules from inventory
  for (const mod of relevantModulesAnalyzed) {
    if (mod.module_name) {
      const key = `${mod.module_address}::${mod.module_name}`;
      if (!uniqueModules.has(key)) {
        const invMod = inventory.modules.find(m => m.module_address === mod.module_address && m.module_name === mod.module_name);
        uniqueModules.set(key, {
          module_address: mod.module_address,
          module_name: mod.module_name,
          role: invMod?.source === "rpc_v3_list" ? "rpc_v3_list" : "publisher_module",
        });
      }
    }
  }

  // Fetch artifacts and compute hashes
  for (const { module_address, module_name, role } of uniqueModules.values()) {
    try {
      const artifact = await getModuleArtifact(rpcUrl, module_address, module_name, rpcOpts);
      const hashResult = hashModuleArtifact(artifact);
      
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      modulePins.push({
        module_address,
        module_name,
        moduleId,
        codeHash: hashResult?.hash || null,
        hashBasis: hashResult?.basis || "none",
        fetchedFrom: artifact.fetchedFrom,
        role,
      });
    } catch (error) {
      // If fetch fails, still add entry with null hash
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      modulePins.push({
        module_address,
        module_name,
        moduleId,
        codeHash: null,
        hashBasis: "none",
        fetchedFrom: "unknown",
        role,
      });
    }
  }

  // Compute aggregate hash
  const modulePinsHash = modulePins.length > 0
    ? aggregateModulePinsHash(modulePins.map(pin => ({
        moduleId: pin.moduleId,
        codeHash: pin.codeHash,
        hashBasis: pin.hashBasis,
      })))
    : undefined;

  return {
    findings,
    modulesAnalyzed,
    coverage: inventory.coverage,
    moduleInventory: inventory,
    privileges,
    invariants,
    modulePins: modulePins, // Always return array (even if empty) for schema stability
    modulePinsHash,
  };
}


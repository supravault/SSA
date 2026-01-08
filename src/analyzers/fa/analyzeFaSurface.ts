// src/analyzers/fa/analyzeFaSurface.ts

import { fetchAccountModuleV3 } from "../../rpc/supraAccountsV3.js";
import { extractEntryFunctions } from "../../rpc/supra.js";
import type { RpcClientOptions } from "../../rpc/supraRpcClient.js";
import type { FaResourceCapabilities } from "./analyzeFaResources.js";
import { buildFAModuleInventory } from "../shared/moduleInventory.js";
import { classifyEntryFunctions } from "../shared/functionClassification.js";
import {
  extractPrivilegesFromAbi,
  mergePrivilegeReports,
  createEmptyPrivilegeReport,
  type PrivilegeReport,
} from "../shared/privilegeModel.js";
import {
  createEmptyInvariantReport,
  calculateOverallInvariantStatus,
  FA_INVARIANTS,
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
  classified_functions: {
    mint: string[];
    burn: string[];
    admin: string[];
    freeze: string[];
    hookConfig: string[];
  };
}

export interface HookModulePin {
  module_address: string;
  module_name: string;
  moduleId: string;
  codeHash: string | null;
  hashBasis: "bytecode" | "abi" | "none";
  fetchedFrom: "rpc_v3" | "rpc_v1" | "unknown";
}

export interface FaSurfaceAnalysis {
  findings: Finding[];
  modulesAnalyzed: ModuleAnalysis[];
  coverage: {
    status: "complete" | "partial";
    reasons: string[];
  };
  privileges?: PrivilegeReport;
  invariants?: InvariantReport;
  hookModulePins?: HookModulePin[];
  hookModulesSurfaceHash?: string;
}

/**
 * Analyze FA surface area: Level 2 privilege & invariants
 * Converts capability PRESENCE into capability REACHABILITY
 */
export async function analyzeFaSurface(
  caps: FaResourceCapabilities,
  rpcUrl: string,
  creatorAddress?: string,
  ownerAddress?: string,
  resourceTypes?: string[],
  rpcOptions?: Partial<RpcClientOptions>,
  parsedResourceCount?: number
): Promise<FaSurfaceAnalysis> {
  const findings: Finding[] = [];
  const rpcOpts: RpcClientOptions = {
    rpcUrl,
    timeout: 10000,
    retries: 2,
    retryDelay: 500,
    ...rpcOptions,
  };

  // Build ref holder addresses array
  const refHolderAddresses: Array<{ refType: "mint" | "burn" | "transfer"; address: string }> = [];
  if (caps.mintRefHolder) {
    refHolderAddresses.push({ refType: "mint", address: caps.mintRefHolder });
  }
  if (caps.burnRefHolder) {
    refHolderAddresses.push({ refType: "burn", address: caps.burnRefHolder });
  }
  if (caps.transferRefHolder) {
    refHolderAddresses.push({ refType: "transfer", address: caps.transferRefHolder });
  }

  // Build module inventory
  const inventory = await buildFAModuleInventory(
    caps.hookModules || [],
    creatorAddress,
    ownerAddress,
    resourceTypes,
    rpcOpts,
    refHolderAddresses.length > 0 ? refHolderAddresses : undefined
  );

  // Analyze each relevant module (hook modules + owner-address modules)
  const modulesAnalyzed: ModuleAnalysis[] = [];
  // Filter to only relevant modules: hook modules + owner-address modules (exclude system modules 0x1, 0x3)
  const normalizedOwnerAddress = caps.owner ? caps.owner.toLowerCase() : null;
  const relevantModules = inventory.modules.filter((m) => {
    if (!m.is_relevant) return false;
    const normalizedAddress = m.module_address.toLowerCase();
    // Exclude system modules
    if (normalizedAddress === "0x1" || normalizedAddress === "0x3") return false;
    // Include hook modules and owner-address modules
    return true;
  });

  for (const module of relevantModules) {
    let abi_fetched = false;
    let abi_error: string | undefined;
    let exposed_entry_functions: string[] = [];

    if (module.module_name) {
      try {
        const moduleResult = await fetchAccountModuleV3(module.module_address, module.module_name, rpcOpts);

        if (moduleResult.module?.abi) {
          abi_fetched = true;
          exposed_entry_functions = extractEntryFunctions(moduleResult.module.abi);
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

    const classified = classifyEntryFunctions(exposed_entry_functions);

    modulesAnalyzed.push({
      module_address: module.module_address,
      module_name: module.module_name,
      source: module.source,
      abi_fetched,
      abi_error,
      exposed_entry_functions,
      classified_functions: classified,
    });
  }

  // Rule: FA-OPAQUE-ABI-001 - Opaque module ABIs
  const opaqueModules = modulesAnalyzed.filter((m) => !m.abi_fetched);
  if (opaqueModules.length > 0) {
    findings.push({
      id: "FA-OPAQUE-ABI-001",
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

  // Rule: FA-MINT-REACH-001 - Mint reachability
  if (caps.hasMintRef) {
    const mintFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of modulesAnalyzed) {
      for (const fn of mod.classified_functions.mint) {
        mintFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (mintFunctions.length > 0) {
      findings.push({
        id: "FA-MINT-REACH-001",
        severity: "HIGH",
        title: "MintRef present AND mint-like entry/exposed functions reachable",
        detail: `FA has MintRef capability AND ${mintFunctions.length} mint-like entry/exposed function(s) found in relevant modules (owner, hook, or ref holder modules). Minting may be callable.`,
        evidence: {
          hasMintRef: true,
          mintFunctions,
          owner: caps.owner,
          mintRefHolder: caps.mintRefHolder || "unknown",
        },
        recommendation: "Review mint authority controls. If public minting is not intended, restrict access or remove MintRef.",
      });
    } else if (!caps.mintRefHolder) {
      // If no mint functions found and holder address unknown, keep medium rating
      findings.push({
        id: "FA-MINT-REACH-001",
        severity: "MEDIUM",
        title: "MintRef holder address unknown (resource doesn't expose holder)",
        detail: "MintRef holder address unknown (resource doesn't expose holder). Mint capability may be restricted or accessed via other means.",
        evidence: {
          hasMintRef: true,
          mintRefHolder: null,
          modulesAnalyzed: modulesAnalyzed.length,
        },
        recommendation: "Monitor for new modules or function additions. Verify mint authority is properly controlled.",
      });
    } else {
      // Holder address known but no mint functions found
      findings.push({
        id: "FA-MINT-REACH-001",
        severity: "MEDIUM",
        title: "Mint reference present but no public mint path detected (yet)",
        detail: `Mint reference exists in resources (holder: ${caps.mintRefHolder}), but no exposed entry functions matching mint patterns were found. Mint capability may be restricted or accessed via other means.`,
        evidence: {
          hasMintRef: true,
          mintRefHolder: caps.mintRefHolder,
          modulesAnalyzed: modulesAnalyzed.length,
        },
        recommendation: "Monitor for new modules or function additions. Verify mint authority is properly controlled.",
      });
    }
  }

  // Rule: FA-BURN-REACH-001 - Burn reachability
  if (caps.hasBurnRef) {
    const burnFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of modulesAnalyzed) {
      for (const fn of mod.classified_functions.burn) {
        burnFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (burnFunctions.length > 0) {
      const hasBurnFrom = burnFunctions.some((bf) => bf.function.toLowerCase().includes("burn_from"));
      findings.push({
        id: "FA-BURN-REACH-001",
        severity: hasBurnFrom ? "HIGH" : "MEDIUM",
        title: "Burn reference present AND burn-like entry function reachable",
        detail: `Burn reference exists in resources AND ${burnFunctions.length} burn-like entry function(s) found. ${hasBurnFrom ? "burn_from-like function detected (HIGH severity)." : ""}`,
        evidence: {
          hasBurnRef: true,
          burnFunctions,
        },
        recommendation: "Review burn authority controls and ensure burn operations are properly gated.",
      });
    }
  }

  // Rule: FA-HOOK-CONFIG-001 - Hook configuration reachability
  if (caps.hasDepositHook || caps.hasWithdrawHook || caps.hasDerivedBalanceHook) {
    const hookConfigFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of modulesAnalyzed) {
      for (const fn of mod.classified_functions.hookConfig) {
        hookConfigFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (hookConfigFunctions.length > 0) {
      findings.push({
        id: "FA-HOOK-CONFIG-001",
        severity: "HIGH",
        title: "Hook configuration/update/dispatch entry/exposed functions reachable",
        detail: `${hookConfigFunctions.length} hook configuration/update/dispatch entry/exposed function(s) found in relevant modules (owner, hook, or ref holder modules). Hook behavior may be modifiable.`,
        evidence: {
          hasDepositHook: caps.hasDepositHook,
          hasWithdrawHook: caps.hasWithdrawHook,
          hasDerivedBalanceHook: caps.hasDerivedBalanceHook,
          hookConfigFunctions,
          owner: caps.owner,
        },
        recommendation:
          "Review hook configuration controls. Unauthorized hook changes could affect token behavior.",
      });
    }
  }

  // Rule: FA-ADMIN-ROTATE-001 - Admin/owner rotation reachability
  if (caps.owner) {
    const adminFunctions: Array<{ module: string; function: string }> = [];
    for (const mod of modulesAnalyzed) {
      for (const fn of mod.classified_functions.admin) {
        adminFunctions.push({
          module: mod.module_name ? `${mod.module_address}::${mod.module_name}` : mod.module_address,
          function: fn,
        });
      }
    }

    if (adminFunctions.length > 0) {
      findings.push({
        id: "FA-ADMIN-ROTATE-001",
        severity: "HIGH",
        title: "Owner present AND admin/owner rotation entry/exposed functions reachable",
        detail: `FA has owner (${caps.owner}) AND ${adminFunctions.length} admin/owner rotation entry/exposed function(s) found in relevant modules (owner, hook, or ref holder modules). Ownership or administrative privileges may be transferable.`,
        evidence: {
          owner: caps.owner,
          adminFunctions,
        },
        recommendation: "Review ownership transfer controls. Unauthorized ownership changes could compromise token security.",
      });
    }
  }

  // Rule: FA-MODULE-COVERAGE-001 - Module coverage partial
  if (inventory.coverage.status === "partial") {
    findings.push({
      id: "FA-MODULE-COVERAGE-001",
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

  // Rule: FA-OPAQUE-CONTROL-001 - Opaque control surface (coverage warning)
  // Trigger if: supply > 0 AND no refs AND no hooks AND no relevant modules
  const hasAnyRef = caps.hasMintRef || caps.hasBurnRef || caps.hasTransferRef;
  const hasAnyHook = caps.hasDepositHook || caps.hasWithdrawHook || caps.hasDerivedBalanceHook;
  const hasRelevantModules = modulesAnalyzed.length > 0;
  
  // Check if supplyCurrent exists and is > 0
  let hasSupply = false;
  if (caps.supplyCurrent) {
    try {
      const parsed = parseFloat(caps.supplyCurrent);
      if (!isNaN(parsed) && parsed > 0) {
        hasSupply = true;
      }
    } catch {
      // If parsing fails, check if string contains non-zero digits
      if (/[1-9]/.test(caps.supplyCurrent)) {
        hasSupply = true;
      }
    }
  }
  
  if (hasSupply && !hasAnyRef && !hasAnyHook && !hasRelevantModules) {
    findings.push({
      id: "FA-OPAQUE-CONTROL-001",
      severity: "MEDIUM",
      title: "FA has circulating supply but no detectable control surface",
      detail: "FA has circulating supply but no detectable control surface (no refs, no hooks, no relevant modules). Control paths may exist outside current heuristics. This is NOT proof of immutability.",
      evidence: {
        supplyCurrent: caps.supplyCurrent,
        owner: caps.owner || null,
        parsedResourceCount: parsedResourceCount || 0,
        hasMintRef: caps.hasMintRef,
        hasBurnRef: caps.hasBurnRef,
        hasTransferRef: caps.hasTransferRef,
        hasDepositHook: caps.hasDepositHook,
        hasWithdrawHook: caps.hasWithdrawHook,
        hasDerivedBalanceHook: caps.hasDerivedBalanceHook,
        relevantModulesCount: modulesAnalyzed.length,
      },
      recommendation: "Investigate alternative control mechanisms. Supply may be managed via non-standard patterns, upgradeable modules, or external contracts not captured by current analysis.",
    });
  }

  // Extract privileges from all relevant modules
  const privilegeReports: PrivilegeReport[] = [];
  let hasOpaqueControl = false;

  for (const mod of modulesAnalyzed) {
    const moduleId = mod.module_name
      ? `${mod.module_address}::${mod.module_name}`
      : mod.module_address;

    if (!mod.abi_fetched || mod.exposed_entry_functions.length === 0) {
      hasOpaqueControl = true;
      continue;
    }

    // Extract privileges from ABI
    const privileges = extractPrivilegesFromAbi(
      {}, // ABI not available, but function names are sufficient
      moduleId,
      mod.exposed_entry_functions,
      [] // FA only uses entry functions
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
  privileges.hasOpaqueControl = hasOpaqueControl || modulesAnalyzed.length === 0;

  // Build invariant report
  const invariantItems: InvariantItem[] = [];

  // FA_OWNER_KNOWN
  if (caps.owner) {
    invariantItems.push({
      id: FA_INVARIANTS.OWNER_KNOWN,
      status: "ok",
      title: "FA owner is known",
      detail: `Owner address: ${caps.owner}`,
    });
  } else {
    invariantItems.push({
      id: FA_INVARIANTS.OWNER_KNOWN,
      status: "warning",
      title: "FA owner not found",
      detail: "No owner address detected in ObjectCore resources",
    });
  }

  // FA_OWNER_STABILITY_SIGNAL
  // This is a placeholder - in a real implementation, we'd check historical snapshots
  invariantItems.push({
    id: FA_INVARIANTS.OWNER_STABILITY_SIGNAL,
    status: "unknown",
    title: "Owner stability signal",
    detail: "Owner stability requires historical comparison (Level 3)",
  });

  // FA_HAS_WITHDRAW_HOOK
  invariantItems.push({
    id: FA_INVARIANTS.HAS_WITHDRAW_HOOK,
    status: caps.hasWithdrawHook ? "ok" : "warning",
    title: caps.hasWithdrawHook ? "Withdraw hook present" : "Withdraw hook not found",
    detail: caps.hasWithdrawHook
      ? "Withdraw hook is configured"
      : "No withdraw hook detected. Withdrawals may not be gated.",
  });

  // FA_UNKNOWN_HOOK_MODULE
  const unknownHookModules = (caps.hookModules || []).filter((h) => {
    const hookModuleId = `${h.module_address}::${h.module_name}`;
    return !modulesAnalyzed.some((m) => {
      const modId = m.module_name ? `${m.module_address}::${m.module_name}` : m.module_address;
      return modId === hookModuleId && m.abi_fetched;
    });
  });
  invariantItems.push({
    id: FA_INVARIANTS.UNKNOWN_HOOK_MODULE,
    status: unknownHookModules.length > 0 ? "warning" : "ok",
    title: unknownHookModules.length > 0
      ? "Unknown hook module(s)"
      : "All hook modules known",
    detail: unknownHookModules.length > 0
      ? `${unknownHookModules.length} hook module(s) have unknown ABIs`
      : "All hook modules have accessible ABIs",
    evidence: unknownHookModules.length > 0
      ? { unknown_modules: unknownHookModules }
      : undefined,
  });

  // FA_MAX_SUPPLY_PRESENT
  if (caps.supplyMax) {
    invariantItems.push({
      id: FA_INVARIANTS.MAX_SUPPLY_PRESENT,
      status: "ok",
      title: "Max supply is set",
      detail: `Max supply: ${caps.supplyMax}`,
    });
  } else {
    invariantItems.push({
      id: FA_INVARIANTS.MAX_SUPPLY_PRESENT,
      status: "warning",
      title: "Max supply not found",
      detail: "No max supply limit detected. Supply may be unbounded.",
    });
  }

  // FA_MAX_SUPPLY_EXCEEDED
  if (caps.supplyMax && caps.supplyCurrent) {
    try {
      const max = parseFloat(caps.supplyMax);
      const current = parseFloat(caps.supplyCurrent);
      if (!isNaN(max) && !isNaN(current)) {
        if (current > max) {
          invariantItems.push({
            id: FA_INVARIANTS.MAX_SUPPLY_EXCEEDED,
            status: "violation",
            title: "Max supply exceeded",
            detail: `Current supply (${current}) exceeds max supply (${max})`,
            evidence: { current, max },
          });
        } else {
          invariantItems.push({
            id: FA_INVARIANTS.MAX_SUPPLY_EXCEEDED,
            status: "ok",
            title: "Max supply not exceeded",
            detail: `Current supply (${current}) is within max supply (${max})`,
          });
        }
      } else {
        invariantItems.push({
          id: FA_INVARIANTS.MAX_SUPPLY_EXCEEDED,
          status: "unknown",
          title: "Max supply check uncertain",
          detail: "Could not parse supply values for comparison",
        });
      }
    } catch {
      invariantItems.push({
        id: FA_INVARIANTS.MAX_SUPPLY_EXCEEDED,
        status: "unknown",
        title: "Max supply check failed",
        detail: "Error comparing supply values",
      });
    }
  } else {
    invariantItems.push({
      id: FA_INVARIANTS.MAX_SUPPLY_EXCEEDED,
      status: "unknown",
      title: "Max supply check not applicable",
      detail: "Max supply or current supply not available",
    });
  }

  const invariants: InvariantReport = {
    items: invariantItems,
    overall: calculateOverallInvariantStatus(invariantItems),
  };

  // Compute hook module hashes for pinning
  const hookModulePins: HookModulePin[] = [];
  const uniqueHookModules = new Map<string, { module_address: string; module_name: string }>();
  
  // Collect unique hook modules from caps.hookModules
  if (caps.hookModules) {
    for (const hook of caps.hookModules) {
      const key = `${hook.module_address}::${hook.module_name}`;
      if (!uniqueHookModules.has(key)) {
        uniqueHookModules.set(key, {
          module_address: hook.module_address,
          module_name: hook.module_name,
        });
      }
    }
  }

  // Fetch artifacts and compute hashes for each unique hook module
  for (const { module_address, module_name } of uniqueHookModules.values()) {
    try {
      const artifact = await getModuleArtifact(rpcUrl, module_address, module_name, rpcOpts);
      const hashResult = hashModuleArtifact(artifact);
      
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      hookModulePins.push({
        module_address,
        module_name,
        moduleId,
        codeHash: hashResult?.hash || null,
        hashBasis: hashResult?.basis || "none",
        fetchedFrom: artifact.fetchedFrom,
      });
    } catch (error) {
      // If fetch fails, still add entry with null hash
      const moduleId = normalizeModuleId(`${module_address}::${module_name}`);
      hookModulePins.push({
        module_address,
        module_name,
        moduleId,
        codeHash: null,
        hashBasis: "none",
        fetchedFrom: "unknown",
      });
    }
  }

  // Compute aggregate hash
  const hookModulesSurfaceHash = hookModulePins.length > 0
    ? aggregateModulePinsHash(hookModulePins.map(pin => ({
        moduleId: pin.moduleId,
        codeHash: pin.codeHash,
        hashBasis: pin.hashBasis,
      })))
    : undefined;

  return {
    findings,
    modulesAnalyzed,
    coverage: inventory.coverage,
    privileges,
    invariants,
    hookModulePins: hookModulePins, // Always return array (even if empty) for schema stability
    hookModulesSurfaceHash,
  };
}

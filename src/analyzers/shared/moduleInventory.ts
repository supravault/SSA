// src/analyzers/shared/moduleInventory.ts

import { fetchAccountModulesV3 } from "../../rpc/supraAccountsV3.js";
import type { RpcClientOptions } from "../../rpc/supraRpcClient.js";

export type ModuleSource = "rpc_v3_list" | "resource_types" | "hooks" | "manual" | "coin_defining" | "fa_owner_modules" | "fa_ref_holder";

export interface ModuleEntry {
  module_address: string;
  module_name?: string; // undefined if module name unknown
  source: ModuleSource;
  is_relevant: boolean;
}

export interface ModuleInventory {
  modules: ModuleEntry[];
  coverage: {
    status: "complete" | "partial";
    reasons: string[];
  };
  recovery?: {
    attempts: string[];
    recovered: Array<{ address: string; oldName: string | null; newName: string; strategy: string }>;
  };
  ownerModulesCount?: number; // For FA: count of modules at owner address
}

/**
 * Extract module addresses from resource type strings
 * Pattern: 0xADDRESS::MODULE::STRUCT
 */
export function extractModulesFromResourceTypes(resourceTypes: string[]): Array<{ address: string; module_name?: string }> {
  const modules: Array<{ address: string; module_name?: string }> = [];
  const seen = new Set<string>();

  for (const type of resourceTypes) {
    const parts = type.split("::");
    if (parts.length >= 2 && parts[0].startsWith("0x")) {
      const address = parts[0].toLowerCase();
      const module_name = parts[1];
      const key = `${address}::${module_name}`;
      if (!seen.has(key)) {
        seen.add(key);
        modules.push({ address, module_name });
      }
    }
  }

  return modules;
}

/**
 * Build module inventory for FA tokens
 */
export async function buildFAModuleInventory(
  hookModules: Array<{ module_address: string; module_name: string; function_name: string }>,
  creatorAddress?: string,
  ownerAddress?: string,
  resourceTypes?: string[],
  rpcOptions?: RpcClientOptions,
  refHolderAddresses?: Array<{ refType: "mint" | "burn" | "transfer"; address: string }>
): Promise<ModuleInventory> {
  const modules: ModuleEntry[] = [];
  const seen = new Set<string>();
  const reasons: string[] = [];
  let ownerModulesCount = 0; // Track owner modules count for reporting

  // Add hook modules
  for (const hook of hookModules) {
    const key = `${hook.module_address}::${hook.module_name}`;
    if (!seen.has(key)) {
      seen.add(key);
      modules.push({
        module_address: hook.module_address,
        module_name: hook.module_name,
        source: "hooks",
        is_relevant: true,
      });
    }
  }

  // Build set of relevant addresses (hook addresses + owner address + ref holder addresses)
  const relevantAddresses = new Set<string>();
  for (const hook of hookModules) {
    relevantAddresses.add(hook.module_address.toLowerCase());
  }
  if (ownerAddress) {
    relevantAddresses.add(ownerAddress.toLowerCase());
  }
  if (refHolderAddresses) {
    for (const refHolder of refHolderAddresses) {
      if (refHolder.address) {
        relevantAddresses.add(refHolder.address.toLowerCase());
      }
    }
  }

  // Add modules from resource types (only if they match relevant addresses)
  if (resourceTypes && resourceTypes.length > 0) {
    const resourceModules = extractModulesFromResourceTypes(resourceTypes);
    for (const rm of resourceModules) {
      const key = rm.module_name ? `${rm.address}::${rm.module_name}` : rm.address;
      if (!seen.has(key)) {
        seen.add(key);
        const normalizedAddress = rm.address.toLowerCase();
        // Only mark as relevant if it matches hook or owner address
        // System modules (0x1, 0x3) are non-relevant
        const isRelevant = relevantAddresses.has(normalizedAddress) && normalizedAddress !== "0x1" && normalizedAddress !== "0x3";
        modules.push({
          module_address: rm.address,
          module_name: rm.module_name,
          source: "resource_types",
          is_relevant: isRelevant,
        });
      }
    }
  }

  // Fetch modules via RPC from owner address (and creator if different)
  const addressesToCheck = new Set<string>();
  if (ownerAddress) addressesToCheck.add(ownerAddress.toLowerCase());
  if (creatorAddress && creatorAddress.toLowerCase() !== ownerAddress?.toLowerCase()) {
    addressesToCheck.add(creatorAddress.toLowerCase());
  }

  let rpcCoverageComplete = true;
  for (const address of addressesToCheck) {
    try {
      const rpcResult = await fetchAccountModulesV3(address, rpcOptions || { rpcUrl: "" });
      if (rpcResult.error) {
        rpcCoverageComplete = false;
        reasons.push(`RPC fetch failed for ${address}: ${rpcResult.error.message || String(rpcResult.error)}`);
        continue;
      }

      const rpcModules = rpcResult.modules || [];
      const isOwnerAddress = ownerAddress && address.toLowerCase() === ownerAddress.toLowerCase();
      
      // Count owner modules
      if (isOwnerAddress) {
        ownerModulesCount = rpcModules.length;
      }
      
      for (const rpcMod of rpcModules) {
        const moduleName = rpcMod.name || undefined;
        const key = moduleName ? `${address}::${moduleName}` : address;
        
        // Check if this is a system module (0x1, 0x3) - mark as non-relevant
        const normalizedModAddress = address.toLowerCase();
        const isSystemModule = normalizedModAddress === "0x1" || normalizedModAddress === "0x3";
        
        // Relevant if: owner address module OR hook address module, AND not system module
        const isRelevant = (isOwnerAddress || relevantAddresses.has(normalizedModAddress)) && !isSystemModule;
        
        if (!seen.has(key)) {
          seen.add(key);
          modules.push({
            module_address: address,
            module_name: moduleName,
            source: isOwnerAddress ? "fa_owner_modules" : "rpc_v3_list",
            is_relevant: isRelevant,
          });
        } else {
          // Update existing entry if it was from hooks/resource_types and now we have name
          const existing = modules.find((m) => m.module_address === address && (!m.module_name || m.module_name === moduleName));
          if (existing) {
            if (!existing.module_name && moduleName) {
              existing.module_name = moduleName;
            }
            // Update relevance: owner address modules are always relevant (unless system)
            if (isOwnerAddress && !isSystemModule) {
              existing.is_relevant = true;
            }
          }
        }
      }
    } catch (error) {
      rpcCoverageComplete = false;
      const errorMsg = error instanceof Error ? error.message : String(error);
      reasons.push(`RPC fetch error for ${address}: ${errorMsg}`);
    }
  }

  // Fetch modules from ref holder addresses
  if (refHolderAddresses) {
    for (const refHolder of refHolderAddresses) {
      if (!refHolder.address) continue;
      
      const normalizedRefHolderAddress = refHolder.address.toLowerCase();
      // Skip if already processed (e.g., same as owner)
      if (normalizedRefHolderAddress === ownerAddress?.toLowerCase()) continue;
      if (normalizedRefHolderAddress === creatorAddress?.toLowerCase()) continue;
      
      try {
        const rpcResult = await fetchAccountModulesV3(normalizedRefHolderAddress, rpcOptions || { rpcUrl: "" });
        if (rpcResult.error) {
          reasons.push(`RPC fetch failed for ${refHolder.refType}Ref holder ${normalizedRefHolderAddress}: ${rpcResult.error.message || String(rpcResult.error)}`);
        } else {
          const rpcModules = rpcResult.modules || [];
          const isSystemModule = normalizedRefHolderAddress === "0x1" || normalizedRefHolderAddress === "0x3";
          const isRelevant = !isSystemModule; // Ref holder modules are relevant unless system
          
          for (const rpcMod of rpcModules) {
            const moduleName = rpcMod.name || undefined;
            const key = moduleName ? `${normalizedRefHolderAddress}::${moduleName}` : normalizedRefHolderAddress;
            
            if (!seen.has(key)) {
              seen.add(key);
              modules.push({
                module_address: normalizedRefHolderAddress,
                module_name: moduleName,
                source: "fa_ref_holder",
                is_relevant: isRelevant,
              });
            }
          }
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        reasons.push(`RPC fetch error for ${refHolder.refType}Ref holder ${normalizedRefHolderAddress}: ${errorMsg}`);
      }
    }
  }

  // Check for modules without names (coverage issue)
  const unnamedModules = modules.filter((m) => !m.module_name);
  if (unnamedModules.length > 0) {
    reasons.push(`${unnamedModules.length} module(s) have unknown names (from ${unnamedModules.map((m) => m.source).join(", ")})`);
  }

  // Check for hook modules not found in RPC list
  const hookAddresses = new Set(hookModules.map((h) => h.module_address.toLowerCase()));
  for (const address of hookAddresses) {
    if (addressesToCheck.has(address)) {
      const rpcMods = modules.filter((m) => m.module_address.toLowerCase() === address && m.source === "rpc_v3_list");
      const hookMods = modules.filter((m) => m.module_address.toLowerCase() === address && m.source === "hooks");
      if (rpcMods.length > 0 && hookMods.length > 0) {
        // Check if hook module names match RPC module names
        const hookNames = new Set(hookMods.map((m) => m.module_name).filter(Boolean));
        const rpcNames = new Set(rpcMods.map((m) => m.module_name).filter(Boolean));
        const missing = Array.from(hookNames).filter((n) => !rpcNames.has(n));
        if (missing.length > 0) {
          reasons.push(`Hook modules ${missing.join(", ")} not found in RPC module list for ${address}`);
        }
      }
    }
  }

  // Coverage is complete if:
  // 1. No critical RPC fetch errors
  // 2. No unnamed modules
  // 3. Owner modules were successfully enumerated (even if count is 0, that's fine)
  const hasCriticalErrors = reasons.some((r) => r.includes("RPC fetch failed") || r.includes("RPC fetch error"));
  const status = !hasCriticalErrors && unnamedModules.length === 0 && reasons.length === 0 ? "complete" : "partial";

  return {
    modules,
    coverage: {
      status,
      reasons,
    },
    ownerModulesCount, // Track owner modules count for reporting
  };
}

/**
 * Build module inventory for legacy coins
 */
export async function buildCoinModuleInventory(
  publisherAddress: string,
  definingModuleName: string,
  resourceTypes?: string[],
  rpcOptions?: RpcClientOptions
): Promise<ModuleInventory> {
  const modules: ModuleEntry[] = [];
  const seen = new Set<string>();
  const reasons: string[] = [];

  // Add defining module
  const definingKey = `${publisherAddress}::${definingModuleName}`;
  seen.add(definingKey);
  modules.push({
    module_address: publisherAddress,
    module_name: definingModuleName,
    source: "coin_defining",
    is_relevant: true,
  });

  // Add modules from resource types (only if they match publisher address)
  const normalizedPublisherAddress = publisherAddress.toLowerCase();
  if (resourceTypes && resourceTypes.length > 0) {
    const resourceModules = extractModulesFromResourceTypes(resourceTypes);
    for (const rm of resourceModules) {
      const key = rm.module_name ? `${rm.address}::${rm.module_name}` : rm.address;
      if (!seen.has(key)) {
        seen.add(key);
        const normalizedResourceAddress = rm.address.toLowerCase();
        // Only mark as relevant if it matches publisher address
        // System modules (0x1, 0x3) and unrelated third-party modules are non-relevant
        const isRelevant = normalizedResourceAddress === normalizedPublisherAddress;
        modules.push({
          module_address: rm.address,
          module_name: rm.module_name,
          source: "resource_types",
          is_relevant: isRelevant,
        });
      }
    }
  }

  // Fetch all modules at publisher address via RPC
  let rpcCoverageComplete = true;
  const recoveryAttempts: string[] = [];
  const recoveredModules: Array<{ address: string; oldName: string | null; newName: string; strategy: string }> = [];
  
  try {
    const rpcResult = await fetchAccountModulesV3(publisherAddress, rpcOptions || { rpcUrl: "" });
    if (rpcResult.error) {
      rpcCoverageComplete = false;
      reasons.push(`RPC fetch failed for ${publisherAddress}: ${rpcResult.error.message || String(rpcResult.error)}`);
    } else {
      const rpcModules = rpcResult.modules || [];
      for (const rpcMod of rpcModules) {
        const moduleName = rpcMod.name || undefined;
        const key = moduleName ? `${publisherAddress}::${moduleName}` : publisherAddress;
        if (!seen.has(key)) {
          seen.add(key);
          modules.push({
            module_address: publisherAddress,
            module_name: moduleName,
            source: "rpc_v3_list",
            is_relevant: true,
          });
        } else {
          // Update existing entry if it was from resource_types and now we have name
          const existing = modules.find((m) => m.module_address === publisherAddress && (!m.module_name || m.module_name === moduleName));
          if (existing && !existing.module_name && moduleName) {
            existing.module_name = moduleName;
            recoveredModules.push({
              address: publisherAddress,
              oldName: null,
              newName: moduleName,
              strategy: "rpc_v3_list",
            });
          }
        }
      }

      // Note: We don't check if defining module was found in RPC list because we manually add it
      // The defining module is always included in the inventory
    }
  } catch (error) {
    rpcCoverageComplete = false;
    const errorMsg = error instanceof Error ? error.message : String(error);
    reasons.push(`RPC fetch error for ${publisherAddress}: ${errorMsg}`);
  }

  // Module name recovery: try to recover names for modules with unknown names
  const unnamedModules = modules.filter((m) => m.is_relevant && !m.module_name && m.module_address === publisherAddress);
  if (unnamedModules.length > 0 && rpcOptions?.rpcUrl) {
    // Strategy 1: Try v1 RPC endpoint (may have different response format)
    try {
      const { fetchModuleListV1 } = await import("../../rpc/supraAccountsV1.js");
      const v1Result = await fetchModuleListV1(rpcOptions.rpcUrl, publisherAddress);
      if (!v1Result.error && v1Result.modules) {
        recoveryAttempts.push("rpc_v1_list");
        for (const v1Mod of v1Result.modules) {
          if (v1Mod.name) {
            // Find unnamed module entry and update it
            const unnamed = unnamedModules.find((m) => !m.module_name);
            if (unnamed) {
              unnamed.module_name = v1Mod.name;
              recoveredModules.push({
                address: publisherAddress,
                oldName: null,
                newName: v1Mod.name,
                strategy: "rpc_v1_list",
              });
            }
          }
        }
      }
    } catch (error) {
      // v1 failed, continue to next strategy
    }

    // Strategy 2: Try fetching individual modules by attempting to parse bytecode or module_id
    // If modules have bytecode in the response, try to extract module name from it
    const stillUnnamed = modules.filter((m) => m.is_relevant && !m.module_name && m.module_address === publisherAddress);
    if (stillUnnamed.length > 0) {
      recoveryAttempts.push("bytecode_parse");
      
      // Try to fetch full module details (which may include name in ABI)
      const { fetchAccountModuleV3 } = await import("../../rpc/supraAccountsV3.js");
      
      // If we have bytecode from the list response, try parsing it
      // Otherwise, try common module name patterns
      const commonNames = [definingModuleName, "coin", "token", "fa", "fungible"];
      
      for (const unnamedMod of stillUnnamed) {
        // Try fetching by common names first
        for (const tryName of commonNames) {
          if (tryName) {
            try {
              const modResult = await fetchAccountModuleV3(publisherAddress, tryName, rpcOptions);
              if (modResult.module?.abi?.name) {
                const recoveredName = modResult.module.abi.name;
                if (recoveredName && recoveredName !== tryName) {
                  // Found a different module, but we can use this name
                  unnamedMod.module_name = recoveredName;
                  recoveredModules.push({
                    address: publisherAddress,
                    oldName: null,
                    newName: recoveredName,
                    strategy: "common_name_probe",
                  });
                  break;
                } else if (recoveredName === tryName) {
                  // This is the module we're looking for
                  unnamedMod.module_name = tryName;
                  recoveredModules.push({
                    address: publisherAddress,
                    oldName: null,
                    newName: tryName,
                    strategy: "common_name_probe",
                  });
                  break;
                }
              }
            } catch {
              // Continue to next name
            }
          }
        }
      }
    }

    // Strategy 3: If modules list response includes bytecode, try parsing module name from bytecode
    // (This would require Move bytecode parsing, which is complex - skip for now)
    // recoveryAttempts.push("bytecode_parse_direct");
  }

  // Check for relevant modules without names (only count these for coverage)
  const relevantUnnamedModules = modules.filter((m) => m.is_relevant && !m.module_name);
  if (relevantUnnamedModules.length > 0) {
    if (recoveryAttempts.length > 0) {
      reasons.push(`${relevantUnnamedModules.length} relevant module(s) have unknown names after ${recoveryAttempts.length} recovery strategies: ${recoveryAttempts.join(", ")}`);
    } else {
      reasons.push(`${relevantUnnamedModules.length} relevant module(s) have unknown names`);
    }
  }

  // Coverage is complete if:
  // 1. Defining module is included (always true, we add it manually)
  // 2. RPC fetch succeeded (or at least didn't fail critically)
  // 3. No relevant unnamed modules
  // Note: We track whether defining module ABI fetch succeeds in the analyzer, not here
  const status = rpcCoverageComplete && relevantUnnamedModules.length === 0 && reasons.length === 0 ? "complete" : "partial";

  const result: ModuleInventory = {
    modules,
    coverage: {
      status,
      reasons,
    },
  };

  // Include recovery information if recovery was attempted
  if (recoveryAttempts.length > 0 || recoveredModules.length > 0) {
    result.recovery = {
      attempts: recoveryAttempts,
      recovered: recoveredModules,
    };
  }

  return result;
}


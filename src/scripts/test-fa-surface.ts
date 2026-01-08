#!/usr/bin/env node

/**
 * Standalone Node CLI script for testing FA surface analysis (Level 2)
 * Fetches FA resources, analyzes them, then resolves ALL relevant modules via RPC ABI fetch
 */

import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";
import { analyzeFaSurface } from "../analyzers/fa/analyzeFaSurface.js";

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

async function main(): Promise<void> {
  try {
    // Read FA address and RPC URL from environment
    const TARGET_FA = process.env.TARGET_FA;
    if (!TARGET_FA) {
      throw new Error("TARGET_FA environment variable is required");
    }

    const rpcUrl = process.env.SUPRA_RPC_URL || process.env.RPC_URL || "https://rpc.supra.com";

    // Call SupraScan GraphQL API
    const data = await suprascanGraphql<{
      addressDetail: {
        isError: boolean;
        errorType: string | null;
        addressDetailSupra: { resources: string | null } | null;
      };
    }>(
      ADDRESS_DETAIL_QUERY,
      {
        address: TARGET_FA,
        blockchainEnvironment: "mainnet",
        isAddressName: false,
      },
      {
        env: "mainnet",
      }
    );

    // Check for errors
    if (data.addressDetail?.isError) {
      const errorType = data.addressDetail.errorType || "Unknown error";
      console.error(`Error: SupraScan returned an error: ${errorType}`);
      process.exit(1);
    }

    // Check if resources are missing
    const resourcesStr = data.addressDetail?.addressDetailSupra?.resources;
    if (!resourcesStr || typeof resourcesStr !== "string" || resourcesStr.trim().length === 0) {
      console.error("Error: Resources are missing or empty in the response");
      process.exit(1);
    }

    // Parse resources to extract resource types
    let resourceTypes: string[] = [];
    try {
      const resources = JSON.parse(resourcesStr);
      if (Array.isArray(resources)) {
        resourceTypes = resources.map((r: any) => r?.type).filter(Boolean);
      }
    } catch {
      // Ignore parse errors
    }

    // Analyze FA resources (Level 1)
    const resourceAnalysis = analyzeFaResources(resourcesStr);

    console.log(`FA Address: ${TARGET_FA}`);
    console.log(`RPC URL: ${rpcUrl}`);
    console.log(`Parsed resource count: ${resourceAnalysis.parsedCount}`);
    console.log("");

    // Print Level 1 caps summary
    console.log("=== Level 1: Capability Presence ===");
    console.log(`hasMintRef: ${resourceAnalysis.caps.hasMintRef}`);
    console.log(`hasBurnRef: ${resourceAnalysis.caps.hasBurnRef}`);
    console.log(`hasTransferRef: ${resourceAnalysis.caps.hasTransferRef}`);
    console.log(`hasDepositHook: ${resourceAnalysis.caps.hasDepositHook}`);
    console.log(`hasWithdrawHook: ${resourceAnalysis.caps.hasWithdrawHook}`);
    console.log(`hasDerivedBalanceHook: ${resourceAnalysis.caps.hasDerivedBalanceHook}`);
    if (resourceAnalysis.caps.owner) {
      console.log(`owner: ${resourceAnalysis.caps.owner}`);
    }
    if (resourceAnalysis.caps.supplyCurrent) {
      console.log(`supplyCurrent: ${resourceAnalysis.caps.supplyCurrent}`);
    }
    if (resourceAnalysis.caps.supplyMax) {
      console.log(`supplyMax: ${resourceAnalysis.caps.supplyMax}`);
    }
    
    // Print ref holders (Level 2+)
    const refHolders: string[] = [];
    if (resourceAnalysis.caps.mintRefHolder) {
      refHolders.push(`mintRefHolder: ${resourceAnalysis.caps.mintRefHolder}`);
    } else if (resourceAnalysis.caps.hasMintRef) {
      refHolders.push(`mintRefHolder: unknown (resource doesn't expose holder)`);
    }
    if (resourceAnalysis.caps.burnRefHolder) {
      refHolders.push(`burnRefHolder: ${resourceAnalysis.caps.burnRefHolder}`);
    } else if (resourceAnalysis.caps.hasBurnRef) {
      refHolders.push(`burnRefHolder: unknown (resource doesn't expose holder)`);
    }
    if (resourceAnalysis.caps.transferRefHolder) {
      refHolders.push(`transferRefHolder: ${resourceAnalysis.caps.transferRefHolder}`);
    } else if (resourceAnalysis.caps.hasTransferRef) {
      refHolders.push(`transferRefHolder: unknown (resource doesn't expose holder)`);
    }
    if (refHolders.length > 0) {
      console.log(`Ref holders: ${refHolders.join(", ")}`);
    }
    
    // Print hook targets from DispatchFunctionStore (authoritative)
    if (resourceAnalysis.caps.hooks) {
      const hookTargets: string[] = [];
      if (resourceAnalysis.caps.hooks.deposit_hook) {
        const h = resourceAnalysis.caps.hooks.deposit_hook;
        hookTargets.push(`deposit_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: medium)`);
      }
      if (resourceAnalysis.caps.hooks.withdraw_hook) {
        const h = resourceAnalysis.caps.hooks.withdraw_hook;
        hookTargets.push(`withdraw_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: high)`);
      }
      if (resourceAnalysis.caps.hooks.transfer_hook) {
        const h = resourceAnalysis.caps.hooks.transfer_hook;
        hookTargets.push(`transfer_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: high)`);
      }
      if (resourceAnalysis.caps.hooks.pre_transfer_hook) {
        const h = resourceAnalysis.caps.hooks.pre_transfer_hook;
        hookTargets.push(`pre_transfer_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: high)`);
      }
      if (resourceAnalysis.caps.hooks.post_transfer_hook) {
        const h = resourceAnalysis.caps.hooks.post_transfer_hook;
        hookTargets.push(`post_transfer_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: medium)`);
      }
      if (resourceAnalysis.caps.hooks.derived_balance_hook) {
        const h = resourceAnalysis.caps.hooks.derived_balance_hook;
        hookTargets.push(`derived_balance_hook: ${h.module_address}::${h.module_name}::${h.function_name} (risk: low)`);
      }
      if (hookTargets.length > 0) {
        console.log("Hook targets (DispatchFunctionStore):");
        hookTargets.forEach((t) => console.log(`  ${t}`));
      }
    }
    console.log("");

    // Analyze FA surface (Level 2)
    console.log("=== Level 2: Privilege & Invariants ===");
    const surfaceAnalysis = await analyzeFaSurface(
      resourceAnalysis.caps,
      rpcUrl,
      resourceAnalysis.caps.owner || undefined,
      resourceAnalysis.caps.owner || undefined,
      resourceTypes,
      undefined, // rpcOptions
      resourceAnalysis.parsedCount // parsedResourceCount
    );

    // Print coverage
    console.log(`Coverage: ${surfaceAnalysis.coverage.status}`);
    if (surfaceAnalysis.coverage.reasons.length > 0) {
      console.log(`Reasons: ${surfaceAnalysis.coverage.reasons.join("; ")}`);
    }
    
    // Print owner modules count if available
    if (resourceAnalysis.caps.owner) {
      const ownerModules = surfaceAnalysis.modulesAnalyzed.filter((m) => m.source === "fa_owner_modules");
      if (ownerModules.length === 0) {
        console.log(`Owner modules: 0 owner modules found at ${resourceAnalysis.caps.owner}`);
      } else {
        console.log(`Owner modules: ${ownerModules.length} module(s) found at ${resourceAnalysis.caps.owner}`);
      }
    }
    console.log("");

    // Print modules analyzed summary table
    // Filter to only relevant modules (hook + owner address, exclude system modules)
    const normalizedOwnerAddress = resourceAnalysis.caps.owner ? resourceAnalysis.caps.owner.toLowerCase() : null;
    const relevantModulesAnalyzed = surfaceAnalysis.modulesAnalyzed.filter((m) => {
      const normalizedAddress = m.module_address.toLowerCase();
      // Exclude system modules
      if (normalizedAddress === "0x1" || normalizedAddress === "0x3") return false;
      return true;
    });
    const nonRelevantModules = surfaceAnalysis.modulesAnalyzed.filter((m) => {
      const normalizedAddress = m.module_address.toLowerCase();
      return normalizedAddress === "0x1" || normalizedAddress === "0x3";
    });
    
    console.log(`Modules Analyzed: ${surfaceAnalysis.modulesAnalyzed.length} total (${relevantModulesAnalyzed.length} relevant, ${nonRelevantModules.length} system/non-relevant)`);
    if (relevantModulesAnalyzed.length > 0) {
      console.log("");
      console.log("Module Summary (relevant only):");
      for (const mod of relevantModulesAnalyzed) {
        const moduleId = mod.module_name ? `${mod.module_address}::${mod.module_name}` : `${mod.module_address}::(unknown)`;
        console.log(`  ${moduleId}`);
        console.log(`    source: ${mod.source}`);
        console.log(`    abi_fetched: ${mod.abi_fetched ? "yes" : "no"}`);
        if (mod.abi_error) {
          console.log(`    error: ${mod.abi_error}`);
        }
        console.log(`    entry_functions: ${mod.exposed_entry_functions.length}`);
        if (mod.exposed_entry_functions.length > 0) {
          const classified = mod.classified_functions;
          const counts = [];
          if (classified.mint.length > 0) counts.push(`mint:${classified.mint.length}`);
          if (classified.burn.length > 0) counts.push(`burn:${classified.burn.length}`);
          if (classified.admin.length > 0) counts.push(`admin:${classified.admin.length}`);
          if (classified.freeze.length > 0) counts.push(`freeze:${classified.freeze.length}`);
          if (classified.hookConfig.length > 0) counts.push(`hookConfig:${classified.hookConfig.length}`);
          if (counts.length > 0) {
            console.log(`    classified: ${counts.join(", ")}`);
          }
        }
        console.log("");
      }
    } else {
      console.log("  (no relevant modules found)");
      console.log("");
    }
    
    if (nonRelevantModules.length > 0) {
      console.log(`System/non-relevant modules (${nonRelevantModules.length}): ${nonRelevantModules.map(m => m.module_address).join(", ")}`);
      console.log("");
    }

    // Print findings
    console.log(`Findings (${surfaceAnalysis.findings.length}):`);
    if (surfaceAnalysis.findings.length === 0) {
      console.log("  (none)");
    } else {
      const severityMap: Record<string, string> = {
        INFO: "info",
        LOW: "low",
        MEDIUM: "medium",
        HIGH: "high",
      };

      for (const finding of surfaceAnalysis.findings) {
        const severity = severityMap[finding.severity] || finding.severity.toLowerCase();
        console.log(`  [${severity}] ${finding.id}: ${finding.title}`);
        if (finding.detail) {
          console.log(`    ${finding.detail}`);
        }
      }
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${errorMessage}`);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run main function
main().catch((error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  console.error(`Unhandled error: ${errorMessage}`);
  process.exit(1);
});

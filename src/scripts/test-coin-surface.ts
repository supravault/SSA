#!/usr/bin/env node

/**
 * Standalone Node CLI script for testing legacy coin surface analysis (Level 2)
 * Fetches coin resources via SupraScan GraphQL, analyzes them, then resolves ALL relevant modules via RPC ABI fetch
 */

import { parseCoinType } from "../core/coinScanner.js";
import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import { analyzeCoinResources } from "../analyzers/coin/analyzeCoinResources.js";
import { analyzeCoinSurface } from "../analyzers/coin/analyzeCoinSurface.js";

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
    // Read coin type and RPC URL from environment
    const TARGET_COIN = process.env.TARGET_COIN;
    if (!TARGET_COIN) {
      throw new Error("TARGET_COIN environment variable is required (format: <addr>::<module>::<COIN>)");
    }

    const rpcUrl = process.env.SUPRA_RPC_URL || process.env.RPC_URL || "https://rpc-mainnet.supra.com";

    // Parse coin type
    let parsed: { publisherAddress: string; moduleName: string; structName: string };
    try {
      parsed = parseCoinType(TARGET_COIN);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid coin type format: ${errorMsg}. Expected format: <addr>::<module>::<COIN>`);
    }

    console.log(`Coin Type: ${TARGET_COIN}`);
    console.log(`RPC URL: ${rpcUrl}`);
    console.log("");

    // Call SupraScan GraphQL API to fetch resources from publisher address
    const data = await suprascanGraphql<{
      addressDetail: {
        isError: boolean;
        errorType: string | null;
        addressDetailSupra: { resources: string | null } | null;
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

    // Analyze coin resources (Level 1)
    const resourceAnalysis = analyzeCoinResources(resourcesStr, TARGET_COIN);

    console.log(`Parsed resource count: ${resourceAnalysis.parsedCount}`);
    console.log("");

    // Print Level 1 caps summary
    console.log("=== Level 1: Capability Presence (Legacy) ===");
    console.log(`hasMintCap: ${resourceAnalysis.caps.hasMintCap}`);
    console.log(`hasBurnCap: ${resourceAnalysis.caps.hasBurnCap}`);
    console.log(`hasFreezeCap: ${resourceAnalysis.caps.hasFreezeCap}`);
    console.log(`hasTransferRestrictions: ${resourceAnalysis.caps.hasTransferRestrictions}`);
    if (resourceAnalysis.caps.owner) {
      console.log(`owner: ${resourceAnalysis.caps.owner}`);
    }
    if (resourceAnalysis.caps.admin) {
      console.log(`admin: ${resourceAnalysis.caps.admin}`);
    }
    if (resourceAnalysis.caps.supplyCurrentBase) {
      console.log(`supplyCurrentBase: ${resourceAnalysis.caps.supplyCurrentBase}`);
    }
    if (resourceAnalysis.caps.supplyMaxBase) {
      console.log(`supplyMaxBase: ${resourceAnalysis.caps.supplyMaxBase}`);
    }
    if (resourceAnalysis.caps.decimals !== null && resourceAnalysis.caps.decimals !== undefined) {
      console.log(`decimals: ${resourceAnalysis.caps.decimals}`);
    }
    if (resourceAnalysis.caps.supplyCurrentFormatted) {
      console.log(`supplyCurrentFormatted: ${resourceAnalysis.caps.supplyCurrentFormatted}`);
    }
    if (resourceAnalysis.caps.supplyUnknown) {
      console.log(`supplyUnknown: true`);
    }
    console.log("");

    // Analyze coin surface (Level 2)
    console.log("=== Level 2: Privilege & Invariants (Legacy) ===");
    const surfaceAnalysis = await analyzeCoinSurface(
      resourceAnalysis.caps,
      parsed.publisherAddress,
      parsed.moduleName,
      rpcUrl,
      resourceTypes,
      undefined, // rpcOptions
      TARGET_COIN, // coinType
      resourceAnalysis.supplyNormalizationFailed // supplyNormalizationFailed
    );

    // Print coverage
    console.log(`Coverage: ${surfaceAnalysis.coverage.status}`);
    if (surfaceAnalysis.coverage.reasons.length > 0) {
      console.log(`Reasons: ${surfaceAnalysis.coverage.reasons.join("; ")}`);
    }
    
    // Print module recovery information if available
    if (surfaceAnalysis.moduleInventory?.recovery) {
      const recovery = surfaceAnalysis.moduleInventory.recovery;
      if (recovery.recovered.length > 0) {
        console.log("");
        console.log("Module Name Recovery:");
        for (const rec of recovery.recovered) {
          console.log(`  [RECOVERED] ${rec.newName} (strategy: ${rec.strategy})`);
        }
      }
      if (recovery.attempts.length > 0 && recovery.recovered.length === 0) {
        console.log("");
        console.log(`Module Recovery Attempted: ${recovery.attempts.join(", ")} (no names recovered)`);
      }
    }
    console.log("");

    // Print modules analyzed summary table
    // Filter to only relevant modules (publisher address)
    const normalizedPublisherAddress = parsed.publisherAddress.toLowerCase();
    const relevantModulesAnalyzed = surfaceAnalysis.modulesAnalyzed.filter((m) => 
      m.module_address.toLowerCase() === normalizedPublisherAddress
    );
    const nonRelevantModules = surfaceAnalysis.modulesAnalyzed.filter((m) => 
      m.module_address.toLowerCase() !== normalizedPublisherAddress
    );
    
    console.log(`Modules Analyzed: ${surfaceAnalysis.modulesAnalyzed.length} total (${relevantModulesAnalyzed.length} relevant, ${nonRelevantModules.length} non-relevant)`);
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
        console.log(`    exposed_functions: ${mod.exposed_functions.length}`);
        if (mod.exposed_entry_functions.length > 0 || mod.exposed_functions.length > 0) {
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
    
    if (nonRelevantModules.length > 0 && process.env.LEGACY_ABI_DEBUG === "1") {
      console.log(`Non-relevant modules (${nonRelevantModules.length}): ${nonRelevantModules.map(m => m.module_address).join(", ")}`);
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

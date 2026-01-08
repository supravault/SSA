/**
 * Level 4 (Indexer & Contextual Parity) Report Formatter
 * Generates structured reports with:
 * - Section A: Token (Coin Type) Facts
 * - Section B: Publisher/Creator (Account) Facts
 * - Section C: Cross-checks (must match / inconsistencies flagged)
 */

import type { ScanResult } from "./types.js";

export interface Level4Report {
  sectionA: {
    coinType: string;
    coinAddress: string; // 0x...::module::COIN (type string, not wallet address)
    symbol?: string;
    decimals?: number;
    supplyOnChainRpc?: string | number; // On-chain supply (RPC) - canonical
    supplyIndexerGraphql?: string | number; // Indexer-reported supply (GraphQL) - economic/UI
    maxSupply?: string | number;
    holders?: number;
    price?: string | number;
    coinMetadata?: {
      name?: string;
      iconUrl?: string;
      verified?: boolean;
      isDualNature?: boolean;
    };
    supplyParity?: {
      driftDetected: boolean;
      tolerance?: string | number;
      difference?: string | number;
      differencePercentage?: number;
      likelyCause?: string;
      explanation?: string;
    };
  };
  sectionB: {
    creatorAddress: string; // 0x... (account address, not coin identifier)
    accountStatus?: "active" | "inactive" | "unknown";
    transactionCount?: number;
    modulesPublished?: string[];
    modulesPublishedCount?: number;
    suspiciousAdminCapabilities?: Array<{
      module: string;
      capability: string;
      severity: string;
    }>;
    ownershipLinks?: Array<{
      relatedAddress: string;
      relationship: string;
    }>;
    deploySignals?: Array<{
      timestamp?: string;
      transactionHash?: string;
      module?: string;
    }>;
    upgradeSignals?: Array<{
      timestamp?: string;
      transactionHash?: string;
      module?: string;
      fromVersion?: string;
      toVersion?: string;
    }>;
  };
  sectionC: {
    // Cross-checks - "claims vs on-chain reality"
    moduleAddressMatchesCreator?: boolean; // For Coin: coin's module address == creator?
    relationshipExplanation?: string;
    // Cross-check 1: creatorAddress (details) vs ObjectCore.owner (resources)
    creatorAddressMatch?: boolean; // GetFaDetails.creatorAddress vs AddressDetail.resources.ObjectCore.owner
    creatorAddressMismatchReason?: string;
    // Cross-check 2: totalSupply (details) vs ConcurrentSupply.current.value (resources)
    supplyMetadataClaimsMatch?: boolean; // GetFaDetails.totalSupply vs AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)
    supplyMetadataMismatchReason?: string;
    // Cross-check 3: verified/holders (details) vs "capabilities present" (resources)
    verifiedVsCapabilitiesCheck?: {
      verified?: boolean; // GetFaDetails.verified
      hasCapabilities: boolean; // Whether capabilities are present in AddressDetail.resources
      holders?: number; // GetFaDetails.holders
      capabilitiesPresent: {
        hasMintRef: boolean;
        hasBurnRef: boolean;
        hasTransferRef: boolean;
        hasDepositHook: boolean;
        hasWithdrawHook: boolean;
        hasDispatchFunctions: boolean;
      };
      mismatch?: string; // Explanation if verified status doesn't align with capabilities
    };
    opaqueAbiButTradable?: boolean;
    opaqueAbiExplanation?: string;
    parityFlags?: Array<{
      flag: string;
      severity: "info" | "warning" | "error";
      message: string;
    }>;
  };
}

/**
 * Generate Level 4 report from ScanResult (supports both Coin and FA)
 */
export function generateLevel4Report(result: ScanResult): Level4Report {
  // Check if this is a Coin or FA scan
  const coinMeta = result.meta.coin_metadata;
  const faMeta = result.meta.fa_metadata;
  const isFA = !!faMeta && !coinMeta;

  if (isFA) {
    return generateLevel4FAReport(result);
  } else {
    return generateLevel4CoinReport(result);
  }
}

/**
 * Generate Level 4 report for Coin tokens
 */
function generateLevel4CoinReport(result: ScanResult): Level4Report {
  const coinMeta = result.meta.coin_metadata;
  const creatorAccount = result.meta.coin_creator_account;
  const crossChecks = result.meta.coin_cross_checks;

  // Section A: Token View (from GetCoinDetails)
  // Use coin_details if available (paired evidence bundle), otherwise fall back to coin_metadata
  const coinDetails = coinMeta?.coin_details;
  const sectionA: Level4Report["sectionA"] = {
    coinType: coinMeta?.coinType || result.target.module_id,
    coinAddress: coinMeta?.coinType || result.target.module_id, // 0x...::module::COIN (type string)
    symbol: coinDetails?.symbol || coinMeta?.symbol,
    decimals: coinDetails?.decimals !== undefined ? coinDetails.decimals : coinMeta?.decimals,
    supplyOnChainRpc: coinMeta?.supplyOnChainRpc, // Explicit label: On-chain supply (RPC)
    supplyIndexerGraphql: coinDetails?.totalSupply || coinMeta?.supplyIndexerGraphql, // Explicit label: Indexer-reported supply (GraphQL)
    maxSupply: undefined, // Could be added if available
    holders: coinDetails?.holders !== undefined ? coinDetails.holders : coinMeta?.holdersCount,
    price: coinDetails?.price || coinMeta?.price,
    coinMetadata: {
      name: coinDetails?.name || coinMeta?.name,
      iconUrl: coinMeta?.iconUrl,
      verified: coinDetails?.verified !== undefined ? coinDetails.verified : coinMeta?.verified,
      isDualNature: coinMeta?.isDualNature,
    },
    supplyParity: coinMeta?.supplyParityCheck
      ? {
          driftDetected: coinMeta.supplyParityCheck.driftDetected,
          tolerance: coinMeta.supplyParityCheck.tolerance,
          difference: coinMeta.supplyParityCheck.difference,
          differencePercentage: coinMeta.supplyParityCheck.differencePercentage,
          likelyCause: coinMeta.supplyParityCheck.likelyCause,
          explanation: coinMeta.supplyParityCheck.driftDetected
            ? `INDEXER_SUPPLY_DRIFT detected: ${coinMeta.supplyParityCheck.likelyCause || "unknown"} (RPC: ${coinMeta.supplyParityCheck.rpcSupply || "N/A"}, GraphQL: ${coinMeta.supplyParityCheck.graphqlSupply || "N/A"})`
            : "Supply sources match within tolerance",
        }
      : undefined,
  };

  // Section B: Publisher/Address View (from AddressDetail)
  // Merge data from creatorAccount and coin_creator_address_resources (paired evidence bundle)
  const creatorResources = coinMeta?.coin_creator_address_resources;
  const sectionB: Level4Report["sectionB"] = creatorAccount
    ? {
        creatorAddress: creatorAccount.address, // 0x... (account address)
        accountStatus: creatorAccount.accountStatus,
        transactionCount: creatorAccount.transactionCount,
        modulesPublished: creatorResources?.modulesPublished || creatorAccount.modulesPublished,
        modulesPublishedCount: creatorResources?.modulesPublishedCount !== undefined 
          ? creatorResources.modulesPublishedCount 
          : creatorAccount.modulesPublishedCount,
        suspiciousAdminCapabilities: creatorAccount.suspiciousAdminCapabilities,
        ownershipLinks: [
          ...(creatorAccount.ownershipLinks || []),
          ...(creatorResources?.owner
            ? [
                {
                  relatedAddress: creatorResources.owner,
                  relationship: "Owner from AddressDetail resources",
                },
              ]
            : []),
        ],
        deploySignals: creatorAccount.deploySignals,
        upgradeSignals: creatorAccount.upgradeSignals,
      }
    : {
        creatorAddress: coinMeta?.creator || coinMeta?.publisherAddress || result.target.module_address,
        accountStatus: "unknown",
        ownershipLinks: creatorResources?.owner
          ? [
              {
                relatedAddress: creatorResources.owner,
                relationship: "Owner from AddressDetail resources",
              },
            ]
          : undefined,
      };

  // Section C: Cross-checks
  const parityFlags: Level4Report["sectionC"]["parityFlags"] = [];
  
  // Check supply parity
  if (coinMeta?.supplyParityCheck?.driftDetected) {
    parityFlags.push({
      flag: "INDEXER_SUPPLY_DRIFT",
      severity: "warning",
      message: `Supply drift detected: ${coinMeta.supplyParityCheck.likelyCause || "unknown"}. RPC: ${coinMeta.supplyParityCheck.rpcSupply || "N/A"}, GraphQL: ${coinMeta.supplyParityCheck.graphqlSupply || "N/A"}`,
    });
  }

  // Check module address vs creator
  if (crossChecks && !crossChecks.moduleAddressMatchesCreator) {
    parityFlags.push({
      flag: "MODULE_ADDRESS_MISMATCH",
      severity: "info",
      message: crossChecks.relationshipExplanation || "Module address differs from creator address",
    });
  }

  // Check supply metadata claims
  if (crossChecks && !crossChecks.supplyMetadataClaimsMatch) {
    parityFlags.push({
      flag: "SUPPLY_METADATA_MISMATCH",
      severity: "warning",
      message: crossChecks.supplyMetadataMismatchReason || "Supply metadata claims do not match",
    });
  }

  // Check opaque ABI but tradable
  if (crossChecks && crossChecks.opaqueAbiButTradable) {
    parityFlags.push({
      flag: "OPAQUE_ABI_TRADABLE",
      severity: "warning",
      message: crossChecks.opaqueAbiExplanation || "Token appears tradable but has opaque ABI",
    });
  }

  const sectionC: Level4Report["sectionC"] = {
    moduleAddressMatchesCreator: crossChecks?.moduleAddressMatchesCreator,
    relationshipExplanation: crossChecks?.relationshipExplanation,
    supplyMetadataClaimsMatch: crossChecks?.supplyMetadataClaimsMatch,
    supplyMetadataMismatchReason: crossChecks?.supplyMetadataMismatchReason,
    opaqueAbiButTradable: crossChecks?.opaqueAbiButTradable,
    opaqueAbiExplanation: crossChecks?.opaqueAbiExplanation,
    parityFlags,
  };

  return {
    sectionA,
    sectionB,
    sectionC,
  };
}

/**
 * Generate Level 4 report for FA tokens
 */
function generateLevel4FAReport(result: ScanResult): Level4Report {
  const faMeta = result.meta.fa_metadata;
  const crossChecks = result.meta.fa_cross_checks;

  // Section A: FA Token Facts - "Token View" (from GetFaDetails)
  // Use fa_details if available (paired evidence bundle), otherwise fall back to fa_metadata
  const faDetails = faMeta?.fa_details;
  const sectionA: Level4Report["sectionA"] = {
    coinType: faMeta?.address || result.target.module_address,
    coinAddress: faMeta?.address || result.target.module_address, // FA address (0x...)
    symbol: faDetails?.faSymbol || faMeta?.symbol,
    decimals: faDetails?.decimals !== undefined ? faDetails.decimals : faMeta?.decimals,
    supplyOnChainRpc: faMeta?.supplyOnChainRpc, // Explicit label: On-chain supply (ConcurrentSupply/RPC-equivalent)
    supplyIndexerGraphql: faDetails?.totalSupply || faMeta?.supplyIndexerGraphql, // Explicit label: Indexer supply (GetFaDetails.totalSupply)
    maxSupply: undefined, // Could be added if available from ConcurrentSupply.max_value
    holders: faDetails?.holders !== undefined ? faDetails.holders : faMeta?.holdersCount,
    price: faDetails?.price ?? faMeta?.price,
    coinMetadata: {
      name: faDetails?.faName || faMeta?.name,
      iconUrl: faMeta?.iconUrl,
      verified: faDetails?.verified !== undefined ? faDetails.verified : faMeta?.verified,
      isDualNature: faMeta?.isDualNature,
    },
    supplyParity: faMeta?.supplyParityCheck
      ? {
          driftDetected: faMeta.supplyParityCheck.driftDetected,
          tolerance: faMeta.supplyParityCheck.tolerance,
          difference: faMeta.supplyParityCheck.difference,
          differencePercentage: faMeta.supplyParityCheck.differencePercentage,
          likelyCause: faMeta.supplyParityCheck.likelyCause,
          explanation: faMeta.supplyParityCheck.driftDetected
            ? `INDEXER_SUPPLY_DRIFT_FA detected: ${faMeta.supplyParityCheck.likelyCause || "unknown"} (RPC: ${faMeta.supplyParityCheck.rpcSupply || "N/A"}, GraphQL: ${faMeta.supplyParityCheck.graphqlSupply || "N/A"})`
            : "Supply sources match within tolerance",
        }
      : undefined,
  };

  // Section B: Publisher/Address View (from AddressDetail)
  // Use data from fa_address_resources and creator_address_resources (paired evidence bundle)
  const faAddressResources = faMeta?.fa_address_resources;
  const creatorAddressResources = faMeta?.creator_address_resources;
  const ownerAddress = faAddressResources?.owner || faDetails?.creatorAddress || faMeta?.creator || faMeta?.ownerOnChain || result.target.module_address;
  
  const sectionB: Level4Report["sectionB"] = {
    creatorAddress: ownerAddress,
    accountStatus: "active", // FA addresses are typically active if metadata exists
    transactionCount: undefined, // Could be added if available
    modulesPublished: creatorAddressResources?.modulesPublished,
    modulesPublishedCount: creatorAddressResources?.modulesPublishedCount,
    suspiciousAdminCapabilities: [
      // From FA address resources
      ...(faAddressResources?.capabilities
        ? [
            ...(faAddressResources.capabilities.hasMintRef
              ? [{ module: "FA", capability: "MintRef (faAddress)", severity: "high" as const }]
              : []),
            ...(faAddressResources.capabilities.hasBurnRef
              ? [{ module: "FA", capability: "BurnRef (faAddress)", severity: "medium" as const }]
              : []),
            ...(faAddressResources.capabilities.hasTransferRef
              ? [{ module: "FA", capability: "TransferRef (faAddress)", severity: "medium" as const }]
              : []),
            ...(faAddressResources.capabilities.hasDepositHook
              ? [{ module: "FA", capability: "DepositHook (faAddress)", severity: "medium" as const }]
              : []),
            ...(faAddressResources.capabilities.hasWithdrawHook
              ? [{ module: "FA", capability: "WithdrawHook (faAddress)", severity: "medium" as const }]
              : []),
          ]
        : []),
      // From creator address resources (if different)
      ...(creatorAddressResources?.capabilities
        ? [
            ...(creatorAddressResources.capabilities.hasMintRef
              ? [{ module: "Creator", capability: "MintRef (creatorAddress)", severity: "high" as const }]
              : []),
            ...(creatorAddressResources.capabilities.hasBurnRef
              ? [{ module: "Creator", capability: "BurnRef (creatorAddress)", severity: "medium" as const }]
              : []),
            ...(creatorAddressResources.capabilities.hasTransferRef
              ? [{ module: "Creator", capability: "TransferRef (creatorAddress)", severity: "medium" as const }]
              : []),
            ...(creatorAddressResources.capabilities.hasDepositHook
              ? [{ module: "Creator", capability: "DepositHook (creatorAddress)", severity: "medium" as const }]
              : []),
            ...(creatorAddressResources.capabilities.hasWithdrawHook
              ? [{ module: "Creator", capability: "WithdrawHook (creatorAddress)", severity: "medium" as const }]
              : []),
          ]
        : []),
    ],
    ownershipLinks: [
      // From FA address resources (ObjectCore.owner)
      ...(faAddressResources?.owner
        ? [
            {
              relatedAddress: faAddressResources.owner,
              relationship: "ObjectCore.owner (from fa_address_resources)",
            },
          ]
        : []),
      // From GetFaDetails (creatorAddress)
      ...(faDetails?.creatorAddress
        ? [
            {
              relatedAddress: faDetails.creatorAddress,
              relationship: "GetFaDetails.creatorAddress (from fa_details)",
            },
          ]
        : []),
      // From creator address resources (if different)
      ...(creatorAddressResources?.owner
        ? [
            {
              relatedAddress: creatorAddressResources.owner,
              relationship: "Owner (from creator_address_resources)",
            },
          ]
        : []),
    ],
    deploySignals: undefined,
    upgradeSignals: undefined,
  };

  // Section C: Cross-checks for FA
  const parityFlags: Level4Report["sectionC"]["parityFlags"] = [];

  // Check supply parity
  if (faMeta?.supplyParityCheck?.driftDetected) {
    parityFlags.push({
      flag: "INDEXER_SUPPLY_DRIFT_FA",
      severity: "warning",
      message: `Supply drift detected: ${faMeta.supplyParityCheck.likelyCause || "unknown"}. RPC: ${faMeta.supplyParityCheck.rpcSupply || "N/A"}, GraphQL: ${faMeta.supplyParityCheck.graphqlSupply || "N/A"}`,
    });
  }

  // Check supply metadata claims
  if (crossChecks && !crossChecks.supplyMetadataClaimsMatch) {
    parityFlags.push({
      flag: "SUPPLY_METADATA_MISMATCH",
      severity: "warning",
      message: crossChecks.supplyMetadataMismatchReason || "Supply metadata claims do not match",
    });
  }

  // Cross-check 1: creatorAddress (details) vs ObjectCore.owner (resources)
  if (crossChecks?.creatorAddressMatch === false || crossChecks?.creatorAddressMismatchReason) {
    parityFlags.push({
      flag: "CREATOR_ADDRESS_MISMATCH",
      severity: "warning",
      message: crossChecks.creatorAddressMismatchReason || "GetFaDetails.creatorAddress does not match AddressDetail.resources.ObjectCore.owner",
    });
  }

  // Cross-check 2: totalSupply (details) vs ConcurrentSupply.current.value (resources)
  if (crossChecks && !crossChecks.supplyMetadataClaimsMatch) {
    parityFlags.push({
      flag: "INDEXER_SUPPLY_DRIFT_FA",
      severity: "warning",
      message: crossChecks.supplyMetadataMismatchReason || "GetFaDetails.totalSupply does not match AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)",
    });
  }

  // Cross-check 3: verified/holders (details) vs "capabilities present" (resources)
  if (crossChecks?.verifiedVsCapabilitiesCheck?.mismatch) {
    parityFlags.push({
      flag: "VERIFIED_VS_CAPABILITIES_MISMATCH",
      severity: "info",
      message: crossChecks.verifiedVsCapabilitiesCheck.mismatch || `Verified status (GetFaDetails.verified=${crossChecks.verifiedVsCapabilitiesCheck.verified}) does not align with capabilities present in AddressDetail.resources`,
    });
  }

  const sectionC: Level4Report["sectionC"] = {
    moduleAddressMatchesCreator: true, // FA address is the token itself, not a module publisher
    relationshipExplanation: "FA address is the token metadata address, not a module publisher",
    // Cross-check 1: creatorAddress vs ObjectCore.owner
    creatorAddressMatch: crossChecks?.creatorAddressMatch,
    creatorAddressMismatchReason: crossChecks?.creatorAddressMismatchReason,
    // Cross-check 2: totalSupply vs ConcurrentSupply.current.value
    supplyMetadataClaimsMatch: crossChecks?.supplyMetadataClaimsMatch,
    supplyMetadataMismatchReason: crossChecks?.supplyMetadataMismatchReason,
    // Cross-check 3: verified/holders vs capabilities present
    verifiedVsCapabilitiesCheck: crossChecks?.verifiedVsCapabilitiesCheck,
    opaqueAbiButTradable: false, // Not applicable for FA (no module ABI)
    opaqueAbiExplanation: undefined,
    parityFlags,
  };

  return {
    sectionA,
    sectionB,
    sectionC,
  };
}

/**
 * Format Level 4 report as human-readable text
 * Optionally accepts ScanResult to show separate resource views
 */
export function formatLevel4ReportAsText(report: Level4Report, result?: ScanResult): string {
  const lines: string[] = [];

  lines.push("=".repeat(80));
  lines.push("LEVEL 4 (INDEXER & CONTEXTUAL PARITY) REPORT");
  lines.push("=".repeat(80));
  lines.push("");

  // Determine if this is an FA or Coin report
  const isFA = !report.sectionA.coinAddress.includes("::");
  
  // Section A: Token View (from GetFaDetails/GetCoinDetails)
  lines.push(isFA ? "SECTION A: TOKEN VIEW (GetFaDetails)" : "SECTION A: TOKEN VIEW (GetCoinDetails)");
  lines.push("-".repeat(80));
  lines.push("Token-facing metadata & stats from SupraScan GraphQL");
  lines.push(isFA 
    ? `FA Identity (FA Address): ${report.sectionA.coinAddress}`
    : `Coin Identity (Coin Type / "Coin Address"): ${report.sectionA.coinAddress}`);
  lines.push(isFA
    ? `  Note: This is an FA address (0x...), not a module publisher`
    : `  Note: This is a type string (0x...::module::COIN), not a wallet address`);
  lines.push("");
  
  // Show source for FA: fa_details (from GetFaDetails)
  if (isFA) {
    lines.push("Source: GetFaDetails(faAddress, blockchainEnvironment:\"mainnet\")");
    lines.push("  - Token metrics: faName, faSymbol, decimals, holders, verified, price, totalSupply, creatorAddress");
    lines.push("");
  } else {
    // Show source for Coin: coin_details (from GetCoinDetails)
    lines.push("Source: GetCoinDetails(coinAddress, blockchainEnvironment:\"mainnet\")");
    lines.push("  - Token metrics: name, symbol, decimals, holders, verified, price, totalSupply, creatorAddress");
    lines.push("");
  }
  if (report.sectionA.symbol) {
    lines.push(`Symbol: ${report.sectionA.symbol}`);
  }
  if (report.sectionA.decimals !== undefined) {
    lines.push(`Decimals: ${report.sectionA.decimals}`);
  }
  if (report.sectionA.supplyOnChainRpc !== undefined) {
    lines.push(isFA
      ? `On-chain supply (ConcurrentSupply/RPC-equivalent): ${report.sectionA.supplyOnChainRpc} (canonical on-chain supply, decimal-adjusted)`
      : `On-chain supply (RPC): ${report.sectionA.supplyOnChainRpc} (canonical on-chain supply)`);
  }
  if (report.sectionA.supplyIndexerGraphql !== undefined) {
    lines.push(isFA
      ? `Indexer supply (GetFaDetails.totalSupply): ${report.sectionA.supplyIndexerGraphql} (economic/UI supply, already decimal-adjusted)`
      : `Indexer-reported supply (GraphQL): ${report.sectionA.supplyIndexerGraphql} (economic/UI supply)`);
  }
  
  // For FA: Show capabilities summary
  if (isFA && report.sectionB.suspiciousAdminCapabilities && report.sectionB.suspiciousAdminCapabilities.length > 0) {
    lines.push("");
    lines.push(`Refs/Caps present:`);
    const capsByType: Record<string, string[]> = {};
    for (const cap of report.sectionB.suspiciousAdminCapabilities) {
      if (!capsByType[cap.capability]) {
        capsByType[cap.capability] = [];
      }
      capsByType[cap.capability].push(cap.severity);
    }
    for (const [capType, severities] of Object.entries(capsByType)) {
      const maxSeverity = severities.includes("high") ? "high" : severities.includes("medium") ? "medium" : "info";
      lines.push(`  - ${capType} (${maxSeverity})`);
    }
  }
  if (report.sectionA.maxSupply !== undefined) {
    lines.push(`Max supply: ${report.sectionA.maxSupply}`);
  }
  if (report.sectionA.holders !== undefined) {
    lines.push(`Holders: ${report.sectionA.holders}`);
  }
  if (report.sectionA.price) {
    lines.push(`Price: ${report.sectionA.price}`);
  }
  if (report.sectionA.coinMetadata?.name) {
    lines.push(`Name: ${report.sectionA.coinMetadata.name}`);
  }
  if (report.sectionA.coinMetadata?.verified !== undefined) {
    lines.push(`Verified: ${report.sectionA.coinMetadata.verified ? "Yes" : "No"}`);
  }
  if (report.sectionA.coinMetadata?.isDualNature) {
    lines.push(`Dual-nature asset: Yes`);
  }
  if (report.sectionA.supplyParity) {
    lines.push("");
    lines.push(`Supply Parity Check:`);
    lines.push(`  Drift detected: ${report.sectionA.supplyParity.driftDetected ? "YES ⚠️" : "NO ✓"}`);
    if (report.sectionA.supplyParity.driftDetected) {
      lines.push(`  Tolerance: ${report.sectionA.supplyParity.tolerance || "N/A"}`);
      if (report.sectionA.supplyParity.difference) {
        lines.push(`  Difference: ${report.sectionA.supplyParity.difference}`);
      }
      if (report.sectionA.supplyParity.differencePercentage !== undefined) {
        lines.push(`  Difference %: ${report.sectionA.supplyParity.differencePercentage.toFixed(2)}%`);
      }
      if (report.sectionA.supplyParity.likelyCause) {
        lines.push(`  Likely cause: ${report.sectionA.supplyParity.likelyCause}`);
      }
      if (report.sectionA.supplyParity.explanation) {
        lines.push(`  Explanation: ${report.sectionA.supplyParity.explanation}`);
      }
    }
  }
  lines.push("");

  // Section B: Publisher/Address View (from AddressDetail)
  lines.push(isFA ? "SECTION B: PUBLISHER/ADDRESS VIEW (AddressDetail)" : "SECTION B: PUBLISHER/ADDRESS VIEW (AddressDetail)");
  lines.push("-".repeat(80));
  lines.push("Actual on-chain resource surface + capability refs from SupraScan GraphQL");
  lines.push(isFA
    ? `Owner/Creator Address: ${report.sectionB.creatorAddress}`
    : `Creator/Publisher Address: ${report.sectionB.creatorAddress}`);
  lines.push(`  Note: This is an account address (0x...), not a token identifier`);
  lines.push("");
  
  // Show source
  if (isFA) {
    lines.push(`Source: AddressDetail(address:${report.sectionB.creatorAddress}, blockchainEnvironment:"mainnet")`);
    lines.push("  - Parsed from addressDetailSupra.resources (stringified JSON):");
    lines.push("    - ObjectCore.owner (canonical owner)");
    lines.push("    - ConcurrentSupply.current.value (on-chain supply)");
    lines.push("    - Mint/Burn/Transfer refs (capability evidence)");
    lines.push("    - Hooks (deposit/withdraw/dispatch function evidence)");
    lines.push("");
  } else {
    lines.push(`Source: AddressDetail(address:${report.sectionB.creatorAddress}, blockchainEnvironment:"mainnet")`);
    lines.push("  - Parsed from addressDetailSupra.resources (stringified JSON):");
    lines.push("    - Supply resources (on-chain supply)");
    lines.push("    - Mint/burn/freeze capabilities (admin capability evidence)");
    lines.push("    - Modules published (deployment evidence)");
    lines.push("");
  }
  if (report.sectionB.accountStatus) {
    lines.push(`Account status: ${report.sectionB.accountStatus}`);
  }
  if (report.sectionB.transactionCount !== undefined) {
    lines.push(`Transaction count: ${report.sectionB.transactionCount}`);
  }
  if (isFA) {
    // For FA: Show owner information
    if (report.sectionB.ownershipLinks && report.sectionB.ownershipLinks.length > 0) {
      const ownerLink = report.sectionB.ownershipLinks.find((l) => l.relationship.includes("ObjectCore.owner"));
      if (ownerLink) {
        lines.push(`Owner (ObjectCore.owner): ${ownerLink.relatedAddress} (canonical on-chain owner)`);
      }
    }
  } else {
    // For Coin: Show modules published
    if (report.sectionB.modulesPublishedCount !== undefined) {
      lines.push(`Modules published: ${report.sectionB.modulesPublishedCount}`);
      if (report.sectionB.modulesPublished && report.sectionB.modulesPublished.length > 0) {
        lines.push(`  Module names: ${report.sectionB.modulesPublished.join(", ")}`);
      }
    }
  }
  if (!isFA && report.sectionB.suspiciousAdminCapabilities && report.sectionB.suspiciousAdminCapabilities.length > 0) {
    lines.push("");
    lines.push(`Suspicious admin capabilities:`);
    for (const cap of report.sectionB.suspiciousAdminCapabilities) {
      lines.push(`  - ${cap.module}::${cap.capability} (${cap.severity})`);
    }
  }
  if (report.sectionB.ownershipLinks && report.sectionB.ownershipLinks.length > 0) {
    lines.push("");
    lines.push(`Ownership links:`);
    for (const link of report.sectionB.ownershipLinks) {
      lines.push(`  - ${link.relatedAddress} (${link.relationship})`);
    }
  }
  if (report.sectionB.deploySignals && report.sectionB.deploySignals.length > 0) {
    lines.push("");
    lines.push(`Deploy signals: ${report.sectionB.deploySignals.length} detected`);
    for (const signal of report.sectionB.deploySignals.slice(0, 5)) {
      lines.push(`  - ${signal.timestamp || "unknown"} ${signal.module || ""} ${signal.transactionHash ? `(${signal.transactionHash.slice(0, 8)}...)` : ""}`);
    }
  }
  if (report.sectionB.upgradeSignals && report.sectionB.upgradeSignals.length > 0) {
    lines.push("");
    lines.push(`Upgrade signals: ${report.sectionB.upgradeSignals.length} detected`);
    for (const signal of report.sectionB.upgradeSignals.slice(0, 5)) {
      lines.push(`  - ${signal.timestamp || "unknown"} ${signal.module || ""} ${signal.transactionHash ? `(${signal.transactionHash.slice(0, 8)}...)` : ""}`);
    }
  }
  lines.push("");

  // Show merged evidence: "Token View" + "Publisher/Address View"
  if (result) {
    lines.push("");
    lines.push("=".repeat(80));
    lines.push("MERGED EVIDENCE: TOKEN VIEW + PUBLISHER/ADDRESS VIEW");
    lines.push("=".repeat(80));
    lines.push("");
    lines.push("This section shows both views merged together for complete context:");
    lines.push(isFA 
      ? "  - Token View: GetFaDetails(faAddress, blockchainEnvironment:\"mainnet\") - Token-facing metadata & stats"
      : "  - Token View: GetCoinDetails(coinAddress, blockchainEnvironment:\"mainnet\") - Token-facing metadata & stats");
    lines.push("  - Publisher/Address View: AddressDetail(address, blockchainEnvironment:\"mainnet\") - Actual on-chain resource surface + capability refs");
    lines.push("");
    lines.push("-".repeat(80));
    lines.push("");

    if (isFA && result.meta.fa_metadata) {
      const faMeta = result.meta.fa_metadata;
      
      // fa_details (from GetFaDetails)
      if (faMeta.fa_details) {
        lines.push("fa_details (from GetFaDetails):");
        const faDetails = faMeta.fa_details;
        if (faDetails.faName) lines.push(`  faName: ${faDetails.faName}`);
        if (faDetails.faSymbol) lines.push(`  faSymbol: ${faDetails.faSymbol}`);
        if (faDetails.decimals !== undefined) lines.push(`  decimals: ${faDetails.decimals}`);
        if (faDetails.holders !== undefined) lines.push(`  holders: ${faDetails.holders}`);
        if (faDetails.verified !== undefined) lines.push(`  verified: ${faDetails.verified}`);
        if (faDetails.price) lines.push(`  price: ${faDetails.price}`);
        if (faDetails.totalSupply) lines.push(`  totalSupply: ${faDetails.totalSupply} (already decimal-adjusted)`);
        if (faDetails.creatorAddress) lines.push(`  creatorAddress: ${faDetails.creatorAddress}`);
        lines.push("");
      }

      // fa_address_resources (from AddressDetail on faAddress)
      if (faMeta.fa_address_resources) {
        lines.push("fa_address_resources (AddressDetail on faAddress):");
        const faAddrRes = faMeta.fa_address_resources;
        lines.push(`  address: ${faAddrRes.address}`);
        if (faAddrRes.owner) lines.push(`  owner (ObjectCore.owner): ${faAddrRes.owner}`);
        if (faAddrRes.supplyCurrent) lines.push(`  supplyCurrent (raw base units): ${faAddrRes.supplyCurrent}`);
        if (faAddrRes.supplyCurrentDecimalAdjusted) lines.push(`  supplyCurrent (decimal-adjusted): ${faAddrRes.supplyCurrentDecimalAdjusted}`);
        if (faAddrRes.capabilities) {
          lines.push(`  capabilities:`);
          const caps = faAddrRes.capabilities;
          if (caps.hasMintRef) lines.push(`    - MintRef: true`);
          if (caps.hasBurnRef) lines.push(`    - BurnRef: true`);
          if (caps.hasTransferRef) lines.push(`    - TransferRef: true`);
          if (caps.hasDepositHook) lines.push(`    - DepositHook: true`);
          if (caps.hasWithdrawHook) lines.push(`    - WithdrawHook: true`);
          if (caps.hasDispatchFunctions) lines.push(`    - DispatchFunctions: true`);
        }
        lines.push("");
      }

      // creator_address_resources (from AddressDetail on creatorAddress when different)
      if (faMeta.creator_address_resources) {
        lines.push("creator_address_resources (AddressDetail on creatorAddress):");
        const creatorAddrRes = faMeta.creator_address_resources;
        lines.push(`  address: ${creatorAddrRes.address}`);
        if (creatorAddrRes.owner) lines.push(`  owner: ${creatorAddrRes.owner}`);
        if (creatorAddrRes.modulesPublished) {
          lines.push(`  modulesPublished: ${creatorAddrRes.modulesPublished.join(", ")}`);
          if (creatorAddrRes.modulesPublishedCount !== undefined) {
            lines.push(`  modulesPublishedCount: ${creatorAddrRes.modulesPublishedCount}`);
          }
        }
        if (creatorAddrRes.capabilities) {
          lines.push(`  capabilities:`);
          const caps = creatorAddrRes.capabilities;
          if (caps.hasMintRef) lines.push(`    - MintRef: true`);
          if (caps.hasBurnRef) lines.push(`    - BurnRef: true`);
          if (caps.hasTransferRef) lines.push(`    - TransferRef: true`);
          if (caps.hasDepositHook) lines.push(`    - DepositHook: true`);
          if (caps.hasWithdrawHook) lines.push(`    - WithdrawHook: true`);
          if (caps.hasDispatchFunctions) lines.push(`    - DispatchFunctions: true`);
        }
        lines.push("");
      }
    } else if (!isFA && result.meta.coin_metadata) {
      const coinMeta = result.meta.coin_metadata;
      
      // coin_details (from GetCoinDetails)
      if (coinMeta.coin_details) {
        lines.push("coin_details (from GetCoinDetails):");
        const coinDetails = coinMeta.coin_details;
        if (coinDetails.name) lines.push(`  name: ${coinDetails.name} (GraphQL field: name, NOT coinName)`);
        if (coinDetails.symbol) lines.push(`  symbol: ${coinDetails.symbol} (GraphQL field: symbol, NOT coinSymbol)`);
        if (coinDetails.assetAddress) lines.push(`  assetAddress: ${coinDetails.assetAddress} (GraphQL field: assetAddress, NOT coinAddress)`);
        if (coinDetails.decimals !== undefined) lines.push(`  decimals: ${coinDetails.decimals}`);
        if (coinDetails.holders !== undefined) lines.push(`  holders: ${coinDetails.holders}`);
        if (coinDetails.verified !== undefined) lines.push(`  verified: ${coinDetails.verified}`);
        if (coinDetails.price) lines.push(`  price: ${coinDetails.price}`);
        if (coinDetails.totalSupply) lines.push(`  totalSupply: ${coinDetails.totalSupply} (indexer-reported)`);
        if (coinDetails.creatorAddress) lines.push(`  creatorAddress: ${coinDetails.creatorAddress}`);
        lines.push("");
      }

      // coin_publisher_address_resources (from AddressDetail on publisherAddress)
      if (coinMeta.coin_publisher_address_resources) {
        lines.push("coin_publisher_address_resources (AddressDetail on publisherAddress):");
        const publisherAddrRes = coinMeta.coin_publisher_address_resources;
        lines.push(`  address: ${publisherAddrRes.address}`);
        lines.push(`  Parsed from addressDetailSupra.resources (stringified JSON):`);
        if (publisherAddrRes.owner) lines.push(`    - ObjectCore.owner: ${publisherAddrRes.owner} (canonical owner)`);
        if (publisherAddrRes.supplyCurrent) lines.push(`    - CoinInfo<T>.supply.value (raw base units): ${publisherAddrRes.supplyCurrent}`);
        if (publisherAddrRes.capabilities) {
          lines.push(`    - Capabilities (mint/burn/transfer refs, hooks):`);
          const caps = publisherAddrRes.capabilities;
          if (caps.hasMintCap) lines.push(`      - MintCap: true`);
          if (caps.hasBurnCap) lines.push(`      - BurnCap: true`);
          if (caps.hasFreezeCap) lines.push(`      - FreezeCap: true`);
          if (caps.hasTransferRestrictions) lines.push(`      - TransferRestrictions: true`);
          if (caps.owner) lines.push(`      - owner: ${caps.owner}`);
          if (caps.admin) lines.push(`      - admin: ${caps.admin}`);
        }
        lines.push("");
      }

      // coin_creator_address_resources (from AddressDetail on creatorAddress)
      if (coinMeta.coin_creator_address_resources) {
        lines.push("coin_creator_address_resources (AddressDetail on creatorAddress):");
        const creatorAddrRes = coinMeta.coin_creator_address_resources;
        lines.push(`  address: ${creatorAddrRes.address}`);
        lines.push(`  Parsed from addressDetailSupra.resources (stringified JSON):`);
        if (creatorAddrRes.owner) lines.push(`    - ObjectCore.owner: ${creatorAddrRes.owner}`);
        if (creatorAddrRes.modulesPublished) {
          lines.push(`    - Modules published: ${creatorAddrRes.modulesPublished.join(", ")}`);
          if (creatorAddrRes.modulesPublishedCount !== undefined) {
            lines.push(`      Count: ${creatorAddrRes.modulesPublishedCount}`);
          }
        }
        if (creatorAddrRes.capabilities) {
          lines.push(`    - Capabilities (mint/burn/transfer refs, hooks):`);
          const caps = creatorAddrRes.capabilities;
          if (caps.hasMintCap) lines.push(`      - MintCap: true`);
          if (caps.hasBurnCap) lines.push(`      - BurnCap: true`);
          if (caps.hasFreezeCap) lines.push(`      - FreezeCap: true`);
          if (caps.hasTransferRestrictions) lines.push(`      - TransferRestrictions: true`);
          if (caps.owner) lines.push(`      - owner: ${caps.owner}`);
          if (caps.admin) lines.push(`      - admin: ${caps.admin}`);
        }
        lines.push("");
      }
    }
  }
  lines.push("");

  // Section C: Cross-checks - "Token View" vs "Publisher/Address View"
  lines.push("SECTION C: CROSS-CHECKS (Token View vs Publisher/Address View)");
  lines.push("-".repeat(80));
  if (isFA) {
    lines.push("Cross-check GetFaDetails (token-facing metadata & stats) vs AddressDetail (actual on-chain resource surface + capability refs)");
    lines.push("Compares: Token View (GetFaDetails) vs Publisher/Address View (AddressDetail)");
  } else {
    lines.push("Cross-check GetCoinDetails (token-facing metadata & stats) vs AddressDetail (actual on-chain resource surface + capability refs)");
    lines.push("Compares: Token View (GetCoinDetails) vs Publisher/Address View (AddressDetail)");
  }
  lines.push("");
  
  if (report.sectionC.moduleAddressMatchesCreator !== undefined && !isFA) {
    lines.push(`Module address matches creator: ${report.sectionC.moduleAddressMatchesCreator ? "YES ✓" : "NO"}`);
    if (report.sectionC.relationshipExplanation) {
      lines.push(`  ${report.sectionC.relationshipExplanation}`);
    }
    lines.push("");
  }

  // Cross-check 1: creatorAddress (details) vs ObjectCore.owner (resources) - FA only
  if (isFA && report.sectionC.creatorAddressMatch !== undefined) {
    if (report.sectionC.creatorAddressMatch === false) {
      lines.push("⚠️ Cross-check 1: Creator Address Mismatch (CREATOR_ADDRESS_MISMATCH):");
      lines.push(`  ${report.sectionC.creatorAddressMismatchReason || "GetFaDetails.creatorAddress does not match AddressDetail.resources.ObjectCore.owner"}`);
    } else {
      lines.push("✓ Cross-check 1: Creator Address Match:");
      lines.push(`  GetFaDetails.creatorAddress matches AddressDetail.resources.ObjectCore.owner`);
    }
    lines.push("");
  }

  // Cross-check 2: totalSupply (details) vs ConcurrentSupply.current.value (resources) - FA only
  if (isFA && report.sectionC.supplyMetadataClaimsMatch !== undefined) {
    if (report.sectionC.supplyMetadataClaimsMatch === false) {
      lines.push("⚠️ Cross-check 2: Supply Mismatch (INDEXER_SUPPLY_DRIFT_FA):");
      lines.push(`  ${report.sectionC.supplyMetadataMismatchReason || "GetFaDetails.totalSupply does not match AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)"}`);
    } else {
      lines.push("✓ Cross-check 2: Supply Match:");
      lines.push(`  GetFaDetails.totalSupply matches AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)`);
    }
    lines.push("");
  } else if (!isFA && report.sectionC.supplyMetadataClaimsMatch !== undefined) {
    lines.push(`Supply/metadata claims match: ${report.sectionC.supplyMetadataClaimsMatch ? "YES ✓" : "NO ⚠️"}`);
    if (report.sectionC.supplyMetadataMismatchReason) {
      lines.push(`  ${report.sectionC.supplyMetadataMismatchReason}`);
    }
    lines.push("");
  }

  // Cross-check 3: verified/holders (details) vs "capabilities present" (resources) - FA only
  if (isFA && report.sectionC.verifiedVsCapabilitiesCheck) {
    const vcCheck = report.sectionC.verifiedVsCapabilitiesCheck;
    lines.push("Cross-check 3: Verified vs Capabilities Check:");
    lines.push(`  GetFaDetails.verified: ${vcCheck.verified !== undefined ? (vcCheck.verified ? "Yes" : "No") : "N/A"}`);
    lines.push(`  GetFaDetails.holders: ${vcCheck.holders !== undefined ? vcCheck.holders : "N/A"}`);
    lines.push(`  AddressDetail.resources capabilities present: ${vcCheck.hasCapabilities ? "Yes" : "No"}`);
    if (vcCheck.capabilitiesPresent) {
      const caps = vcCheck.capabilitiesPresent;
      const capList: string[] = [];
      if (caps.hasMintRef) capList.push("MintRef");
      if (caps.hasBurnRef) capList.push("BurnRef");
      if (caps.hasTransferRef) capList.push("TransferRef");
      if (caps.hasDepositHook) capList.push("DepositHook");
      if (caps.hasWithdrawHook) capList.push("WithdrawHook");
      if (caps.hasDispatchFunctions) capList.push("DispatchFunctions");
      if (capList.length > 0) {
        lines.push(`    Capabilities found: ${capList.join(", ")}`);
      }
    }
    if (vcCheck.mismatch) {
      lines.push(`  ⚠️ Mismatch (VERIFIED_VS_CAPABILITIES_MISMATCH): ${vcCheck.mismatch}`);
    } else {
      lines.push(`  ✓ Verified status aligns with capabilities present`);
    }
    lines.push("");
  }

  if (!isFA && report.sectionC.opaqueAbiButTradable !== undefined) {
    lines.push(`Opaque ABI but tradable: ${report.sectionC.opaqueAbiButTradable ? "YES ⚠️" : "NO ✓"}`);
    if (report.sectionC.opaqueAbiExplanation) {
      lines.push(`  ${report.sectionC.opaqueAbiExplanation}`);
    }
    lines.push("");
  }
  if (report.sectionC.parityFlags && report.sectionC.parityFlags.length > 0) {
    lines.push("");
    lines.push(`Parity Flags:`);
    for (const flag of report.sectionC.parityFlags) {
      const icon = flag.severity === "error" ? "🚨" : flag.severity === "warning" ? "⚠️" : "ℹ️";
      lines.push(`  ${icon} [${flag.flag}] ${flag.message}`);
    }
  }
  lines.push("");
  lines.push("=".repeat(80));

  return lines.join("\n");
}

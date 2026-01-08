/**
 * Coin Token Scanner for Supra Move Coin tokens (legacy coin standard)
 * Scans Coin tokens using on-chain data only (no source files required)
 * Coin type format: 0xPUBLISHER::MODULE::STRUCT
 */

import type { ScanResult, Finding, Verdict, VerdictTier, ModuleId, SurfaceAreaReport, Severity } from "./types.js";
import { viewFunctionRawRpc } from "../rpc/viewRpc.js";
import { fetchCoinDetailsFromSupraScan, fetchAllTransactionsFromSupraScan } from "../rpc/supraScanGraphql.js";
import { fetchAccountModulesV3, fetchAccountModuleV3 } from "../rpc/supraAccountsV3.js";
import { fetchAccountResourcesV3 } from "../rpc/supraResourcesV3.js";
import { fetchAddressDetailSupra } from "../adapters/suprascanGraphql.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import { getIsoTimestamp } from "../utils/time.js";
import { randomUUID } from "crypto";
import { calculateSeverityCounts, calculateRiskScore, calculateBadgeEligibility } from "./scoring.js";
import { scanAbiForCapabilities, scanBytecodeForCapabilities, extractEntryFunctionsFromAbi } from "./surface.js";
import { analyzeCoinResources } from "../analyzers/coin/analyzeCoinResources.js";

export interface CoinTokenMetadata {
  coinType: string; // Full struct tag: 0xPUBLISHER::MODULE::STRUCT
  publisherAddress: string;
  moduleName: string;
  structName: string;
  name?: string;
  symbol?: string;
  decimals?: number;
  totalSupply?: string | number;
  creator?: string;
  holdersCount?: number;
  fetchMethod?: string; // "supra_framework_coin_views" | "suprascan_graphql"
  fetchError?: string;
  // Optional SupraScan-specific fields
  iconUrl?: string;
  verified?: boolean;
  price?: string | number;
  isDualNature?: boolean; // True if coin is also an FA
  faAddress?: string; // FA address if dual-nature
  // Level 4 fields (minimal addition for type compatibility)
  supplyIndexerGraphql?: string | number;
  supplyOnChainRpc?: string | number;
  coin_creator_address_transactions?: any;
  supplyParityCheck?: any;
  // Level 4: Separate resource views (paired evidence bundle)
  coin_details?: {
    name?: string;
    symbol?: string;
    verified?: boolean;
    holders?: number;
    creatorAddress?: string;
    totalSupply?: string | number;
    iconUrl?: string;
  };
  coin_publisher_address_resources?: any;
  coin_creator_address_resources?: any;
  // RPC plan debug info
  rpcPlan?: {
    provider_chain: string[];
    v3_modules?: { url?: string; used: boolean };
    suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
    framework_views_enabled: boolean;
    framework_views_success?: boolean;
    suprascan_graphql_success?: boolean;
    bytecode_fetch_success?: boolean;
  };
}

export interface CoinScanOptions {
  rpc_url?: string;
  proxy_base?: string;
}

/**
 * Parse coin type into components
 * Format: 0xPUBLISHER::MODULE::STRUCT
 */
export function parseCoinType(coinType: string): {
  publisherAddress: string;
  moduleName: string;
  structName: string;
} {
  const parts = coinType.split("::");
  if (parts.length !== 3) {
    throw new Error(`Invalid coin type format: ${coinType}. Expected format: 0xPUBLISHER::MODULE::STRUCT`);
  }
  
  return {
    publisherAddress: parts[0],
    moduleName: parts[1],
    structName: parts[2],
  };
}

/**
 * Fetch Coin token metadata from Supra RPC and SupraScan GraphQL
 */
export async function fetchCoinMetadata(
  coinType: string,
  rpcUrl: string
): Promise<CoinTokenMetadata> {
  const parsed = parseCoinType(coinType);
  
  const metadata: CoinTokenMetadata = {
    coinType,
    publisherAddress: parsed.publisherAddress,
    moduleName: parsed.moduleName,
    structName: parsed.structName,
  };

  // RPC Plan: Track exact RPC calls made (Level-1 scan plan)
  const normalizedRpcUrl = rpcUrl.replace(/\/+$/, "");
  const rpcPlan: CoinTokenMetadata["rpcPlan"] = {
    provider_chain: [],
    v3_modules: {
      url: `${normalizedRpcUrl}/rpc/v3/accounts/${parsed.publisherAddress}/modules`,
      used: false,
    },
    suprascan_graphql: {
      url: process.env.SUPRASCAN_GRAPHQL_URL || "https://suprascan.io/api/graphql",
      queryName: "GetCoinDetails",
      used: false,
    },
    framework_views_enabled: false,
  };

  // Debug toggle
  const debug =
    process.env.SSA_DEBUG_VIEW === "1" ||
    process.env.SSA_DEBUG_COIN === "1" ||
    process.env.DEBUG_VIEW === "1";

  // OPTIONAL: Try Supra framework coin views (feature-flagged)
  // Default: disabled to avoid noisy failing calls
  const enableFrameworkViews = process.env.COIN_ENABLE_FRAMEWORK_VIEWS === "1";
  rpcPlan.framework_views_enabled = enableFrameworkViews;
  let viewsSucceeded = 0;

  if (enableFrameworkViews) {
    rpcPlan.provider_chain.push("framework_views");
    
    const frameworkCoinViews = [
      { name: "name", fn: `0x1::coin::name` },
      { name: "symbol", fn: `0x1::coin::symbol` },
      { name: "decimals", fn: `0x1::coin::decimals` },
      { name: "supply", fn: `0x1::coin::supply` },
    ];

    for (const view of frameworkCoinViews) {
      try {
        // Framework coin views use type arguments only
        const result = await viewFunctionRawRpc(
          normalizedRpcUrl,
          `${view.fn}<${coinType}>`,
          [], // No runtime arguments
          [coinType] // Type argument
        );

        const parsedResult = result?.result;
        let value = parsedResult;
        if (Array.isArray(value)) {
          value = value[0];
        } else if (value && typeof value === "object" && value.result !== undefined) {
          value = Array.isArray(value.result) ? value.result[0] : value.result;
        }

        if (value !== null && value !== undefined) {
          viewsSucceeded++;
          
          if (view.name === "name") {
            metadata.name = String(value);
          } else if (view.name === "symbol") {
            metadata.symbol = String(value);
          } else if (view.name === "decimals") {
            metadata.decimals = Number(value);
          } else if (view.name === "supply") {
            metadata.totalSupply = String(value);
          }
        }
      } catch (error) {
        if (debug) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          console.debug(`Coin view ${view.name} failed: ${errorMsg}`);
        }
      }
    }

    if (viewsSucceeded > 0) {
      metadata.fetchMethod = "supra_framework_coin_views";
      rpcPlan.framework_views_success = true;
    } else {
      rpcPlan.framework_views_success = false;
    }
  }

  // ============================================================================
  // LEVEL 4: Two GraphQL Fetch Paths from SupraScan (ALWAYS RUN BOTH)
  // ============================================================================
  // Path 1: Token/Coin details query (from token page)
  //   - Legacy coin: GetCoinDetails(coinType, blockchainEnvironment)
  //   - Returns: name/symbol/decimals/totalSupply/holders/creatorAddress/etc.
  // Path 2: Address resources query (from wallet/creator page)
  //   - AddressDetail(address, blockchainEnvironment, isAddressName, ...)
  //   - Returns: addressDetailSupra.resources (stringified JSON) with on-chain capability surface
  // Both outputs are merged into one report for cross-checking "claims vs on-chain reality"
  // ============================================================================

  // STEP 1: Path 1 - Token/Coin details query (GetCoinDetails) - ALWAYS
  // This represents INDEXER / UI / ECONOMIC SUPPLY and metadata claims
  rpcPlan.provider_chain.push("suprascan_graphql");
  rpcPlan.suprascan_graphql!.used = true;
  rpcPlan.suprascan_graphql!.queryName = "GetCoinDetails"; // Track operation name
  const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet").toLowerCase() as "mainnet" | "testnet";
  
  const suprascanData = await fetchCoinDetailsFromSupraScan(coinType, suprascanEnv);
  let graphqlSupply: string | number | undefined = undefined;

  // LEVEL 4: Store GetCoinDetails separately as coin_details (paired evidence bundle)
  // IMPORTANT: Field names match actual GraphQL API:
  // - name (NOT coinName)
  // - symbol (NOT coinSymbol)  
  // - assetAddress (NOT coinAddress)
  const coinDetails: CoinTokenMetadata["coin_details"] = suprascanData
    ? {
        name: suprascanData.name, // GraphQL field: name
        symbol: suprascanData.symbol, // GraphQL field: symbol
        verified: suprascanData.verified,
        holders: suprascanData.holders,
        creatorAddress: suprascanData.creatorAddress ? String(suprascanData.creatorAddress) : undefined,
        totalSupply: suprascanData.totalSupply ? String(suprascanData.totalSupply) : undefined, // Indexer-reported supply
        iconUrl: undefined, // Not available from GetCoinDetails
      }
    : undefined;

  if (suprascanData) {
    // Map SupraScan data to metadata (for other fields, still allow fallback)
    if (suprascanData.name && !metadata.name) {
      metadata.name = suprascanData.name;
    }
    if (suprascanData.symbol && !metadata.symbol) {
      metadata.symbol = suprascanData.symbol;
    }
    if (suprascanData.decimals !== undefined && metadata.decimals === undefined) {
      metadata.decimals = Number(suprascanData.decimals);
    }
    // LEVEL 4: Store GraphQL supply separately (never overwrite)
    if (suprascanData.totalSupply) {
      graphqlSupply = String(suprascanData.totalSupply);
      metadata.supplyIndexerGraphql = graphqlSupply;
      // Also set legacy totalSupply for backward compatibility (but don't overwrite if RPC already set)
      if (!metadata.totalSupply) {
        metadata.totalSupply = graphqlSupply;
      }
    }
    if (suprascanData.creatorAddress && !metadata.creator) {
      metadata.creator = String(suprascanData.creatorAddress);
    }
    if (suprascanData.holders !== undefined && metadata.holdersCount === undefined) {
      metadata.holdersCount = Number(suprascanData.holders);
    }
    
    // Optional SupraScan-specific fields
    if (suprascanData.iconUrl) {
      metadata.iconUrl = suprascanData.iconUrl;
    }
    if (suprascanData.verified !== undefined) {
      metadata.verified = suprascanData.verified;
    }
    if (suprascanData.price) {
      metadata.price = String(suprascanData.price);
    }

    if (
      metadata.symbol ||
      metadata.decimals !== undefined ||
      metadata.supplyIndexerGraphql ||
      metadata.name
    ) {
      metadata.fetchMethod = "suprascan_graphql";
      rpcPlan.suprascan_graphql!.used = true;
      rpcPlan.suprascan_graphql_success = true;
    } else {
      rpcPlan.suprascan_graphql!.used = false;
      rpcPlan.suprascan_graphql_success = false;
    }
  } else {
    rpcPlan.suprascan_graphql!.used = false;
    rpcPlan.suprascan_graphql_success = false;
  }

  // Store coin_details separately
  metadata.coin_details = coinDetails;

  // STEP 2: Path 2 - Address resources query (AddressDetail) - ALWAYS
  // Fetch AddressDetail for publisher address to get on-chain CoinInfo<T> resources (on-chain truth)
  // This represents CANONICAL ON-CHAIN SUPPLY and capability reality
  let rpcSupply: string | number | undefined = undefined;
  let rpcDecimals: number | undefined = metadata.decimals;
  
  // Publisher Address Resources (AddressDetail on publisher address)
  let publisherAddressResources: {
    address: string;
    resources?: string;
    owner?: string;
    supplyCurrent?: string;
    capabilities?: {
      hasMintCap: boolean;
      hasBurnCap: boolean;
      hasFreezeCap: boolean;
      hasTransferRestrictions: boolean;
      owner?: string;
      admin?: string;
    };
  } | undefined = undefined;

  try {
    // Fetch AddressDetail for publisher address (where coin module is published)
    const publisherAddressDetail = await fetchAddressDetailSupra(parsed.publisherAddress, suprascanEnv);
    
    if (publisherAddressDetail && !publisherAddressDetail.isError && publisherAddressDetail.addressDetailSupra?.resources) {
      const resourcesStr = publisherAddressDetail.addressDetailSupra.resources;
      
      if (resourcesStr && typeof resourcesStr === "string" && resourcesStr.trim().length > 0) {
        // Analyze resources to extract CoinInfo<T>, mint/burn/transfer refs, hooks, ObjectCore.owner
        const resourceAnalysis = analyzeCoinResources(resourcesStr, coinType);
        
        publisherAddressResources = {
          address: parsed.publisherAddress,
          resources: resourcesStr,
          owner: resourceAnalysis.caps.owner || undefined,
          supplyCurrent: resourceAnalysis.caps.supplyCurrentBase || undefined,
          capabilities: {
            hasMintCap: resourceAnalysis.caps.hasMintCap,
            hasBurnCap: resourceAnalysis.caps.hasBurnCap,
            hasFreezeCap: resourceAnalysis.caps.hasFreezeCap,
            hasTransferRestrictions: resourceAnalysis.caps.hasTransferRestrictions,
            owner: resourceAnalysis.caps.owner || undefined,
            admin: resourceAnalysis.caps.admin || undefined,
          },
        };
        
        // Extract on-chain supply from CoinInfo<T> resource
        if (resourceAnalysis.caps.supplyCurrentBase) {
          rpcSupply = resourceAnalysis.caps.supplyCurrentBase;
          metadata.supplyOnChainRpc = rpcSupply;
          // Also set legacy totalSupply for backward compatibility (but prefer RPC if both exist)
          metadata.totalSupply = rpcSupply;
          
          // Extract decimals from resources if available
          if (resourceAnalysis.caps.decimals !== null && resourceAnalysis.caps.decimals !== undefined) {
            rpcDecimals = resourceAnalysis.caps.decimals;
            if (metadata.decimals === undefined) {
              metadata.decimals = rpcDecimals;
            }
          }
        }
      }
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.SSA_DEBUG_COIN === "1";
    if (debug) {
      console.debug(`[Coin] AddressDetail fetch for publisher address failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Store publisher address resources separately
  if (publisherAddressResources) {
    metadata.coin_publisher_address_resources = {
      address: publisherAddressResources.address,
      resources: publisherAddressResources.resources,
      owner: publisherAddressResources.owner,
      supplyCurrent: publisherAddressResources.supplyCurrent,
      capabilities: publisherAddressResources.capabilities,
    };
  }

  // STEP 3: Level 4 Parity Evaluation
  // Compare RPC supply vs GraphQL supply and flag INDEXER_SUPPLY_DRIFT if difference exceeds tolerance
  const tolerance = process.env.SSA_SUPPLY_TOLERANCE ? Number(process.env.SSA_SUPPLY_TOLERANCE) : 0.01; // Default 1% tolerance
  const supplyParityCheck: typeof metadata.supplyParityCheck = {
    driftDetected: false,
    tolerance,
    rpcSupply: rpcSupply !== undefined ? String(rpcSupply) : undefined,
    graphqlSupply: graphqlSupply !== undefined ? String(graphqlSupply) : undefined,
  };

  if (rpcSupply !== undefined && graphqlSupply !== undefined) {
    try {
      const rpcSupplyNum = typeof rpcSupply === "string" ? parseFloat(rpcSupply) : Number(rpcSupply);
      const graphqlSupplyNum = typeof graphqlSupply === "string" ? parseFloat(graphqlSupply) : Number(graphqlSupply);
      
      if (!isNaN(rpcSupplyNum) && !isNaN(graphqlSupplyNum) && rpcSupplyNum > 0) {
        const absoluteDifference = Math.abs(rpcSupplyNum - graphqlSupplyNum);
        const percentageDifference = (absoluteDifference / rpcSupplyNum) * 100;
        
        supplyParityCheck.difference = String(absoluteDifference);
        supplyParityCheck.differencePercentage = percentageDifference;
        
        // Flag drift if difference exceeds tolerance (default 1%)
        if (percentageDifference > (tolerance * 100)) {
          supplyParityCheck.driftDetected = true;
          
          // Explain likely cause
          if (percentageDifference > 10) {
            supplyParityCheck.likelyCause = "significant_drift";
          } else if (rpcDecimals !== undefined && metadata.decimals !== undefined && rpcDecimals !== metadata.decimals) {
            supplyParityCheck.likelyCause = "decimals_mismatch";
          } else if (metadata.isDualNature) {
            supplyParityCheck.likelyCause = "dual_nature_asset";
          } else {
            supplyParityCheck.likelyCause = "indexer_lag_or_burned_escrow";
          }
        }
      }
    } catch (error) {
      // Parity check calculation failed, but don't fail the scan
      if (process.env.SSA_DEBUG_COIN === "1") {
        console.debug(`[Coin] Supply parity check calculation failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } else if (rpcSupply !== undefined || graphqlSupply !== undefined) {
    // Only one source available - still store but note the missing source
    supplyParityCheck.likelyCause = "single_source_only";
  }

  metadata.supplyParityCheck = supplyParityCheck;

  // STEP 3: Fetch AddressDetail for creator address - ALWAYS (Level 4 requirement: paired evidence bundle)
  // AddressDetail(address=creator) using creator wallet address to capture resource/capability reality
  const creatorAddress = metadata.creator || parsed.publisherAddress;
  let creatorAddressResources: typeof metadata.coin_creator_address_resources | undefined = undefined;

  if (creatorAddress) {
    try {
      const normalizedCreatorAddress = creatorAddress.toLowerCase().startsWith("0x")
        ? creatorAddress.toLowerCase()
        : `0x${creatorAddress.toLowerCase()}`;

      const creatorAddressDetail = await fetchAddressDetailSupra(normalizedCreatorAddress, suprascanEnv);

      if (creatorAddressDetail && !creatorAddressDetail.isError && creatorAddressDetail.addressDetailSupra?.resources) {
        const resourcesStr = creatorAddressDetail.addressDetailSupra.resources;

        if (resourcesStr && typeof resourcesStr === "string" && resourcesStr.trim().length > 0) {
          // Analyze resources to extract capabilities from creator wallet
          const resourceAnalysis = analyzeCoinResources(resourcesStr, coinType);

          creatorAddressResources = {
            address: normalizedCreatorAddress,
            resources: resourcesStr,
            owner: resourceAnalysis.caps.owner || undefined,
            capabilities: {
              hasMintCap: resourceAnalysis.caps.hasMintCap,
              hasBurnCap: resourceAnalysis.caps.hasBurnCap,
              hasFreezeCap: resourceAnalysis.caps.hasFreezeCap,
              hasTransferRestrictions: resourceAnalysis.caps.hasTransferRestrictions,
              owner: resourceAnalysis.caps.owner || undefined,
              admin: resourceAnalysis.caps.admin || undefined,
            },
            modulesPublished: undefined, // Will be populated later if needed
            modulesPublishedCount: undefined,
          };
        }
      }
    } catch (error) {
      const debug = process.env.SSA_DEBUG_COIN === "1";
      if (debug) {
        console.debug(`[Coin] AddressDetail fetch for creator address failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // Store creator address resources separately
  metadata.coin_creator_address_resources = creatorAddressResources;

  // STEP 4: Fetch GetAllTransactions for creator address (supporting evidence) - ALWAYS
  const lastNTxs = parseInt(process.env.SSA_TX_LIMIT || "10", 10); // Default: last 10 transactions
  
  if (creatorAddress) {
    try {
      const creatorAddressTxs = await fetchAllTransactionsFromSupraScan({
        blockchainEnvironment: suprascanEnv,
        address: creatorAddress.toLowerCase().startsWith("0x")
          ? creatorAddress.toLowerCase()
          : `0x${creatorAddress.toLowerCase()}`,
        page: 1,
        rowsPerPage: lastNTxs,
      });

      if (creatorAddressTxs && creatorAddressTxs.transactions) {
        metadata.coin_creator_address_transactions = {
          address: creatorAddress,
          transactions: creatorAddressTxs.transactions
            .slice(0, lastNTxs)
            .map((tx) => ({
              transactionHash: tx.transactionHash || "",
              senderAddress: tx.senderAddress || "",
              receiverAddress: tx.receiverAddress || null,
              transferAmount: tx.transferAmount || "0",
              confirmationTime: tx.confirmationTime || null,
              transactionStatus: tx.transactionStatus || "unknown",
              functionName: tx.functionName || null,
              type: tx.type || null,
            })),
          totalItems: creatorAddressTxs.totalItems,
          foundCount: creatorAddressTxs.foundCount,
        };
      }
    } catch (error) {
      const debug = process.env.SSA_DEBUG_COIN === "1";
      if (debug) {
        console.debug(`[Coin] GetAllTransactions fetch for creator address failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // Store RPC plan in metadata
  metadata.rpcPlan = rpcPlan;

  return metadata;
}

/**
 * LEVEL 4: Fetch Creator/Publisher Account Facts
 * Fetch wallet account data: status, tx count, modules published, suspicious admin capabilities, ownership links, deploy/upgrade signals
 */
async function fetchCreatorAccountData(
  creatorAddress: string,
  rpcUrl: string,
  suprascanEnv: "mainnet" | "testnet"
): Promise<{
  address: string;
  accountStatus?: "active" | "inactive" | "unknown";
  transactionCount?: number;
  modulesPublished?: string[];
  modulesPublishedCount?: number;
  suspiciousAdminCapabilities?: Array<{
    module: string;
    capability: string;
    severity: Severity;
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
}> {
  const normalizedAddress = creatorAddress.toLowerCase().startsWith("0x")
    ? creatorAddress.toLowerCase()
    : `0x${creatorAddress.toLowerCase()}`;

  // Fix: Use Awaited to unwrap Promise type, or define shape directly
  const accountData: Awaited<ReturnType<typeof fetchCreatorAccountData>> = {
    address: normalizedAddress,
    accountStatus: "unknown",
    modulesPublished: [],
    suspiciousAdminCapabilities: [],
    ownershipLinks: [],
    deploySignals: [],
    upgradeSignals: [],
  };

  const rpcOptions: RpcClientOptions = {
    rpcUrl,
    timeout: 10000,
    retries: 2,
    retryDelay: 500,
  };

  try {
    // Fetch modules published at creator address
    const moduleListResponse = await fetchAccountModulesV3(normalizedAddress, rpcOptions);
    if (moduleListResponse.modules && moduleListResponse.modules.length > 0) {
      accountData.accountStatus = "active";
      accountData.modulesPublished = moduleListResponse.modules.map((m) => m.name || m.abi?.name || "unknown").filter((n) => n !== "unknown");
      accountData.modulesPublishedCount = accountData.modulesPublished.length;
      
      // Scan for suspicious admin capabilities in published modules
      for (const module of moduleListResponse.modules) {
        if (module.abi?.exposed_functions) {
          const dangerousPatterns = ["mint", "burn", "freeze", "pause", "blacklist", "admin", "owner", "upgrade"];
          const moduleName = module.name || module.abi?.name || "unknown";
          
          for (const func of module.abi.exposed_functions) {
            const funcName = func.name?.toLowerCase() || "";
            const matchedPatterns = dangerousPatterns.filter((pattern) => funcName.includes(pattern));
            
            if (matchedPatterns.length > 0) {
              // Check for gating markers
              const gatingMarkers = ["only_admin", "only_owner", "require_admin", "assert_owner"];
              const hasGating = gatingMarkers.some((marker) => funcName.includes(marker));
              
              if (!hasGating) {
                accountData.suspiciousAdminCapabilities!.push({
                  module: moduleName,
                  capability: func.name || funcName,
                  severity: matchedPatterns.includes("mint") || matchedPatterns.includes("burn") ? "high" : "medium",
                });
              }
            }
          }
        }
      }
    } else {
      accountData.accountStatus = "inactive";
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_COIN === "1";
    if (debug) {
      console.debug(`[Coin] Failed to fetch creator account modules: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  try {
    // Fetch transaction count from SupraScan GraphQL (best-effort)
    const txData = await fetchAllTransactionsFromSupraScan({
      blockchainEnvironment: suprascanEnv,
      address: normalizedAddress,
      page: 1,
      rowsPerPage: 1,
    });
    
    if (txData && !txData.isError) {
      accountData.transactionCount = txData.totalItems || 0;
      
      // Extract deploy/upgrade signals from transactions (best-effort, limited by pagination)
      // Note: Full analysis would require scanning all transactions, which is expensive
      for (const tx of txData.transactions.slice(0, 10)) { // Only check first 10
        if (tx.functionName && (tx.functionName.toLowerCase().includes("publish") || tx.functionName.toLowerCase().includes("deploy"))) {
          accountData.deploySignals!.push({
            timestamp: tx.confirmationTime || undefined,
            transactionHash: tx.transactionHash || undefined,
            module: tx.functionName || undefined,
          });
        }
        if (tx.functionName && tx.functionName.toLowerCase().includes("upgrade")) {
          accountData.upgradeSignals!.push({
            timestamp: tx.confirmationTime || undefined,
            transactionHash: tx.transactionHash || undefined,
            module: tx.functionName || undefined,
          });
        }
      }
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_COIN === "1";
    if (debug) {
      console.debug(`[Coin] Failed to fetch creator account transactions: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return accountData;
}

/**
 * Scan Coin token
 */
export async function scanCoinToken(
  coinType: string,
  options: CoinScanOptions = {}
): Promise<ScanResult> {
  const startTime = Date.now();
  const requestId = randomUUID();
  const timestamp = getIsoTimestamp();
  const rpcUrl = options.rpc_url || process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
  const proxyBase = options.proxy_base || process.env.PROD_API;

  // Parse coin type
  let parsed: { publisherAddress: string; moduleName: string; structName: string };
  try {
    parsed = parseCoinType(coinType);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    return {
      request_id: requestId,
      target: {
        chain: "supra",
        module_address: "unknown",
        module_name: "coin_token",
        module_id: `unknown::coin_token`,
      },
      scan_level: "quick",
      timestamp_iso: timestamp,
      engine: {
        name: "ssa-scanner",
        version: "0.1.0",
        ruleset_version: "move-ruleset-0.1.0",
      },
      artifact: {
        fetch_method: "rpc",
        artifact_hash: `coin_${coinType}`,
        binding_note: `Coin token scan for ${coinType}`,
        metadata: {},
      },
      summary: {
        risk_score: 0,
        verdict: "inconclusive",
        severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        badge_eligibility: {
          scanned: false,
          no_critical: true,
          security_verified: false,
          continuously_monitored: false,
          reasons: [`Invalid coin type format: ${errorMsg}`],
        },
        capabilities: {
          poolStats: false,
          totalStaked: false,
          queue: false,
          userViews: false,
        },
      },
      findings: [],
      meta: {
        scan_options: options,
        rpc_url: rpcUrl,
        duration_ms: Date.now() - startTime,
        verdict_reason: `Invalid coin type format: ${errorMsg}`,
      },
    };
  }

  // Fetch metadata (includes Level 4 dual supply tracking + AddressDetail for creator)
  const metadata = await fetchCoinMetadata(coinType, rpcUrl);
  const hasMetadata = !!(metadata.symbol || metadata.decimals !== undefined || metadata.totalSupply || metadata.supplyOnChainRpc || metadata.supplyIndexerGraphql || metadata.name);
  const rpcPlan = metadata.rpcPlan; // Extract RPC plan from metadata
  const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet").toLowerCase() as "mainnet" | "testnet";

  // LEVEL 4: Fetch Creator/Publisher Account Facts (separate from coin stats)
  // Note: creator address resources may already be in metadata.coin_creator_address_resources from fetchCoinMetadata
  const creatorAddress = metadata.creator || parsed.publisherAddress;
  const creatorAccountData = await fetchCreatorAccountData(creatorAddress, rpcUrl, suprascanEnv);
  
  // Merge AddressDetail resources into creatorAccountData if available (paired evidence bundle)
  if (metadata.coin_creator_address_resources) {
    // Merge capabilities from AddressDetail resources if available
    if (metadata.coin_creator_address_resources.capabilities) {
      const addrCapabilities = metadata.coin_creator_address_resources.capabilities;
      // Add to suspiciousAdminCapabilities if not already present
      const existingCapabilities = creatorAccountData.suspiciousAdminCapabilities || [];
      const newCapabilities = [];
      
      if (addrCapabilities.hasMintCap) {
        if (!existingCapabilities.some((c) => c.capability.includes("mint"))) {
          newCapabilities.push({ module: "Coin", capability: "MintCap", severity: "high" as Severity });
        }
      }
      if (addrCapabilities.hasBurnCap) {
        if (!existingCapabilities.some((c) => c.capability.includes("burn"))) {
          newCapabilities.push({ module: "Coin", capability: "BurnCap", severity: "medium" as Severity });
        }
      }
      if (addrCapabilities.hasFreezeCap) {
        if (!existingCapabilities.some((c) => c.capability.includes("freeze"))) {
          newCapabilities.push({ module: "Coin", capability: "FreezeCap", severity: "medium" as Severity });
        }
      }
      
      creatorAccountData.suspiciousAdminCapabilities = [...existingCapabilities, ...newCapabilities];
    }
    
    // Use modules from AddressDetail resources if available
    if (metadata.coin_creator_address_resources.modulesPublished) {
      creatorAccountData.modulesPublished = metadata.coin_creator_address_resources.modulesPublished;
      creatorAccountData.modulesPublishedCount = metadata.coin_creator_address_resources.modulesPublishedCount;
    }
    
    // Use owner from AddressDetail resources if available
    if (metadata.coin_creator_address_resources.owner) {
      creatorAccountData.ownershipLinks = [
        ...(creatorAccountData.ownershipLinks || []),
        {
          relatedAddress: metadata.coin_creator_address_resources.owner,
          relationship: "Owner from AddressDetail resources",
        },
      ];
    }
  }
  
  // LEVEL 4: Cross-checks (initial setup, will be updated later)
  const crossChecks: {
    moduleAddressMatchesCreator: boolean;
    relationshipExplanation: string;
    supplyMetadataClaimsMatch: boolean;
    supplyMetadataMismatchReason?: string;
    opaqueAbiButTradable: boolean;
    opaqueAbiExplanation?: string;
  } = {
    moduleAddressMatchesCreator: parsed.publisherAddress.toLowerCase() === creatorAddress.toLowerCase(),
    relationshipExplanation: parsed.publisherAddress.toLowerCase() === creatorAddress.toLowerCase()
      ? "Coin's module address matches creator address"
      : `Coin's module address (${parsed.publisherAddress}) differs from creator address (${creatorAddress}). This is normal if the creator deployed modules at a different address.`,
    supplyMetadataClaimsMatch: metadata.supplyParityCheck?.driftDetected === false,
    supplyMetadataMismatchReason: metadata.supplyParityCheck?.driftDetected
      ? `Supply drift detected: ${metadata.supplyParityCheck.likelyCause || "unknown"} (RPC: ${metadata.supplyParityCheck.rpcSupply || "N/A"}, GraphQL: ${metadata.supplyParityCheck.graphqlSupply || "N/A"})`
      : undefined,
    opaqueAbiButTradable: false, // Will be set later based on surface report
    opaqueAbiExplanation: undefined, // Will be set later based on surface report
  };

  // Fetch bytecode/ABI from publisher address (hybrid mode)
  // Collect ALL modules from publisher (important for backdoor scan)
  // Do NOT filter to moduleName - treat ALL returned modules as the publisher surface
  let hasBytecodeOrSource = false;
  let hasAbi = false;
  let modulesExist = false;
  let allPublisherModules: Array<{ name: string; bytecode?: string; abi?: any }> = [];
  let scannedModulesCount = 0; // Modules with bytecode/ABI
  let totalModulesCount = 0; // Total modules at publisher address
  
  const rpcOptions: RpcClientOptions = {
    rpcUrl,
    timeout: 10000,
    retries: 2,
    retryDelay: 500,
  };

  try {
    // Fetch ALL modules from publisher address (important for backdoor scan)
    // RPC call: GET {RPC}/rpc/v3/accounts/{publisher}/modules
    if (rpcPlan) {
      rpcPlan.v3_modules!.used = true;
      rpcPlan.provider_chain.push("v3_modules");
    }
    
    const moduleListResponse = await fetchAccountModulesV3(parsed.publisherAddress, rpcOptions);
    if (moduleListResponse.modules && moduleListResponse.modules.length > 0) {
      modulesExist = true;
      totalModulesCount = moduleListResponse.modules.length;
      
      // LEVEL 1: Collect ALL modules (NO FILTERING)
      // Enumerate every module returned by RPC - this is deterministic enumeration
      allPublisherModules = moduleListResponse.modules.map((m) => ({
        name: m.name || m.abi?.name || "unknown",
        bytecode: m.bytecode,
        abi: m.abi,
      })).filter((m) => m.name !== "unknown"); // Only filter out truly unknown names
      
      // Count modules with bytecode/ABI (must have bytecode OR abi to count as scanned)
      for (const module of allPublisherModules) {
        if (module.bytecode || module.abi) {
          scannedModulesCount++;
          if (module.bytecode) {
            hasBytecodeOrSource = true;
          }
          if (module.abi) {
            hasAbi = true;
          }
        }
      }
      
      // Update total count to match actual collected modules
      totalModulesCount = allPublisherModules.length;
      
      // If target module not in list, fetch it directly (but still include all others)
      const targetModuleExists = allPublisherModules.some((m) => 
        m.name === parsed.moduleName || m.abi?.name === parsed.moduleName
      );
      
      if (!targetModuleExists) {
        const moduleResponse = await fetchAccountModuleV3(
          parsed.publisherAddress,
          parsed.moduleName,
          rpcOptions
        );
        
        if (moduleResponse.module) {
          allPublisherModules.push({
            name: parsed.moduleName,
            bytecode: moduleResponse.module.bytecode,
            abi: moduleResponse.module.abi,
          });
          totalModulesCount++;
          
          if (moduleResponse.module.bytecode || moduleResponse.module.abi) {
            scannedModulesCount++;
            if (moduleResponse.module.bytecode) {
              hasBytecodeOrSource = true;
            }
            if (moduleResponse.module.abi) {
              hasAbi = true;
            }
          }
        }
      }
    } else {
      // No modules found
      if (rpcPlan) {
        rpcPlan.v3_modules!.used = false;
      }
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.SSA_DEBUG_COIN === "1";
    if (debug) {
      console.debug(`[Coin] Module fetch failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (rpcPlan) {
      rpcPlan.v3_modules!.used = false;
    }
  }

  // Coin-specific rules: Analyze bytecode/ABI for dangerous patterns
  // Scan ALL modules from publisher (not just target module)
  const coinFindings: Finding[] = [];

  // LEVEL 1: Build Surface Area Report
  const surfaceReport: SurfaceAreaReport = {
    kind: "coin",
    publisher: parsed.publisherAddress,
    modules_total: totalModulesCount,
    modules_list: allPublisherModules.map((m) => m.name),
    entry_functions_by_module: {},
    exposed_functions_empty_modules: [],
    capability_hits_by_module: {},
    capability_hits_total: 0,
    opaque_abi: {
      flagged: false,
      severity: "medium",
      reason: "",
    },
  };

  // Try to load SupraScan evidence if available (do not fail if absent)
  try {
    const suprascanEvidencePath = process.env.SUPRASCAN_EVIDENCE_PATH;
    if (suprascanEvidencePath) {
      const { readFileSync } = await import("fs");
      try {
        const enrichedEvidence = JSON.parse(readFileSync(suprascanEvidencePath, "utf-8"));
        if (enrichedEvidence.kind === "coin" && enrichedEvidence.flags && enrichedEvidence.risk) {
          surfaceReport.suprascan_evidence = {
            flags: enrichedEvidence.flags,
            risk: enrichedEvidence.risk,
          };
        }
      } catch (fileError) {
        // File doesn't exist or is invalid - silently continue
      }
    }
  } catch (error) {
    // SupraScan evidence not available - silently continue (do not fail)
    // This is expected if SupraScan evidence file doesn't exist
  }

  // Enumerate entry functions and capabilities for each module
  let totalEntryFunctions = 0;
  for (const module of allPublisherModules) {
    const moduleName = module.name;
    
    // Extract entry functions from ABI
    const entryFunctions = extractEntryFunctionsFromAbi(module.abi);
    if (entryFunctions.length > 0) {
      surfaceReport.entry_functions_by_module![moduleName] = entryFunctions;
      totalEntryFunctions += entryFunctions.length;
    } else if (module.abi && Array.isArray(module.abi.exposed_functions) && module.abi.exposed_functions.length === 0) {
      // ABI exists but exposed_functions is empty
      surfaceReport.exposed_functions_empty_modules!.push(moduleName);
    }
    
    // Scan for capability patterns
    const capabilityHits: string[] = [];
    if (module.abi) {
      capabilityHits.push(...scanAbiForCapabilities(module.abi));
    }
    if (module.bytecode) {
      const bytecodeBuffer = typeof module.bytecode === "string" 
        ? Buffer.from(module.bytecode.replace(/^0x/, ""), "hex")
        : Buffer.isBuffer(module.bytecode) 
          ? module.bytecode 
          : null;
      if (bytecodeBuffer) {
        capabilityHits.push(...scanBytecodeForCapabilities(bytecodeBuffer));
      } else {
        capabilityHits.push(...scanBytecodeForCapabilities(module.bytecode));
      }
    }
    
    if (capabilityHits.length > 0) {
      surfaceReport.capability_hits_by_module![moduleName] = capabilityHits;
      surfaceReport.capability_hits_total! += capabilityHits.length;
    }
  }
  
  surfaceReport.entry_functions_total = totalEntryFunctions;

  // Opaque ABI Detection (MEDIUM severity)
  // Check if token appears tradable and has opaque ABI
  let isTradable = false;
  let tradableSignal = "unknown";
  
  // Check SupraScan metadata for price
  if (metadata.price) {
    isTradable = true;
    tradableSignal = "suprascan_price";
  } else if (process.env.SSA_ASSUME_TRADABLE === "1") {
    isTradable = true;
    tradableSignal = "env_flag";
  }
  
  const hasOpaqueAbi = 
    (totalEntryFunctions === 0 && modulesExist) ||
    (surfaceReport.exposed_functions_empty_modules!.length > 0);
  
  if (isTradable && hasOpaqueAbi) {
    surfaceReport.opaque_abi!.flagged = true;
    surfaceReport.opaque_abi!.signal_tradable = tradableSignal;
    surfaceReport.opaque_abi!.affected_modules = surfaceReport.exposed_functions_empty_modules!.length > 0
      ? surfaceReport.exposed_functions_empty_modules
      : surfaceReport.modules_list;
    surfaceReport.opaque_abi!.reason = `Token appears tradable (signal: ${tradableSignal}) but has opaque ABI: ${totalEntryFunctions === 0 ? "no entry functions found" : "modules with empty exposed_functions"}`;
    
    // LEVEL 4: Update cross-checks
    crossChecks.opaqueAbiButTradable = true;
    crossChecks.opaqueAbiExplanation = surfaceReport.opaque_abi!.reason;
    
    // Add finding for opaque ABI
    coinFindings.push({
      id: "SSA-L1-OPAQUE-ABI",
      title: "Opaque ABI Detected (Tradable Token)",
      severity: "medium",
      confidence: 0.8,
      description: surfaceReport.opaque_abi!.reason,
      recommendation: "Verify that entry functions are properly exposed in ABI. Opaque ABIs prevent visibility into token behavior.",
      evidence: {
        kind: "abi_pattern",
        matched: ["opaque_abi", "no_entry_functions"],
        locations: surfaceReport.opaque_abi!.affected_modules!.map((mod) => ({
          fn: `${parsed.publisherAddress}::${mod}`,
          note: "Module with opaque ABI",
        })),
      },
      references: [],
    });
  } else {
    surfaceReport.opaque_abi!.reason = isTradable 
      ? "ABI is transparent (entry functions visible)"
      : `Tradable status unknown (signal: ${tradableSignal})`;
    crossChecks.opaqueAbiExplanation = surfaceReport.opaque_abi!.reason;
  }

  // Analyze bytecode/ABI for dangerous patterns (mint, burn, freeze, pause, blacklist, admin, owner, upgrade)
  const dangerousPatterns = ["mint", "burn", "freeze", "pause", "blacklist", "admin", "owner", "upgrade"];
  const gatingMarkers = ["only_admin", "only_owner", "require_admin", "assert_owner", "check_capability", "verify_signer"];
  
  if (hasBytecodeOrSource || hasAbi) {
    // Scan ALL publisher modules (not just target module)
    for (const module of allPublisherModules) {
      // Analyze module ABI
      if (module.abi?.exposed_functions) {
        for (const func of module.abi.exposed_functions) {
          const funcName = func.name?.toLowerCase() || "";
          const matchedPatterns = dangerousPatterns.filter((pattern) => funcName.includes(pattern));
          
          if (matchedPatterns.length > 0) {
            // Check for gating markers in function name or ABI
            const hasGating = 
              gatingMarkers.some((marker) => funcName.includes(marker)) ||
              (func.params?.some((p: any) => typeof p === "string" && gatingMarkers.some((marker) => p.toLowerCase().includes(marker))));
            
            if (!hasGating) {
              // Check bytecode strings if available
              let bytecodeHasGating = false;
              if (module.bytecode) {
                const bytecodeLower = module.bytecode.toLowerCase();
                bytecodeHasGating = gatingMarkers.some((marker) => bytecodeLower.includes(marker));
              }
              
              if (!bytecodeHasGating) {
                coinFindings.push({
                  id: "COIN-SEC-001",
                  title: "Dangerous Function Without Clear Access Control",
                  severity: matchedPatterns.includes("mint") || matchedPatterns.includes("burn") ? "high" : "medium",
                  confidence: module.abi ? 0.8 : 0.6,
                  description: `Module "${module.name}" contains exposed function "${func.name}" matching dangerous patterns (${matchedPatterns.join(", ")}) but lacks clear gating mechanisms (admin/owner checks, capability verification).`,
                  recommendation: "Implement strict access control checks (e.g., `only_admin`, `only_owner`, capability checks) for functions that modify token state or configuration.",
                  evidence: {
                    kind: module.abi ? "abi_pattern" : "bytecode_pattern",
                    matched: matchedPatterns,
                    locations: [{ fn: `${parsed.publisherAddress}::${module.name}::${func.name}`, note: "Function matches dangerous pattern without clear gating" }],
                  },
                  references: [],
                });
              }
            }
          }
        }
      }
      
      // Analyze bytecode strings for dangerous patterns (if no ABI)
      if (module.bytecode && !module.abi) {
        const bytecodeLower = module.bytecode.toLowerCase();
        const dangerousStrings = dangerousPatterns.filter((pattern) => bytecodeLower.includes(pattern));
        const gatingStrings = gatingMarkers.filter((marker) => bytecodeLower.includes(marker));
        
        // If we find dangerous patterns but no gating, raise concern
        if (dangerousStrings.length > 0 && gatingStrings.length === 0) {
          coinFindings.push({
            id: "COIN-SEC-002",
            title: "Potential Dangerous Patterns in Bytecode",
            severity: "medium",
            confidence: 0.5,
            description: `Module "${module.name}" bytecode contains patterns (${dangerousStrings.join(", ")}) that may indicate dangerous functions, but no clear gating mechanisms detected. ABI analysis recommended for accurate assessment.`,
            recommendation: "Review module ABI or source code to verify access control mechanisms for functions matching these patterns.",
            evidence: {
              kind: "bytecode_pattern",
              matched: dangerousStrings,
              locations: [{ fn: `${parsed.publisherAddress}::${module.name}`, note: "Module bytecode analysis" }],
            },
            references: [],
          });
        }
      }
    }
  }
  
  // Metadata validation
  if (!hasMetadata) {
    coinFindings.push({
      id: "COIN-META-001",
      title: "Missing or Incomplete Metadata",
      severity: "low",
      confidence: 0.9,
      description: `Coin metadata is missing or incomplete. Missing: ${[
        !metadata.symbol && "symbol",
        metadata.decimals === undefined && "decimals",
        !metadata.totalSupply && "totalSupply",
      ].filter(Boolean).join(", ")}`,
      recommendation: "Ensure all standard coin metadata fields are available via view functions or indexer.",
      evidence: {
        kind: "metadata",
        matched: [],
        locations: [],
      },
      references: [],
    });
  }

  // Gate HIGH/CRITICAL findings: only allow if bytecode/ABI present
  const filteredFindings = coinFindings.filter((f) => {
    if ((f.severity === "high" || f.severity === "critical") && !hasBytecodeOrSource) {
      return false;
    }
    return true;
  });

  const severityCounts = calculateSeverityCounts(filteredFindings);
  let riskScore = calculateRiskScore(filteredFindings);

  // Determine verdict with explicit tiers
  // Verdict PASS only means "no high-risk patterns found in available on-chain publisher modules + metadata"
  // Code-Verified only if ALL modules scanned with bytecode
  const allModulesScanned = modulesExist && scannedModulesCount === totalModulesCount && totalModulesCount > 0;
  const partialCoverage = modulesExist && scannedModulesCount < totalModulesCount && totalModulesCount > 0;
  
  // Determine assurance level
  let assuranceLevel: "metadata_only" | "adjacent_code_inspected" | "code_verified";
  if (allModulesScanned && hasBytecodeOrSource) {
    assuranceLevel = "code_verified";
  } else {
    assuranceLevel = "metadata_only";
  }
  
  let verdict: Verdict = "inconclusive";
  let verdictTier: VerdictTier = "inconclusive";
  let verdictReason: string | undefined;

  if (!hasMetadata) {
    verdict = "inconclusive";
    verdictTier = "inconclusive";
    verdictReason = `Coin metadata unavailable via RPC views/indexer. ${metadata.fetchError || "No metadata found"}`;
  } else if (partialCoverage) {
    // Partial module coverage - cannot be Code-Verified
    verdict = "inconclusive";
    verdictTier = "metadata";
    verdictReason = `Partial module coverage: scanned_modules=${scannedModulesCount} / total_modules=${totalModulesCount}. Code-Verified requires all modules to be scanned with bytecode.`;
  } else if (allModulesScanned && hasBytecodeOrSource && severityCounts.critical === 0 && severityCounts.high === 0) {
    // Code-verified PASS (all modules scanned)
    verdict = "pass";
    verdictTier = "verified";
    assuranceLevel = "code_verified";
    verdictReason = `Code-Verified: no high-risk patterns detected in scanned publisher modules. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
  } else if (allModulesScanned && hasBytecodeOrSource && (severityCounts.critical > 0 || severityCounts.high > 0)) {
    // Code-verified FAIL (all modules scanned but findings)
    verdict = "fail";
    verdictTier = "fail";
    assuranceLevel = "code_verified";
    verdictReason = `Code-verified scan detected high/critical findings in publisher modules.`;
  } else if (!hasBytecodeOrSource && filteredFindings.every((f) => f.severity === "low" || f.severity === "info")) {
    // Metadata-only PASS
    verdict = "pass";
    verdictTier = "metadata";
    assuranceLevel = "metadata_only";
    const isSupraScanMetadata = metadata.fetchMethod === "suprascan_graphql";
    const evidenceSource = isSupraScanMetadata
      ? "Metadata fetched via SupraScan GraphQL (public indexer); code-level verification requires bytecode/ABI."
      : "Code-level security verification requires bytecode/ABI.";
    verdictReason = `Metadata Verified only (indexer/RPC). Code not verified. ${evidenceSource}`;
  } else {
    // Metadata-only with findings
    verdict = "inconclusive";
    verdictTier = "metadata";
    const isSupraScanMetadata = metadata.fetchMethod === "suprascan_graphql";
    const evidenceSource = isSupraScanMetadata
      ? "Metadata fetched via SupraScan GraphQL (public indexer); code-level verification requires bytecode/ABI."
      : "Code-level security verification requires bytecode/ABI.";
    verdictReason = `Metadata scan completed with findings. ${evidenceSource}`;
  }

  const duration = Date.now() - startTime;

  // Get engine version
  function getEngineVersion(): string {
    try {
      const { readFileSync } = require("fs");
      const { fileURLToPath } = require("url");
      const { dirname, join } = require("path");
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = dirname(__filename);
      const packagePath = join(__dirname, "../../package.json");
      const pkg = JSON.parse(readFileSync(packagePath, "utf-8"));
      return pkg.version || "0.1.0";
    } catch {
      return "0.1.0";
    }
  }

  return {
    request_id: requestId,
    target: {
      chain: "supra",
      module_address: parsed.publisherAddress,
      module_name: parsed.moduleName,
      module_id: `${parsed.publisherAddress}::${parsed.moduleName}`,
    },
    scan_level: "quick",
    timestamp_iso: timestamp,
    engine: {
      name: "ssa-scanner",
      version: getEngineVersion(),
      ruleset_version: "move-ruleset-0.1.0",
    },
    artifact: {
      fetch_method: "rpc",
      artifact_hash: `coin_${coinType}`,
      binding_note: `Coin token scan for ${coinType}`,
      metadata: {
        coin_metadata: metadata,
        metadata_fetch_method: metadata.fetchMethod || "unknown",
        metadata_fetch_error: metadata.fetchError,
      },
    },
    summary: {
      risk_score: riskScore,
      verdict,
      severity_counts: severityCounts,
      badge_eligibility: calculateBadgeEligibility(
        "quick",
        `coin_${coinType}`,
        severityCounts,
        timestamp,
        hasBytecodeOrSource
      ),
      capabilities: {
        poolStats: false,
        totalStaked: false,
        queue: false,
        userViews: false,
      },
      assurance_level: assuranceLevel,
    },
    findings: filteredFindings,
    meta: {
      scan_options: options,
      rpc_url: rpcUrl,
      duration_ms: duration,
      artifact_mode: hasBytecodeOrSource ? "view_plus_onchain_module" : "view_only",
      artifact_loaded: false,
      artifact_components: {
        hasSource: false,
        hasAbi: hasAbi,
        hasBytecode: hasBytecodeOrSource,
        origin: {
          kind: "manual",
          path: "coin_metadata_only",
        },
        onChainBytecodeFetched: hasBytecodeOrSource,
      },
      rule_capabilities: {
        viewOnly: !hasBytecodeOrSource,
        hasAbi: hasAbi,
        hasBytecodeOrSource: hasBytecodeOrSource,
        artifactMode: hasBytecodeOrSource ? "view_plus_onchain_module" : "view_only",
      },
      verdict_reason: verdictReason,
      verdict_tier: verdictTier,
      security_verified: allModulesScanned && hasBytecodeOrSource && severityCounts.critical === 0 && severityCounts.high === 0,
      metadata_verified: hasMetadata,
      code_verified: allModulesScanned && hasBytecodeOrSource,
      coin_metadata: metadata,
      coin_modules_exist: modulesExist,
      coin_bytecode_fetched: hasBytecodeOrSource,
      coin_publisher_modules: allPublisherModules.map((m) => m.name),
      coin_publisher_modules_count: totalModulesCount,
      coin_scanned_modules_count: scannedModulesCount,
      coin_rpc_plan: metadata.rpcPlan,
      surface_report: surfaceReport,
      // LEVEL 4: Creator/Publisher Account Facts
      coin_creator_account: creatorAccountData,
      // LEVEL 4: Cross-checks
      coin_cross_checks: crossChecks,
    },
  };
}


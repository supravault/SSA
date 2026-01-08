/**
 * FA Token Scanner for Supra Move FA tokens
 * Scans FA tokens using on-chain data only (no source files required)
 * FA address is a metadata address, NOT a module publisher
 */

import type { ModuleId, ScanResult, Finding, Verdict, VerdictTier, SurfaceAreaReport } from "./types.js";
import { fetchResourcesV1 } from "../rpc/supraResourcesV1.js";
import { fetchFaDetailsFromSupraScan, fetchFaHoldersFromSupraScan, fetchAllTransactionsFromSupraScan } from "../rpc/supraScanGraphql.js";
import { fetchAccountModulesV3 } from "../rpc/supraAccountsV3.js";
import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";
import type { Finding as FaResourceFinding } from "../analyzers/fa/analyzeFaResources.js";
import { fetchAccountResourcesV3 } from "../rpc/supraResourcesV3.js";
import { fetchAddressDetailSupra } from "../adapters/suprascanGraphql.js";
import { runScan } from "./scanner.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import { getIsoTimestamp } from "../utils/time.js";
import { randomUUID } from "crypto";
import { calculateSeverityCounts, calculateRiskScore, calculateBadgeEligibility } from "./scoring.js";
import { createRequire } from "module";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

export interface FATokenMetadata {
  address: string;
  creator?: string;
  symbol?: string;
  decimals?: number;
  totalSupply?: string | number;
  holdersCount?: number;
  name?: string;
  fetchMethod?: string; // "supra_framework_fa_views" | "supra_rpc_v1_resources" | "suprascan_graphql"
  fetchError?: string;
  // Optional SupraScan-specific fields
  iconUrl?: string;
  verified?: boolean;
  isDualNature?: boolean;
  // Level 4: Dual supply tracking (never overwrite, always show both)
  supplyOnChainRpc?: string | number; // On-chain supply from ConcurrentSupply (canonical, decimal-adjusted)
  supplyIndexerGraphql?: string | number; // Indexer-reported supply from GetFaDetails (economic/UI, already decimal-adjusted)
  ownerOnChain?: string; // Owner from ObjectCore.owner (canonical)
  capabilitiesSummary?: {
    hasMintRef: boolean;
    hasBurnRef: boolean;
    hasTransferRef: boolean;
    hasDepositHook: boolean;
    hasWithdrawHook: boolean;
    hasDispatchFunctions: boolean;
  };
  supplyParityCheck?: {
    driftDetected: boolean;
    tolerance?: string | number;
    rpcSupply?: string | number;
    graphqlSupply?: string | number;
    difference?: string | number;
    differencePercentage?: number;
    likelyCause?: string;
  };
  // Level 4: Separate resource views (paired evidence bundle)
  fa_details?: {
    faName?: string;
    faSymbol?: string;
    decimals?: number;
    holders?: number;
    verified?: boolean;
    price?: string | number;
    totalSupply?: string | number;
    creatorAddress?: string;
  };
  fa_address_resources?: {
    address: string;
    resources?: string;
    owner?: string;
    supplyCurrent?: string;
    supplyCurrentDecimalAdjusted?: string | number;
    capabilities?: {
      hasMintRef: boolean;
      hasBurnRef: boolean;
      hasTransferRef: boolean;
      hasDepositHook: boolean;
      hasWithdrawHook: boolean;
      hasDispatchFunctions: boolean;
    };
  };
  creator_address_resources?: {
    address: string;
    resources?: string;
    owner?: string;
    capabilities?: {
      hasMintRef: boolean;
      hasBurnRef: boolean;
      hasTransferRef: boolean;
      hasDepositHook: boolean;
      hasWithdrawHook: boolean;
      hasDispatchFunctions: boolean;
    };
    modulesPublished?: string[];
    modulesPublishedCount?: number;
  };
  fa_address_transactions?: {
    address: string;
    transactions?: Array<{
      transactionHash?: string;
      senderAddress?: string;
      receiverAddress?: string;
      transferAmount?: string;
      confirmationTime?: string;
      transactionStatus?: string;
      functionName?: string;
      type?: string;
    }>;
    totalItems?: number;
    foundCount?: number;
  };
  creator_address_transactions?: {
    address: string;
    transactions?: Array<{
      transactionHash?: string;
      senderAddress?: string;
      receiverAddress?: string;
      transferAmount?: string;
      confirmationTime?: string;
      transactionStatus?: string;
      functionName?: string;
      type?: string;
    }>;
    totalItems?: number;
    foundCount?: number;
  };
  // RPC plan debug info (attached by fetchFAMetadata)
  rpcPlan?: {
    provider_chain: string[];
    resources_endpoint?: string;
    resources_success?: boolean;
    framework_views_enabled: boolean;
    framework_views_success?: boolean;
    suprascan_graphql_success?: boolean;
  };
}

export interface FAScanOptions {
  rpc_url?: string;
  proxy_base?: string;
  fa_owner?: string; // Optional owner address for owner-specific checks
}

/**
 * Fetch FA token metadata from Supra RPC
 * Uses Supra framework FA module view functions
 * FA metadata address is NOT a module publisher - use framework FA module views
 * 
 * Supra framework FA views require BOTH:
 * - exactly 1 type_argument (generic T) - the Move struct tag like "0x...::module::TYPE"
 * - exactly 1 runtime argument (string) - either TARGET_COIN_TYPE or TARGET_FA
 * 
 * Example: 0x1::fungible_asset::symbol<T>(arg_string)
 * - coinType: Move struct tag like "0x...::module::TYPE" (from TARGET_COIN_TYPE env var)
 * - Used for type_args[0] (always)
 * - argString: Either coinType or faAddress (determined via probe script or FA_VIEW_ARG_CONVENTION env var)
 * - Used for args[0] (runtime argument)
 */
export async function fetchFAMetadata(
  faAddress: string,
  rpcUrl: string
): Promise<FATokenMetadata> {
  const normalizedAddress = faAddress.toLowerCase().startsWith("0x") 
    ? faAddress.toLowerCase() 
    : `0x${faAddress.toLowerCase()}`;
  
  const metadata: FATokenMetadata = {
    address: normalizedAddress,
  };

  // Get coin type (Move struct tag) from env var - OPTIONAL
  // Format: "0xADDR::module::TYPE" (full Move struct tag)
  // Used for type_args[0] (always)
  // Runtime arg (args[0]) is determined via FA_VIEW_ARG_CONVENTION or defaults to coinType
  // If not provided, we'll try to infer it from metadata/resources
  let coinTypeString = process.env.TARGET_COIN_TYPE || process.env.FA_STRUCT_TAG;

  // RPC Plan: Track exact RPC calls made (Level-1 scan plan)
  const normalizedRpcUrl = rpcUrl.replace(/\/+$/, "");
  const rpcPlan: {
    provider_chain: string[];
    v1_resources?: { url?: string; used: boolean };
    v1_view?: { url?: string; attempts?: string[]; used: boolean };
    suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
    resources_endpoint?: string; // Legacy field
    resources_success?: boolean; // Legacy field
    framework_views_enabled: boolean;
    framework_views_success?: boolean;
    suprascan_graphql_success?: boolean;
  } = {
    provider_chain: [],
    v1_resources: {
      url: `${normalizedRpcUrl}/rpc/v1/accounts/${normalizedAddress}/resources`,
      used: false,
    },
    v1_view: {
      url: `${normalizedRpcUrl}/rpc/v1/view`,
      attempts: [],
      used: false,
    },
    suprascan_graphql: {
      url: process.env.SUPRASCAN_GRAPHQL_URL || "https://suprascan.io/api/graphql",
      queryName: "GetFaDetails",
      used: false,
    },
    framework_views_enabled: false,
  };
  
  // Debug toggle for verbose per-view logging
  const debug =
    process.env.SSA_DEBUG_VIEW === "1" ||
    process.env.SSA_DEBUG_FA === "1" ||
    process.env.DEBUG_VIEW === "1";

  // PRIMARY: Try fetching resources from the FA address (v3/v2/v1)
  // This is the primary chain-first method
  rpcPlan.provider_chain.push("resources");
  let resourcesSucceeded = false;
  
  try {
    const rpcOptions: RpcClientOptions = {
      rpcUrl: normalizedRpcUrl,
      timeout: 10000,
      retries: 2,
      retryDelay: 500,
    };

    // Try v3/v2 resources endpoints first
    const resourcesResult = await fetchAccountResourcesV3(normalizedAddress, rpcOptions);
    
    rpcPlan.resources_endpoint = `${normalizedRpcUrl}/rpc/v3/accounts/${normalizedAddress}/resources`;
    
    if (!resourcesResult.error && resourcesResult.resources && resourcesResult.resources.length > 0) {
      // Look for FA metadata in resources
      for (const resource of resourcesResult.resources) {
        if (resource.type && (resource.type.includes("fungible_asset") || resource.type.includes("FA") || resource.type.includes("Metadata"))) {
          // Try to extract metadata from resource data
          const data = resource.data || resource;
          if (data.symbol) metadata.symbol = String(data.symbol);
          if (data.decimals !== undefined) metadata.decimals = Number(data.decimals);
          if (data.supply !== undefined) metadata.totalSupply = String(data.supply);
          if (data.total_supply !== undefined) metadata.totalSupply = String(data.total_supply);
          if (data.name) metadata.name = String(data.name);
          if (data.creator) metadata.creator = String(data.creator);
          
          if (metadata.symbol || metadata.decimals !== undefined || metadata.totalSupply) {
            metadata.fetchMethod = "supra_rpc_v3_resources";
            resourcesSucceeded = true;
            rpcPlan.resources_success = true;
            break;
          }
        }
      }
    }

    // If still no metadata, try v1 resources as fallback
    if (!resourcesSucceeded) {
      try {
        rpcPlan.v1_resources!.used = true; // Mark as used before calling
        const v1ResourcesResult = await fetchResourcesV1(normalizedRpcUrl, normalizedAddress);
        
        rpcPlan.resources_endpoint = `${normalizedRpcUrl}/rpc/v1/accounts/${normalizedAddress}/resources`;
        
        if (v1ResourcesResult.resources && v1ResourcesResult.resources.length > 0) {
          for (const resource of v1ResourcesResult.resources) {
            if (resource.type && (resource.type.includes("fungible_asset") || resource.type.includes("FA"))) {
              const data = resource.data || resource;
              if (data.symbol) metadata.symbol = String(data.symbol);
              if (data.decimals !== undefined) metadata.decimals = Number(data.decimals);
              if (data.supply !== undefined) metadata.totalSupply = String(data.supply);
              if (data.total_supply !== undefined) metadata.totalSupply = String(data.total_supply);
              if (data.name) metadata.name = String(data.name);
              if (data.creator) metadata.creator = String(data.creator);
              
              if (metadata.symbol || metadata.decimals !== undefined || metadata.totalSupply) {
                metadata.fetchMethod = "supra_rpc_v1_resources";
                resourcesSucceeded = true;
                rpcPlan.resources_success = true;
                break;
              }
            }
          }
        }
        if (!resourcesSucceeded) {
          rpcPlan.resources_success = false;
        }
      } catch (v1Error) {
        // Silently fail v1 fallback
        rpcPlan.v1_resources!.used = false;
        rpcPlan.resources_success = false;
      }
    }
  } catch (error) {
    metadata.fetchError = error instanceof Error ? error.message : String(error);
    rpcPlan.resources_success = false;
    // Only log resource fetch failures in debug mode
    if (debug) {
      console.debug(`FA resources fetch failed: ${metadata.fetchError}`);
    }
  }

  // SECONDARY: Try Supra framework FA module views with view call negotiator
  // Use negotiator to test different payload shapes and find the correct convention
  // Only attempt if coinTypeString is provided (required for framework views)
  // Determine provider mode early (needed for decision logic)
  const providerMode = process.env.FA_METADATA_PROVIDER || "auto"; // auto | rpc | suprascan
  
  // Helper: Check if coin type is a valid struct tag
  function isValidStructTag(tag: string | undefined): boolean {
    if (!tag || typeof tag !== "string") return false;
    // Must start with 0x, contain exactly 2 occurrences of :: (3 segments)
    const parts = tag.split("::");
    return tag.startsWith("0x") && parts.length === 3 && !tag.startsWith("0x1::object");
  }
  
  const enableFrameworkViews = process.env.FA_ENABLE_FRAMEWORK_VIEWS === "1" || process.env.FA_ENABLE_VIEWS === "1";
  rpcPlan.framework_views_enabled = enableFrameworkViews;
  let viewsSucceeded = 0;

  // Determine if we want RPC-based metadata (resources + framework views)
  const wantRpc = providerMode === "rpc" || (providerMode === "auto" && !resourcesSucceeded);
  const shouldAttemptFrameworkViews = 
    enableFrameworkViews && 
    isValidStructTag(coinTypeString) && 
    providerMode !== "suprascan" && 
    (wantRpc || (providerMode === "auto" && !resourcesSucceeded));

  // Attempt framework views if conditions are met
  if (shouldAttemptFrameworkViews) {
    const frameworkFAViews = [
      { name: "symbol", fn: `0x1::fungible_asset::symbol` },
      { name: "decimals", fn: `0x1::fungible_asset::decimals` },
      { name: "supply", fn: `0x1::fungible_asset::supply` },
      { name: "name", fn: `0x1::fungible_asset::name` },
    ];

    rpcPlan.provider_chain.push("v1_view");
    rpcPlan.v1_view!.used = true;

    // Negotiate view call shape using the first view function
    // coinTypeString is guaranteed to be valid here due to shouldAttemptFrameworkViews check
    // coinTypeString is guaranteed to be valid here due to shouldAttemptFrameworkViews check
    const { negotiateViewCallShape } = await import("../rpc/viewCallNegotiator.js");
    const negotiatedResult = await negotiateViewCallShape(
      normalizedRpcUrl,
      frameworkFAViews[0].fn,
      coinTypeString!,
      normalizedAddress
    );

    if (negotiatedResult && negotiatedResult.success) {
      // Use the negotiated shape for all subsequent views
      rpcPlan.v1_view!.attempts!.push(`negotiated_shape: ${negotiatedResult.shape.name}`);
      
      for (const view of frameworkFAViews) {
        try {
          const { viewFunctionRawRpc } = await import("../rpc/viewRpc.js");
          const result = await viewFunctionRawRpc(
            normalizedRpcUrl,
            view.fn,
            negotiatedResult.shape.args,
            negotiatedResult.shape.typeArgs
          );

          // Harden result parsing: handle array responses
          let parsedResult = result?.result;
          if (Array.isArray(parsedResult)) {
            parsedResult = parsedResult[0];
          } else if (parsedResult && typeof parsedResult === "object" && parsedResult.result !== undefined) {
            parsedResult = Array.isArray(parsedResult.result) ? parsedResult.result[0] : parsedResult.result;
          }

          if (parsedResult !== null && parsedResult !== undefined) {
            viewsSucceeded++;
            
            // Coerce types appropriately
            if (view.name === "symbol") {
              metadata.symbol = String(parsedResult);
            } else if (view.name === "decimals") {
              metadata.decimals = Number(parsedResult);
            } else if (view.name === "supply") {
              metadata.totalSupply = String(parsedResult);
            } else if (view.name === "name") {
              metadata.name = String(parsedResult);
            }
          }
        } catch (error) {
          // Continue to next view - only log failures in debug mode
          if (debug) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            console.debug(`FA view ${view.name} failed: ${errorMsg}`);
          }
        }
      }

      // If views succeeded, mark as view-based fetch
      if (viewsSucceeded > 0) {
        metadata.fetchMethod = "supra_framework_fa_views";
        rpcPlan.framework_views_success = true;
      } else {
        rpcPlan.framework_views_success = false;
        rpcPlan.v1_view!.used = false;
      }
    } else {
      // Negotiation failed - skip view calls
      rpcPlan.v1_view!.used = false;
      rpcPlan.framework_views_success = false;
      if (debug) {
        console.debug(`[FA] View call negotiation failed, skipping RPC views`);
      }
    }
  } else if (enableFrameworkViews) {
    // Framework views enabled but skipped - provide truthful debug message
    if (debug) {
      if (providerMode === "suprascan") {
        console.debug(`[FA] Framework views enabled but skipped (Provider=suprascan: skipping framework views by policy)`);
      } else if (resourcesSucceeded && providerMode === "auto") {
        console.debug(`[FA] Framework views enabled but skipped (metadata already resolved via resources)`);
      } else if (!isValidStructTag(coinTypeString)) {
        console.debug(`[FA] Framework views enabled but skipped (no coin type struct tag available)`);
      }
    }
    // Don't add "v1_view" to provider_chain if we didn't attempt it
  }

  // Check metadata completeness for auto provider policy
  const hasCoreMetadata =
    !!(metadata.symbol || metadata.name || metadata.decimals !== undefined || metadata.totalSupply);

  const needsSurfaceMetadata =
    !metadata.creator || metadata.totalSupply === undefined || metadata.totalSupply === null || metadata.totalSupply === "";

  // Determine if SupraScan should be attempted
  const shouldTrySupraScan =
    providerMode === "suprascan" ||
    (providerMode === "auto" && (!hasCoreMetadata || needsSurfaceMetadata));

  // Track why SupraScan is being called (for debug and used flag logic)
  const isSupraScanForSurfaceMetadata = providerMode === "auto" && hasCoreMetadata && needsSurfaceMetadata;

  // ============================================================================
  // LEVEL 4: Two GraphQL Fetch Paths from SupraScan (ALWAYS RUN BOTH)
  // ============================================================================
  // Path 1: Token/FA details query (from token page)
  //   - FA: GetFaDetails(faAddress, blockchainEnvironment)
  //   - Returns: name/symbol/decimals/totalSupply/holders/creatorAddress/etc.
  // Path 2: Address resources query (from wallet/creator page)
  //   - AddressDetail(address, blockchainEnvironment, isAddressName, ...)
  //   - Returns: addressDetailSupra.resources (stringified JSON) with on-chain capability surface
  // Both outputs are merged into one report for cross-checking "claims vs on-chain reality"
  // ============================================================================

  // STEP 1: Path 1 - Token/FA details query (GetFaDetails) - ALWAYS
  // This represents INDEXER / UI / ECONOMIC SUPPLY and metadata claims
  const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet") as "mainnet" | "testnet";
  rpcPlan.provider_chain.push("suprascan_graphql");
  rpcPlan.suprascan_graphql!.used = true;
  rpcPlan.suprascan_graphql!.queryName = "GetFaDetails"; // Track operation name
  
  const suprascanData = await fetchFaDetailsFromSupraScan(normalizedAddress, suprascanEnv);
  let graphqlSupply: string | number | undefined = undefined;

  // LEVEL 4: Store GetFaDetails separately as fa_details (paired evidence bundle)
  const faDetails: typeof metadata.fa_details = suprascanData
    ? {
        faName: suprascanData.faName,
        faSymbol: suprascanData.faSymbol,
        decimals: suprascanData.decimals !== undefined ? Number(suprascanData.decimals) : undefined,
        holders: suprascanData.holders,
        verified: suprascanData.verified,
        price: suprascanData.price !== undefined && suprascanData.price !== null ? String(suprascanData.price) : undefined,
        totalSupply: suprascanData.totalSupply ? String(suprascanData.totalSupply) : undefined, // Already decimal-adjusted from indexer
        creatorAddress: suprascanData.creatorAddress ? String(suprascanData.creatorAddress) : undefined,
      }
    : undefined;

  if (suprascanData) {
    // Map SupraScan data to metadata (for other fields, still allow fallback)
    if (!metadata.name && suprascanData.faName) {
      metadata.name = suprascanData.faName;
    }
    if (!metadata.symbol && suprascanData.faSymbol) {
      metadata.symbol = suprascanData.faSymbol;
    }
    if (metadata.decimals === undefined && suprascanData.decimals !== undefined) {
      metadata.decimals = Number(suprascanData.decimals);
    }
    // LEVEL 4: Store GraphQL supply separately (never overwrite)
    if (suprascanData.totalSupply) {
      graphqlSupply = String(suprascanData.totalSupply); // Already decimal-adjusted from indexer
      metadata.supplyIndexerGraphql = graphqlSupply;
      // Also set legacy totalSupply for backward compatibility (but don't overwrite if RPC already set)
      if (!metadata.totalSupply) {
        metadata.totalSupply = graphqlSupply;
      }
    }
    if (!metadata.creator && suprascanData.creatorAddress) {
      metadata.creator = String(suprascanData.creatorAddress);
    }
    if (metadata.holdersCount === undefined && suprascanData.holders !== undefined) {
      metadata.holdersCount = Number(suprascanData.holders);
    }
    
    // Optional SupraScan-specific fields
    if (suprascanData.iconUrl) {
      metadata.iconUrl = suprascanData.iconUrl;
    }
    if (suprascanData.verified !== undefined) {
      metadata.verified = suprascanData.verified;
    }
    if (suprascanData.isDualNature !== undefined) {
      metadata.isDualNature = suprascanData.isDualNature;
    }
    if (suprascanData.price !== undefined && suprascanData.price !== null) {
      (metadata as any).price = suprascanData.price;
    }

    // Try to infer coin type from SupraScan if dual-nature and coin type not provided
    if (!coinTypeString && suprascanData.isDualNature) {
      try {
        const { fetchCoinDetailsFromSupraScan } = await import("../rpc/supraScanGraphql.js");
        const coinDetails = await fetchCoinDetailsFromSupraScan(normalizedAddress, suprascanEnv);
      } catch {
        // Silently fail
      }
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

  // Store fa_details separately
  metadata.fa_details = faDetails;

  // STEP 2: Path 2 - Address resources query (AddressDetail) - ALWAYS fetch BOTH:
  // a) AddressDetail(faAddress) - FA metadata object resources (on-chain capability surface)
  // b) AddressDetail(creatorAddress) - IF creatorAddress exists AND differs from faAddress
  // Extract from resources (stringified JSON):
  //   - ConcurrentSupply.current.value (raw base units) -> on-chain supply
  //   - ObjectCore.owner -> canonical owner
  //   - Mint/burn/transfer refs -> capability evidence
  //   - Hooks -> dispatch function evidence
  // This represents CANONICAL ON-CHAIN SUPPLY and capability reality
  let rpcSupply: string | number | undefined = undefined;
  let rpcDecimals: number | undefined = metadata.decimals;
  let ownerOnChain: string | undefined = undefined;
  let capabilitiesSummary: FATokenMetadata["capabilitiesSummary"] | undefined = undefined;
  
  // FA Address Resources (AddressDetail on faAddress)
  let faAddressResources: {
    address?: string;
    resources?: string;
    resourceAnalysis?: ReturnType<typeof analyzeFaResources>;
    owner?: string;
    supplyCurrent?: string;
    capabilities?: FATokenMetadata["capabilitiesSummary"];
  } | undefined = undefined;

  // Creator Address Resources (AddressDetail on creatorAddress when different)
  let creatorAddressResources: {
    address: string;
    resources?: string;
    resourceAnalysis?: ReturnType<typeof analyzeFaResources>;
    owner?: string;
    capabilities?: FATokenMetadata["capabilitiesSummary"];
  } | undefined = undefined;

  // STEP 2a: Fetch AddressDetail for FA address - ALWAYS
  try {
    const faAddressDetail = await fetchAddressDetailSupra(normalizedAddress, suprascanEnv);
    
    if (faAddressDetail && !faAddressDetail.isError && faAddressDetail.addressDetailSupra?.resources) {
      const resourcesStr = faAddressDetail.addressDetailSupra.resources;
      
      if (resourcesStr && typeof resourcesStr === "string" && resourcesStr.trim().length > 0) {
        // Analyze resources to extract ConcurrentSupply, ObjectCore.owner, capabilities
        const resourceAnalysis = analyzeFaResources(resourcesStr);
        
        const faCapabilities = {
          hasMintRef: resourceAnalysis.caps.hasMintRef,
          hasBurnRef: resourceAnalysis.caps.hasBurnRef,
          hasTransferRef: resourceAnalysis.caps.hasTransferRef,
          hasDepositHook: resourceAnalysis.caps.hasDepositHook,
          hasWithdrawHook: resourceAnalysis.caps.hasWithdrawHook,
          hasDispatchFunctions: resourceAnalysis.caps.hasDepositHook || resourceAnalysis.caps.hasWithdrawHook || resourceAnalysis.caps.hasDerivedBalanceHook,
        };
        faAddressResources = {
          address: normalizedAddress,
          resources: resourcesStr,
          resourceAnalysis,
          owner: resourceAnalysis.caps.owner || undefined,
          supplyCurrent: resourceAnalysis.caps.supplyCurrent || undefined,
          capabilities: faCapabilities,
        };
        
        // Extract on-chain supply from ConcurrentSupply.current.value (raw base units)
        if (resourceAnalysis.caps.supplyCurrent) {
          const supplyRawBaseUnits = resourceAnalysis.caps.supplyCurrent;
          
          // Decimal-adjust: onChainSupply = concurrentSupply.value / 10^decimals
          if (rpcDecimals !== undefined && rpcDecimals !== null) {
            try {
              const baseValue = BigInt(supplyRawBaseUnits);
              const divisor = BigInt(10 ** rpcDecimals);
              const wholePart = baseValue / divisor;
              const fractionalPart = baseValue % divisor;
              
              if (fractionalPart === BigInt(0)) {
                rpcSupply = wholePart.toString();
              } else {
                rpcSupply = `${wholePart}.${fractionalPart.toString().padStart(rpcDecimals, "0")}`;
              }
            } catch {
              // If decimal adjustment fails, store raw value
              rpcSupply = supplyRawBaseUnits;
            }
          } else {
            // No decimals available, store raw value
            rpcSupply = supplyRawBaseUnits;
          }
          
          metadata.supplyOnChainRpc = rpcSupply;
          // Also set legacy totalSupply for backward compatibility (prefer RPC if both exist)
          if (!metadata.totalSupply || metadata.supplyIndexerGraphql) {
            // If we have GraphQL supply, keep both; otherwise set RPC as legacy
            if (!metadata.supplyIndexerGraphql) {
              metadata.totalSupply = rpcSupply;
            }
          }
        }
        
        // Extract owner from ObjectCore.owner (canonical)
        if (resourceAnalysis.caps.owner) {
          ownerOnChain = resourceAnalysis.caps.owner;
          metadata.ownerOnChain = ownerOnChain;
        }
        
        // Extract capabilities summary
        if (faAddressResources && faAddressResources.capabilities) {
          capabilitiesSummary = faAddressResources.capabilities;
          metadata.capabilitiesSummary = capabilitiesSummary;
        }
      }
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_FA === "1" || process.env.SSA_DEBUG_VIEW === "1";
    if (debug) {
      console.debug(`[FA] AddressDetail fetch for FA address failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // STEP 2b: Fetch AddressDetail for creator address - IF creatorAddress exists AND differs from faAddress
  const creatorAddressForResources = metadata.creator || ownerOnChain;
  if (creatorAddressForResources && creatorAddressForResources.toLowerCase() !== normalizedAddress.toLowerCase()) {
    try {
      const normalizedCreatorAddress = creatorAddressForResources.toLowerCase().startsWith("0x")
        ? creatorAddressForResources.toLowerCase()
        : `0x${creatorAddressForResources.toLowerCase()}`;
      
      const creatorAddressDetail = await fetchAddressDetailSupra(normalizedCreatorAddress, suprascanEnv);
      
      if (creatorAddressDetail && !creatorAddressDetail.isError && creatorAddressDetail.addressDetailSupra?.resources) {
        const resourcesStr = creatorAddressDetail.addressDetailSupra.resources;
        
        if (resourcesStr && typeof resourcesStr === "string" && resourcesStr.trim().length > 0) {
          // Analyze resources to extract capabilities from creator wallet
          const resourceAnalysis = analyzeFaResources(resourcesStr);
          
          const creatorCapabilities = {
            hasMintRef: resourceAnalysis.caps.hasMintRef,
            hasBurnRef: resourceAnalysis.caps.hasBurnRef,
            hasTransferRef: resourceAnalysis.caps.hasTransferRef,
            hasDepositHook: resourceAnalysis.caps.hasDepositHook,
            hasWithdrawHook: resourceAnalysis.caps.hasWithdrawHook,
            hasDispatchFunctions: resourceAnalysis.caps.hasDepositHook || resourceAnalysis.caps.hasWithdrawHook || resourceAnalysis.caps.hasDerivedBalanceHook,
          };
          creatorAddressResources = {
            address: normalizedCreatorAddress,
            resources: resourcesStr,
            resourceAnalysis,
            owner: resourceAnalysis.caps.owner || undefined,
            capabilities: creatorCapabilities,
          };
          if (creatorAddressResources) {
            metadata.creator_address_resources = creatorAddressResources;
          }
        }
      }
    } catch (error) {
      const debug = process.env.SSA_DEBUG_FA === "1" || process.env.SSA_DEBUG_VIEW === "1";
      if (debug) {
        console.debug(`[FA] AddressDetail fetch for creator address failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // LEVEL 4: Store both resource views separately in metadata (paired evidence bundle)
  if (faAddressResources) {
    metadata.fa_address_resources = {
      address: normalizedAddress,
      resources: faAddressResources.resources,
      owner: faAddressResources.owner,
      supplyCurrent: faAddressResources.supplyCurrent,
      supplyCurrentDecimalAdjusted: rpcSupply,
      capabilities: faAddressResources.capabilities,
    };
  }
  
  if (creatorAddressResources) {
    metadata.creator_address_resources = {
      address: creatorAddressResources.address,
      resources: creatorAddressResources.resources,
      owner: creatorAddressResources.owner,
      capabilities: creatorAddressResources.capabilities,
      modulesPublished: undefined, // Could be added if needed
      modulesPublishedCount: undefined,
    };
  }

  // STEP 3: Level 4 Parity Evaluation
  // Compare RPC supply (decimal-adjusted) vs GraphQL supply (already decimal-adjusted) and flag INDEXER_SUPPLY_DRIFT_FA
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
      if (process.env.SSA_DEBUG_FA === "1") {
        console.debug(`[FA] Supply parity check calculation failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } else if (rpcSupply !== undefined || graphqlSupply !== undefined) {
    // Only one source available - still store but note the missing source
    supplyParityCheck.likelyCause = "single_source_only";
  }

  metadata.supplyParityCheck = supplyParityCheck;

  // STEP 4: Fetch GetAllTransactions for supporting evidence (ALWAYS)
  // Fetch transactions for both FA address and creator address (if different)
  const lastNTxs = parseInt(process.env.SSA_TX_LIMIT || "10", 10); // Default: last 10 transactions

  // Fetch transactions for FA address
  try {
    const faAddressTxs = await fetchAllTransactionsFromSupraScan({
      blockchainEnvironment: suprascanEnv,
      address: normalizedAddress,
      page: 1,
      rowsPerPage: lastNTxs,
    });

    if (faAddressTxs && faAddressTxs.transactions) {
      metadata.fa_address_transactions = {
        address: normalizedAddress,
        transactions: faAddressTxs.transactions
          .slice(0, lastNTxs)
          .map((tx) => ({
            transactionHash: tx.transactionBasicInfo?.transactionHash,
            senderAddress: tx.transactionBasicInfo?.senderAddress,
            receiverAddress: tx.transactionBasicInfo?.receiverAddress,
            transferAmount: tx.transactionBasicInfo?.transferAmount,
            confirmationTime: tx.transactionBasicInfo?.confirmationTime,
            transactionStatus: tx.transactionBasicInfo?.transactionStatus,
            functionName: tx.transactionBasicInfo?.functionName,
            type: tx.transactionBasicInfo?.type,
          })),
        totalItems: faAddressTxs.totalItems,
        foundCount: faAddressTxs.foundCount,
      };
    }
  } catch (error) {
    const debug = process.env.SSA_DEBUG_FA === "1";
    if (debug) {
      console.debug(`[FA] GetAllTransactions fetch for FA address failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Fetch transactions for creator address (if different from FA address)
  // Reuse creatorAddressForResources from above, or compute if not available
  const creatorAddressForTxs = metadata.creator || ownerOnChain;
  if (creatorAddressForTxs && creatorAddressForTxs.toLowerCase() !== normalizedAddress.toLowerCase()) {
    try {
      const normalizedCreatorAddress = creatorAddressForTxs.toLowerCase().startsWith("0x")
        ? creatorAddressForTxs.toLowerCase()
        : `0x${creatorAddressForTxs.toLowerCase()}`;

      const creatorAddressTxs = await fetchAllTransactionsFromSupraScan({
        blockchainEnvironment: suprascanEnv,
        address: normalizedCreatorAddress,
        page: 1,
        rowsPerPage: lastNTxs,
      });

      if (creatorAddressTxs && creatorAddressTxs.transactions) {
        metadata.creator_address_transactions = {
          address: normalizedCreatorAddress,
          transactions: creatorAddressTxs.transactions
            .slice(0, lastNTxs)
            .map((tx) => ({
              transactionHash: tx.transactionBasicInfo?.transactionHash,
              senderAddress: tx.transactionBasicInfo?.senderAddress,
              receiverAddress: tx.transactionBasicInfo?.receiverAddress,
              transferAmount: tx.transactionBasicInfo?.transferAmount,
              confirmationTime: tx.transactionBasicInfo?.confirmationTime,
              transactionStatus: tx.transactionBasicInfo?.transactionStatus,
              functionName: tx.transactionBasicInfo?.functionName,
              type: tx.transactionBasicInfo?.type,
            })),
          totalItems: creatorAddressTxs.totalItems,
          foundCount: creatorAddressTxs.foundCount,
        };
      }
    } catch (error) {
      const debug = process.env.SSA_DEBUG_FA === "1";
      if (debug) {
        console.debug(`[FA] GetAllTransactions fetch for creator address failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // Try to infer coin type from v3 resources if not provided
  // Only infer from strict token-specific indicators, never from generic resources like ObjectCore
  if (!coinTypeString) {
    try {
      const rpcOptions: RpcClientOptions = {
        rpcUrl: normalizedRpcUrl,
        timeout: 10000,
        retries: 1,
        retryDelay: 500,
      };
      const resourcesResult = await fetchAccountResourcesV3(normalizedAddress, rpcOptions);
      
      if (resourcesResult.resources && resourcesResult.resources.length > 0) {
        for (const resource of resourcesResult.resources) {
          // Method 1: Check for fungible_asset::Metadata<T> pattern and extract struct tag
          if (resource.type && typeof resource.type === "string") {
            // Match pattern: fungible_asset::Metadata<0xADDR::module::TYPE>
            const metadataMatch = resource.type.match(/fungible_asset::Metadata<(.+::.+::.+)>/);
            if (metadataMatch && metadataMatch[1]) {
              const extractedCoinType = metadataMatch[1].trim();
              // Validate it's a proper struct tag using helper function
              if (isValidStructTag(extractedCoinType)) {
                coinTypeString = extractedCoinType;
                if (debug) {
                  console.debug(`[FA] Inferred coin type from fungible_asset::Metadata resource: ${coinTypeString}`);
                }
                break;
              }
            }
          }
          
          // Method 2: Check resource.data for explicit coin type fields
          if (resource.data && typeof resource.data === "object") {
            const data = resource.data as any;
            // Check for explicit coin type fields
            const coinTypeFields = ["coin_type", "struct_tag", "asset_type", "type_tag"];
            for (const field of coinTypeFields) {
              if (data[field] && typeof data[field] === "string") {
                const potentialCoinType = data[field].trim();
                // Validate it's a proper struct tag using helper function
                if (isValidStructTag(potentialCoinType)) {
                  coinTypeString = potentialCoinType;
                  if (debug) {
                    console.debug(`[FA] Inferred coin type from resource.data.${field}: ${coinTypeString}`);
                  }
                  break;
                }
              }
            }
            if (coinTypeString) break;
          }
        }
      }
    } catch (error) {
      // Silently fail coin type inference
      if (debug) {
        console.debug(`[FA] Coin type inference from resources failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // Store inferred coin type in metadata for later use
  if (coinTypeString) {
    (metadata as any).coinType = coinTypeString;
  }

  // Store RPC plan in metadata for debug output
  (metadata as any).rpcPlan = rpcPlan;

  return metadata;
}

/**
 * Execute FA-specific security rules (metadata-based only)
 */
function executeFARules(
  metadata: FATokenMetadata,
  bytecodeData: { functionNames: string[]; entryFunctions: string[]; strings: string[]; markers: string[] },
  hasBytecode: boolean
): Finding[] {
  const findings: Finding[] = [];

  // FA-MINT-001: Mintable post-deploy (HIGH/CRITICAL only if bytecode evidence)
  // Since FA scan doesn't fetch bytecode, this will only trigger if bytecode is somehow available
  const mintPatterns = bytecodeData.markers.filter((m) =>
    m.toLowerCase().includes("mint")
  );
  const hasMintFunction = bytecodeData.functionNames.some((fn) =>
    fn.toLowerCase().includes("mint")
  );
  
  if ((mintPatterns.length > 0 || hasMintFunction) && hasBytecode) {
    // Check for access control markers
    const hasAccessControl = bytecodeData.markers.some((m) =>
      m.toLowerCase().includes("admin") ||
      m.toLowerCase().includes("owner") ||
      m.toLowerCase().includes("only_")
    );
    
    findings.push({
      id: "FA-MINT-001",
      title: "Token Appears Mintable Post-Deploy",
      severity: hasAccessControl ? "high" : "critical",
      confidence: hasBytecode ? 0.8 : 0.4,
      description: `Mint function patterns detected in bytecode. ${hasAccessControl ? "Access control markers found, but verify enforcement." : "No clear access control markers detected."}`,
      recommendation: hasAccessControl
        ? "Verify that mint functions are properly gated and cannot be called by unauthorized parties."
        : "Implement access control (admin/owner checks) for mint functions to prevent unauthorized minting.",
      evidence: {
        kind: hasBytecode ? "bytecode_pattern" : "heuristic",
        matched: mintPatterns.length > 0 ? mintPatterns : ["mint function detected"],
        locations: [],
      },
      references: [],
    });
  }

  // FA-FREEZE-001: Freeze/blacklist/pause capability (metadata-based, low confidence)
  // Since we don't have bytecode, this is informational only
  if (!hasBytecode) {
    findings.push({
      id: "FA-FREEZE-001",
      title: "Freeze/Blacklist/Pause Capability Unknown",
      severity: "info",
      confidence: 0.3,
      description: "Cannot verify freeze/blacklist/pause capabilities without bytecode. FA tokens may have these features.",
      recommendation: "Review token documentation or source code to verify freeze/blacklist/pause capabilities.",
      evidence: {
        kind: "heuristic",
        matched: [],
        locations: [],
      },
      references: [],
    });
  }

  // FA-UPGRADE-001: Upgrade/admin controls (metadata-based, low confidence)
  if (!hasBytecode) {
    findings.push({
      id: "FA-UPGRADE-001",
      title: "Upgrade/Admin Controls Unknown",
      severity: "info",
      confidence: 0.3,
      description: "Cannot verify upgrade/admin controls without bytecode. FA tokens may have upgrade capabilities.",
      recommendation: "Review token documentation or source code to verify upgrade/admin mechanisms.",
      evidence: {
        kind: "heuristic",
        matched: [],
        locations: [],
      },
      references: [],
    });
  }

  // FA-META-001: Missing/empty metadata
  if (!metadata.symbol || metadata.decimals === undefined || !metadata.totalSupply) {
    findings.push({
      id: "FA-META-001",
      title: "Missing or Incomplete Metadata",
      severity: "low",
      confidence: 0.9,
      description: `Token metadata is missing or incomplete. Missing: ${[
        !metadata.symbol && "symbol",
        metadata.decimals === undefined && "decimals",
        !metadata.totalSupply && "totalSupply",
      ].filter(Boolean).join(", ")}`,
      recommendation: "Ensure all standard FA metadata fields (symbol, decimals, totalSupply) are available via view functions.",
      evidence: {
        kind: "metadata",
        matched: [],
        locations: [],
      },
      references: [],
    });
  }

  // FA-SUPPLY-001: Supply anomalies
  if (metadata.totalSupply !== undefined) {
    const supply = Number(metadata.totalSupply);
    if (supply === 0) {
      findings.push({
        id: "FA-SUPPLY-001",
        title: "Zero Total Supply",
        severity: "medium",
        confidence: 0.8,
        description: "Token has zero total supply. This may indicate a deployment issue or all tokens have been burned.",
        recommendation: "Verify token deployment and initial minting were successful.",
        evidence: {
          kind: "metadata",
          matched: ["totalSupply=0"],
          locations: [],
        },
        references: [],
      });
    }
  }

  // FA-OBS-001: Event markers (not applicable for metadata-only scan)
  // Skip this rule for FA metadata-only scans

  return findings;
}

/**
 * Execute FA holder concentration rule (heuristic, metadata-based)
 */
function executeFAHolderConcentrationRule(
  holdersData: {
    faHolders: Array<{
      address: string;
      addressAlias?: string | null;
      quantity: string;
      value?: string | null;
      percentage?: number;
    }>;
  } | null
): Finding[] {
  const findings: Finding[] = [];

  if (!holdersData || !holdersData.faHolders || holdersData.faHolders.length === 0) {
    return findings;
  }

  const holders = holdersData.faHolders;
  
  // Check top holder concentration
  const top1Percentage = holders[0]?.percentage ?? 0;
  const top5Percentage = holders.slice(0, 5).reduce((sum, h) => sum + (h.percentage ?? 0), 0);

  if (top1Percentage >= 50) {
    findings.push({
      id: "FA-HOLDERS-001",
      title: "High Holder Concentration (Top Holder ≥50%)",
      severity: "medium",
      confidence: 0.7,
      description: `Top holder controls ${top1Percentage.toFixed(2)}% of token supply. High concentration may indicate centralization risk.`,
      recommendation: "Review token distribution and consider mechanisms to encourage broader distribution.",
      evidence: {
        kind: "heuristic",
        matched: [`top1_percentage=${top1Percentage.toFixed(2)}%`],
        locations: [],
      },
      references: [],
    });
  } else if (top5Percentage >= 80) {
    findings.push({
      id: "FA-HOLDERS-002",
      title: "High Holder Concentration (Top 5 ≥80%)",
      severity: "medium",
      confidence: 0.7,
      description: `Top 5 holders control ${top5Percentage.toFixed(2)}% of token supply. High concentration may indicate centralization risk.`,
      recommendation: "Review token distribution and consider mechanisms to encourage broader distribution.",
      evidence: {
        kind: "heuristic",
        matched: [`top5_percentage=${top5Percentage.toFixed(2)}%`],
        locations: [],
      },
      references: [],
    });
  } else if (holders.length > 0) {
    // Info finding for normal distribution
    findings.push({
      id: "FA-HOLDERS-003",
      title: "Holder Distribution Analyzed",
      severity: "info",
      confidence: 0.8,
      description: `Token has ${holders.length} top holders analyzed. Top holder: ${top1Percentage.toFixed(2)}%, Top 5: ${top5Percentage.toFixed(2)}%.`,
      recommendation: "Monitor holder distribution over time for signs of increasing concentration.",
      evidence: {
        kind: "heuristic",
        matched: [`top1_percentage=${top1Percentage.toFixed(2)}%`, `top5_percentage=${top5Percentage.toFixed(2)}%`],
        locations: [],
      },
      references: [],
    });
  }

  return findings;
}

/**
 * Scan an FA token
 */
export async function scanFAToken(
  faAddress: string,
  options: FAScanOptions = {}
): Promise<ScanResult> {
  const startTime = Date.now();
  const requestId = randomUUID();
  const timestamp = getIsoTimestamp();
  const rpcUrl = options.rpc_url || process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
  const proxyBase = options.proxy_base || process.env.PROD_API;

  // Fetch FA metadata via Supra framework FA views and/or resources (includes Level 4 dual supply tracking)
  // NOTE: FA address is NOT a module publisher - do NOT fetch modules from FA address
  const metadata = await fetchFAMetadata(faAddress, rpcUrl);
  const rpcPlan = metadata.rpcPlan; // Extract RPC plan from metadata
  
  // Check if metadata fetch succeeded
  const hasMetadata = !!(metadata.symbol || metadata.decimals !== undefined || metadata.totalSupply || metadata.supplyOnChainRpc || metadata.supplyIndexerGraphql);
  
  if (!hasMetadata && !metadata.fetchError) {
    metadata.fetchError = "No metadata found via views or resources";
  }

  // LEVEL 4: Cross-checks for FA - "claims vs on-chain reality"
  // Cross-check GetFaDetails (token-facing metadata & stats) vs AddressDetail (actual on-chain resource surface + capability refs)
  
  // Cross-check 1: creatorAddress (details) vs ObjectCore.owner (resources)
  const creatorAddressDetails = metadata.fa_details?.creatorAddress || metadata.creator;
  const ownerOnChainResources = metadata.ownerOnChain || metadata.fa_address_resources?.owner;
  const creatorAddressMatch = creatorAddressDetails && ownerOnChainResources
    ? creatorAddressDetails.toLowerCase() === ownerOnChainResources.toLowerCase()
    : undefined;
  const creatorAddressMismatchReason = creatorAddressDetails && ownerOnChainResources && !creatorAddressMatch
    ? `Creator address mismatch: GetFaDetails.creatorAddress="${creatorAddressDetails}" vs AddressDetail.resources.ObjectCore.owner="${ownerOnChainResources}"`
    : undefined;

  // Cross-check 2: totalSupply (details) vs ConcurrentSupply.current.value (resources)
  // This is already done via supplyParityCheck, but make it explicit here
  const totalSupplyDetails = metadata.fa_details?.totalSupply || metadata.supplyIndexerGraphql;
  const supplyOnChainResources = metadata.supplyOnChainRpc || metadata.fa_address_resources?.supplyCurrentDecimalAdjusted;
  const supplyMatch = metadata.supplyParityCheck?.driftDetected === false;
  const supplyMismatchReason = metadata.supplyParityCheck?.driftDetected
    ? `Supply mismatch (INDEXER_SUPPLY_DRIFT_FA): GetFaDetails.totalSupply="${totalSupplyDetails}" vs AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)="${supplyOnChainResources}". Likely cause: ${metadata.supplyParityCheck.likelyCause || "unknown"}. Difference: ${metadata.supplyParityCheck.difference || "N/A"} (${metadata.supplyParityCheck.differencePercentage !== undefined ? metadata.supplyParityCheck.differencePercentage.toFixed(2) : "N/A"}%)`
    : undefined;

  // Cross-check 3: verified/holders (details) vs "capabilities present" (resources)
  const verifiedDetails = metadata.fa_details?.verified || metadata.verified;
  const holdersDetails = metadata.fa_details?.holders || metadata.holdersCount;
  const capabilitiesResources = metadata.capabilitiesSummary || metadata.fa_address_resources?.capabilities;
  const hasCapabilities = capabilitiesResources
    ? (capabilitiesResources.hasMintRef || capabilitiesResources.hasBurnRef || capabilitiesResources.hasTransferRef || capabilitiesResources.hasDepositHook || capabilitiesResources.hasWithdrawHook || capabilitiesResources.hasDispatchFunctions)
    : false;
  
  // Flag if verified but no capabilities (or vice versa)
  const verifiedVsCapabilitiesCheck = verifiedDetails !== undefined && capabilitiesResources !== undefined
    ? {
        verified: verifiedDetails,
        hasCapabilities,
        holders: holdersDetails,
        capabilitiesPresent: {
          hasMintRef: capabilitiesResources.hasMintRef,
          hasBurnRef: capabilitiesResources.hasBurnRef,
          hasTransferRef: capabilitiesResources.hasTransferRef,
          hasDepositHook: capabilitiesResources.hasDepositHook,
          hasWithdrawHook: capabilitiesResources.hasWithdrawHook,
          hasDispatchFunctions: capabilitiesResources.hasDispatchFunctions,
        },
        mismatch: verifiedDetails && !hasCapabilities ? "Verified in details but no capabilities found in resources" : !verifiedDetails && hasCapabilities ? "Not verified in details but capabilities present in resources" : undefined,
      }
    : undefined;

  const crossChecks = {
    // Cross-check 1: creatorAddress vs ObjectCore.owner
    creatorAddressMatch,
    creatorAddressMismatchReason,
    // Cross-check 2: totalSupply vs ConcurrentSupply.current.value
    supplyMetadataClaimsMatch: supplyMatch,
    supplyMetadataMismatchReason: supplyMismatchReason,
    // Cross-check 3: verified/holders vs capabilities present
    verifiedVsCapabilitiesCheck,
    // Legacy field name for backward compatibility
    ownerMatch: creatorAddressMatch,
    ownerMismatchReason: creatorAddressMismatchReason,
  };

  // Fetch FA holders from SupraScan (optional, when provider is suprascan or auto)
  let faHoldersData: {
    faHolders: Array<{
      address: string;
      addressAlias?: string | null;
      quantity: string;
      value?: string | null;
      percentage?: number;
    }>;
    pageNumber: number;
    pageCount: number;
    totalItems: number;
    nextPage: boolean;
  } | null = null;

  // LEVEL-1: Control Surface Verification via Resources
  // Analyze FA resources from SupraScan AddressDetail (works even when hasBytecode = false)
  let faResourceAnalysis: {
    findings: FaResourceFinding[];
    caps: {
      hasMintRef: boolean;
      hasBurnRef: boolean;
      hasTransferRef: boolean;
      hasDepositHook: boolean;
      hasWithdrawHook: boolean;
      hasDerivedBalanceHook: boolean;
      owner?: string | null;
      supplyCurrent?: string | null;
      supplyMax?: string | null;
      hookModules?: Array<{ module_address: string; module_name: string; function_name: string }>;
    };
    parsedCount: number;
  } | null = null;

  const ADDRESS_DETAIL_QUERY = `
query AddressDetail($address: String, $page: Int, $offset: Int, $userWalletAddress: String, $blockchainEnvironment: BlockchainEnvironment, $isAddressName: Boolean) {
  addressDetail(address: $address, page: $page, offset: $offset, userWalletAddress: $userWalletAddress, blockchainEnvironment: $blockchainEnvironment, isAddressName: $isAddressName) {
    __typename
    isSaved
    isError
    errorType
    addressDetailSupra {
      __typename
      resources
    }
  }
}
`;

  const providerMode = process.env.FA_METADATA_PROVIDER || "auto";
  if (providerMode === "suprascan" || providerMode === "auto") {
    try {
      const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet") as "mainnet" | "testnet";
      
      // Fetch holders
      const holdersResult = await fetchFaHoldersFromSupraScan(faAddress, suprascanEnv, 1, 10);
      if (holdersResult) {
        faHoldersData = {
          faHolders: holdersResult.faHolders,
          pageNumber: holdersResult.pageNumber,
          pageCount: holdersResult.pageCount,
          totalItems: holdersResult.totalItems,
          nextPage: holdersResult.nextPage,
        };
      }

      // Fetch AddressDetail for resource analysis
      try {
        const data = await suprascanGraphql<{
          addressDetail: {
            isError: boolean;
            errorType: string | null;
            addressDetailSupra: { resources: string | null } | null;
          };
        }>(ADDRESS_DETAIL_QUERY, {
          address: faAddress,
          blockchainEnvironment: suprascanEnv,
          isAddressName: false,
        }, {
          endpoint: process.env.SUPRASCAN_GRAPHQL_URL || "https://suprascan.io/api/graphql",
          env: suprascanEnv,
        });

        const resourcesStr = data.addressDetail?.addressDetailSupra?.resources;
        // Only analyze if resources string is non-empty and valid-looking
        if (resourcesStr && typeof resourcesStr === "string" && resourcesStr.trim().length > 0 && !data.addressDetail.isError) {
          faResourceAnalysis = analyzeFaResources(resourcesStr);
        }
      } catch (resourceError) {
        // Silently fail - resource fetch is optional
        const debug = process.env.SSA_DEBUG_FA === "1";
        if (debug) {
          console.debug(`[FA] Failed to fetch AddressDetail resources: ${resourceError instanceof Error ? resourceError.message : String(resourceError)}`);
        }
      }
    } catch (error) {
      // Silently fail - holders and resource fetch are optional
      const debug = process.env.SSA_DEBUG_FA === "1";
      if (debug) {
        console.debug(`[FA] Failed to fetch holders/resources: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }

  // DUAL-NATURE HANDLING: If FA is dual-nature, run coin scan automatically
  // Only run coin scan if we have a valid coin type struct tag
  let coinScanResult: ScanResult | null = null;
  let coinTypeFromMetadata: string | undefined;
  
  // Helper: Check if coin type is a valid struct tag
  // Must start with 0x, contain exactly 2 occurrences of :: (3 segments), and not be 0x1::object::*
  function isValidCoinStructTag(tag: string | undefined): boolean {
    if (!tag || typeof tag !== "string") return false;
    const parts = tag.split("::");
    return tag.startsWith("0x") && parts.length === 3 && !tag.startsWith("0x1::object");
  }
  
  // Try to get coin type from metadata (inferred or user-provided)
  coinTypeFromMetadata = (metadata as any).coinType || process.env.TARGET_COIN_TYPE || process.env.FA_STRUCT_TAG;
  
  // Only run coin scan if dual-nature is detected AND we have a valid coin type struct tag
  if (metadata.isDualNature && isValidCoinStructTag(coinTypeFromMetadata)) {
    console.log(`[FA] Dual-nature token detected. Running coin scan for: ${coinTypeFromMetadata}`);
    try {
      const { scanCoinToken } = await import("./coinScanner.js");
      coinScanResult = await scanCoinToken(coinTypeFromMetadata!, {
        rpc_url: rpcUrl,
      });
    } catch (coinScanError) {
      console.warn(`[FA] Coin scan failed for dual-nature token: ${coinScanError instanceof Error ? coinScanError.message : String(coinScanError)}`);
      coinScanResult = null;
    }
  } else if (metadata.isDualNature && !isValidCoinStructTag(coinTypeFromMetadata)) {
    // Dual-nature detected but no valid coin type - log debug message
    const debug = process.env.SSA_DEBUG_FA === "1" || process.env.SSA_DEBUG_VIEW === "1";
    if (debug) {
      console.debug(`[FA] Dual-nature token detected but coin scan skipped (no valid coin type struct tag available)`);
    }
  }

  // FA scanning: metadata-only analysis (no module bytecode fetch from FA address)
  // FA address is a metadata address, not a module publisher
  const bytecodeData: {
    functionNames: string[];
    entryFunctions: string[];
    strings: string[];
    markers: string[];
  } = {
    functionNames: [],
    entryFunctions: [],
    strings: [],
    markers: [],
  };

  // No bytecode/ABI for FA scan (FA address is not a module publisher)
  const hasBytecode = false;
  const hasAbi = false;

  // Execute FA-specific rules (metadata-based only, no bytecode analysis)
  const faFindings = executeFARules(metadata, bytecodeData, false);
  
  // Execute FA holder concentration rule (if holders data available)
  const holderFindings = executeFAHolderConcentrationRule(faHoldersData);
  
  // LEVEL-1: Control Surface Verification - Convert resource analysis findings to SSA Finding format
  const resourceFindings: Finding[] = (faResourceAnalysis?.findings || []).map((f: FaResourceFinding): Finding => {
    const severityMap: Record<string, "info" | "low" | "medium" | "high" | "critical"> = {
      "INFO": "info",
      "LOW": "low",
      "MEDIUM": "medium",
      "HIGH": "high",
    };
    return {
      id: f.id,
      title: f.title,
      severity: severityMap[f.severity] || "info",
      confidence: 0.9, // Resource-based evidence is high confidence
      description: f.detail,
      recommendation: f.recommendation || "",
      evidence: {
        kind: "metadata" as const,
        matched: Object.keys(f.evidence || {}),
        locations: [],
      },
      references: [],
    };
  });

  // PART 1: Scan creator modules for FA control (ONLY if modules exist)
  // FA tokens may have NO publisher modules - only scan if modules list is non-empty
  const creatorModuleScans: Array<{
    moduleId: string;
    scanResult: ScanResult;
    bytecode_present?: boolean;
    abi_present?: boolean;
    module_scan_summary?: {
      verdict: Verdict;
      risk_score: number;
      findings_count: number;
    };
  }> = [];
  let creatorModuleFindings: Finding[] = [];
  let hasCreatorBytecode = false;
  let hasCustomModules = false;
  let creatorModules: Array<{ name: string; bytecode?: string; abi?: any }> = [];

  if (metadata.creator) {
    try {
      console.log(`[FA] Checking for modules at creator address: ${metadata.creator}`);
      
      // Use canonical v3-first, v2-fallback RPC client
      const rpcOptions: RpcClientOptions = {
        rpcUrl,
        timeout: 10000,
        retries: 2,
        retryDelay: 500,
      };

      try {
        const moduleListResponse = await fetchAccountModulesV3(metadata.creator, rpcOptions);
        
        if (moduleListResponse.error) {
          throw new Error(`RPC error: ${moduleListResponse.error.message}`);
        }

        const modules = moduleListResponse.modules || [];
        
        // Only proceed if modules exist (FA tokens may have NO publisher modules)
        if (modules.length === 0) {
          console.log(`[FA] No modules found at creator address (framework-managed FA)`);
          hasCustomModules = false;
        } else {
          hasCustomModules = true;
          
          // Extract module names (may be in name field or need to parse from ABI)
          creatorModules = modules.map((m) => {
            // If name is present, use it
            if (m.name) {
              return { name: m.name, bytecode: m.bytecode, abi: m.abi };
            }
            
            // If ABI has name, use it
            if (m.abi?.name) {
              return { name: m.abi.name, bytecode: m.bytecode, abi: m.abi };
            }
            
            // Fallback: try to infer from coin type or use placeholder
            // This shouldn't happen, but handle gracefully
            return { name: "unknown", bytecode: m.bytecode, abi: m.abi };
          }).filter((m) => m.name !== "unknown"); // Filter out unknowns

          console.log(`[FA] Found ${creatorModules.length} custom modules via RPC v3/v2`);
        }
      } catch (rpcError) {
        console.warn(`[FA] Module discovery failed: ${rpcError instanceof Error ? rpcError.message : String(rpcError)}`);
        // Treat as no custom modules (framework-managed)
        hasCustomModules = false;
      }

      // Only scan modules if custom modules exist
      if (hasCustomModules && creatorModules.length > 0) {
        // Identify candidate FA-control modules using heuristics
        const faControlKeywords = [
          "mint", "burn", "freeze", "blacklist", "pause", "admin", "owner", 
          "cap", "treasury", "supply", "upgrade", "governance", "token", 
          "fa", "fungible", "asset", "control", "manage"
        ];

        const candidateModules = creatorModules.filter((m) => {
          const moduleNameLower = m.name.toLowerCase();
          
          // Check module name
          if (faControlKeywords.some((keyword) => moduleNameLower.includes(keyword))) {
            return true;
          }
          
          // Check ABI for control-related functions
          if (m.abi?.exposed_functions) {
            const functionNames = m.abi.exposed_functions.map((f: any) => f.name?.toLowerCase() || "").join(" ");
            if (faControlKeywords.some((keyword) => functionNames.includes(keyword))) {
              return true;
            }
          }
          
          // Check bytecode strings if available (basic heuristic)
          if (m.bytecode) {
            // Simple check: if bytecode exists and module name suggests control, include it
            // More sophisticated analysis would require bytecode parsing
          }
          
          return false;
        });

        console.log(`[FA] Identified ${candidateModules.length} candidate FA-control modules: ${candidateModules.map((m) => m.name).join(", ")}`);

        // Scan each candidate module
        for (const module of candidateModules) {
          try {
            const moduleId: ModuleId = {
              address: metadata.creator,
              module_name: module.name,
            };

            console.log(`[FA] Scanning creator module: ${metadata.creator}::${module.name}`);
            
            // Run scan (will fetch bytecode/ABI via RPC if not already available)
            const moduleScanResult = await runScan(moduleId, {
              rpc_url: rpcUrl,
              proxy_base: proxyBase,
              scan_level: "quick",
            });

            creatorModuleScans.push({
              moduleId: `${metadata.creator}::${module.name}`,
              scanResult: moduleScanResult,
              bytecode_present: moduleScanResult.meta.rule_capabilities?.hasBytecodeOrSource || false,
              abi_present: moduleScanResult.meta.rule_capabilities?.hasAbi || false,
              module_scan_summary: {
                verdict: moduleScanResult.summary.verdict,
                risk_score: moduleScanResult.summary.risk_score,
                findings_count: moduleScanResult.findings.length,
              },
            });

            // Collect findings from module scans
            creatorModuleFindings.push(...moduleScanResult.findings);

            // Check if any module scan has bytecode
            if (moduleScanResult.meta.rule_capabilities?.hasBytecodeOrSource) {
              hasCreatorBytecode = true;
            }
          } catch (moduleScanError) {
            console.warn(`[FA] Failed to scan creator module ${module.name}: ${moduleScanError instanceof Error ? moduleScanError.message : String(moduleScanError)}`);
            // Add finding for failed module scan
            creatorModuleFindings.push({
              id: "FA-MODULE-SCAN-FAILED",
              title: "Creator Module Scan Failed",
              severity: "low",
              confidence: 0.5,
              description: `Failed to scan creator module "${module.name}" for FA control capabilities.`,
              recommendation: "Manually verify module security or provide module source code for analysis.",
              evidence: {
                kind: "heuristic",
                matched: [module.name],
                locations: [],
              },
              references: [],
            });
          }
        }
      } else {
        // No custom modules - framework-managed FA
        console.log(`[FA] No custom modules to scan (framework-managed FA)`);
      }
    } catch (creatorError) {
      console.warn(`[FA] Creator module discovery failed: ${creatorError instanceof Error ? creatorError.message : String(creatorError)}`);
      hasCustomModules = false;
    }
  }

  // LEVEL 1: Build Surface Area Report for FA
  const surfaceReport: SurfaceAreaReport = {
    kind: "fa",
    fa_surface: {
      surface_known: false,
      reason: "",
      control_modules: [],
      scanned_modules: [],
    },
  };

  // Try to load SupraScan evidence if available (do not fail if absent)
  try {
    const suprascanEvidencePath = process.env.SUPRASCAN_EVIDENCE_PATH;
    if (suprascanEvidencePath) {
      const { readFileSync } = await import("fs");
      try {
        const enrichedEvidence = JSON.parse(readFileSync(suprascanEvidencePath, "utf-8"));
        if (enrichedEvidence.kind === "fa" && enrichedEvidence.flags && enrichedEvidence.risk) {
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
    // This is expected if SupraScan evidence file doesn't exist or fs import fails
  }

  // Attempt BEST-EFFORT discovery of control modules
  if (metadata.creator) {
    // Check if we found control modules
    if (hasCustomModules && creatorModules.length > 0) {
      const controlModuleNames = creatorModules.map((m) => m.name);
      surfaceReport.fa_surface!.control_modules = controlModuleNames;
      
      // Check if control modules were scanned
      const scannedModuleNames = creatorModuleScans
        .filter((scan) => scan.bytecode_present || scan.abi_present)
        .map((scan) => scan.moduleId.split("::")[1]); // Extract module name from moduleId
      
      if (scannedModuleNames.length > 0) {
        surfaceReport.fa_surface!.surface_known = true;
        surfaceReport.fa_surface!.scanned_modules = scannedModuleNames;
        surfaceReport.fa_surface!.reason = `FA control modules discovered and scanned: ${scannedModuleNames.join(", ")}`;
      } else {
        surfaceReport.fa_surface!.surface_known = false;
        surfaceReport.fa_surface!.reason = `FA control modules discovered but not scanned (no bytecode/ABI available)`;
      }
    } else {
      // No custom modules - framework-managed FA
      surfaceReport.fa_surface!.surface_known = false;
      surfaceReport.fa_surface!.reason = "FA has no bytecode at FA address; control modules not resolved (framework-managed FA)";
    }
  } else {
    // No creator address
    surfaceReport.fa_surface!.surface_known = false;
    surfaceReport.fa_surface!.reason = "FA creator address unknown; cannot resolve control modules";
  }

  // Add finding based on control surface visibility
  if (metadata.creator) {
    if (hasCustomModules && !hasCreatorBytecode) {
      // Custom modules exist but bytecode/ABI not available - control surface is opaque
      faFindings.push({
        id: "SSA-L1-FA-OPAQUE-CONTROL-SURFACE",
        title: "FA Control Surface Unknown",
        severity: "medium",
        confidence: 0.7,
        description: surfaceReport.fa_surface!.reason || `FA control modules discovered but not scanned (no bytecode/ABI available)`,
        recommendation: "Verify FA control mechanisms. Custom FAs should have visible control surfaces with inspectable bytecode/ABI.",
        evidence: {
          kind: "heuristic",
          matched: ["fa_control_surface", "opaque"],
          locations: [],
        },
        references: [],
      });
    } else if (!hasCustomModules) {
      // Framework-managed FA - no custom modules at creator address
      faFindings.push({
        id: "FA-FRAMEWORK-MANAGED-001",
        title: "Framework-Managed FA (No Custom Publisher Modules)",
        severity: "info",
        confidence: 0.8,
        description: "No modules found at creator address; control surface likely framework-managed. Code-level verification not possible from publisher modules.",
        recommendation: "If stronger assurance is needed, link a related coin type / module or provide token source / docs.",
        evidence: {
          kind: "heuristic",
          matched: ["framework_managed", "no_custom_modules"],
          locations: [],
        },
        references: [],
      });
    }
  }

  // FA scan: metadata-only, no module rules (FA address is not a module publisher)
  const moduleFindings: Finding[] = [];

  // Determine code verification status first (needed for FA-CENTRAL-001)
  const adjacentCodeInspected = hasCreatorBytecode && hasCustomModules;
  const codeVerified = adjacentCodeInspected; // Only true when creator modules were scanned with bytecode
  
  // FA-CENTRAL-001 removed - deduplicated with SSA-L1-FA-OPAQUE-CONTROL-SURFACE
  // SSA-L1-FA-OPAQUE-CONTROL-SURFACE is the canonical finding for opaque control surface
  
  const allFindings = [...faFindings, ...moduleFindings, ...creatorModuleFindings, ...holderFindings, ...resourceFindings];
  
  // Gate HIGH/CRITICAL findings: only allow if bytecode/ABI present
  // hasBytecodeOrSource should mean "we have inspectable code evidence for control modules"
  const hasBytecodeOrSource = hasCreatorBytecode; // Only true if creator modules scanned with bytecode
  const filteredFindings = allFindings.filter((f) => {
    // Allow HIGH/CRITICAL only if bytecode/ABI is present
    if ((f.severity === "high" || f.severity === "critical") && !hasBytecodeOrSource) {
      // Remove HIGH/CRITICAL findings when no bytecode/ABI
      return false;
    }
    return true;
  });
  const severityCounts = calculateSeverityCounts(filteredFindings);
  let riskScore = calculateRiskScore(filteredFindings);
  
  // Optional: Risk score floor - if riskScore is 0 but there are INFO findings for unknown capabilities
  if (riskScore === 0) {
    const hasUnknownCapabilityInfo = filteredFindings.some(
      (f) => f.severity === "info" && (f.id === "FA-FREEZE-001" || f.id === "FA-UPGRADE-001")
    );
    if (hasUnknownCapabilityInfo) {
      riskScore = 1; // Set floor to 1 for presentation
    }
  }

  // Determine assurance level
  let assuranceLevel: "metadata_only" | "adjacent_code_inspected" | "code_verified";
  if (adjacentCodeInspected) {
    assuranceLevel = "adjacent_code_inspected";
  } else {
    assuranceLevel = "metadata_only";
  }

  // Determine verdict with explicit tiers
  let verdict: Verdict = "inconclusive";
  let verdictTier: VerdictTier = "inconclusive";
  let verdictReason: string | undefined;

  // Don't mark as INCONCLUSIVE solely due to missing coin type
  // Only mark as INCONCLUSIVE if metadata itself is unavailable
  if (!hasMetadata) {
    verdict = "inconclusive";
    verdictTier = "inconclusive";
    verdictReason = `FA metadata unavailable via public views/resources. ${metadata.fetchError || "No metadata found"}`;
  } else if (codeVerified && severityCounts.critical === 0 && severityCounts.high === 0) {
    // Code-verified PASS (creator modules scanned with bytecode)
    verdict = "pass";
    verdictTier = "verified";
    verdictReason = `Code-verified scan completed. No high-risk findings detected.`;
  } else if (codeVerified && (severityCounts.critical > 0 || severityCounts.high > 0)) {
    // Code-verified FAIL (creator modules scanned with bytecode)
    verdict = "fail";
    verdictTier = "fail";
    verdictReason = `Code-verified scan detected high/critical findings.`;
  } else if (!codeVerified && severityCounts.critical === 0 && severityCounts.high === 0) {
    // View-only PASS (no bytecode/source available)
    verdict = "pass";
    verdictTier = "metadata";
    verdictReason = `View-only scan completed. No high-risk findings detected.`;
  } else if (!hasBytecodeOrSource && filteredFindings.every((f) => f.severity === "low" || f.severity === "info")) {
    // Metadata-only PASS
    verdict = "pass";
    verdictTier = "metadata";
    if (coinScanResult && coinScanResult.meta.code_verified) {
      // Dual-nature with code-verified coin scan
      assuranceLevel = "code_verified";
      verdictReason = `FA: Metadata-Only PASS. Coin (dual-nature): Code-Verified PASS. No high-risk patterns detected in scanned publisher modules. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
    } else if (coinScanResult && !coinScanResult.meta.code_verified) {
      verdictReason = `Metadata-Only: no high-risk metadata red flags; code-level verification not available. FA tokens usually do not have publisher bytecode at the FA address; code-level verification is not possible unless a related coin module is discovered. Coin scan attempted but code not verified. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
    } else if (metadata.isDualNature && !coinScanResult) {
      verdictReason = `Metadata-Only: no high-risk metadata red flags; code-level verification not available. FA tokens usually do not have publisher bytecode at the FA address; code-level verification is not possible unless a related coin module is discovered. Dual-nature detected but coin scan unavailable. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
    } else if (adjacentCodeInspected) {
      assuranceLevel = "adjacent_code_inspected";
      verdictReason = `Adjacent Code Inspected: no high-risk findings in creator modules. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
    } else {
      verdictReason = `Metadata-Only: no high-risk metadata red flags; code-level verification not available. FA tokens usually do not have publisher bytecode at the FA address; code-level verification is not possible unless a related coin module is discovered. Note: PASS does NOT prove absence of backdoors; it only means no high-risk findings in available evidence.`;
    }
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

  // Get engine version (ESM-safe)
  function getEngineVersion(): string {
    try {
      const require = createRequire(import.meta.url);
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = dirname(__filename);
      const packagePath = join(__dirname, "../../package.json");
      const pkg = require(packagePath);
      return pkg.version || "0.1.0";
    } catch {
      return "0.1.0";
    }
  }


  return {
    request_id: requestId,
    target: {
      chain: "supra",
      module_address: faAddress,
      module_name: "fa_token",
      module_id: `${faAddress}::fa_token`,
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
      artifact_hash: `fa_${faAddress}`,
      binding_note: `FA token scan for ${faAddress}`,
      metadata: {
        fa_metadata: metadata,
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
        `fa_${faAddress}`,
        severityCounts,
        timestamp,
        codeVerified // Security Verified badge requires bytecode/source evidence
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
      artifact_mode: adjacentCodeInspected ? "view_plus_onchain_module" : "view_only",
      artifact_loaded: adjacentCodeInspected,
      artifact_components: {
        hasSource: false,
        hasAbi: false,
        hasBytecode: adjacentCodeInspected,
        origin: {
          kind: "manual",
          path: "fa_metadata_only",
        },
        onChainBytecodeFetched: adjacentCodeInspected,
      },
      rule_capabilities: {
        viewOnly: !hasCreatorBytecode || !hasCustomModules, // View-only unless creator modules scanned with bytecode
        hasAbi: creatorModuleScans.some((s) => s.abi_present) || false, // True if any creator module has ABI
        hasBytecodeOrSource: hasCreatorBytecode, // Only true if creator modules scanned with bytecode
        artifactMode: adjacentCodeInspected ? "view_plus_onchain_module" : "view_only",
      },
      verdict_reason: verdictReason,
      fa_metadata: metadata,
      creator_module_scans: creatorModuleScans.length > 0 ? creatorModuleScans : undefined,
      creator_modules_scanned: creatorModuleScans.length,
      metadata_verified: hasMetadata, // FA metadata verified
      code_verified: codeVerified, // Only true when creator modules were scanned with bytecode
      has_custom_modules: hasCustomModules, // Whether creator address has custom modules
      // LEVEL 4: Cross-checks for FA
      fa_cross_checks: crossChecks,
      verdict_tier: verdictTier, // Explicit verdict tier
      fa_rpc_plan: rpcPlan, // RPC plan debug info
      surface_report: surfaceReport,
      fa_resource_analysis: faResourceAnalysis ? {
        hasMintRef: faResourceAnalysis.caps.hasMintRef,
        hasBurnRef: faResourceAnalysis.caps.hasBurnRef,
        hasTransferRef: faResourceAnalysis.caps.hasTransferRef,
        hasDispatchFunctions: faResourceAnalysis.caps.hasDepositHook || faResourceAnalysis.caps.hasWithdrawHook || faResourceAnalysis.caps.hasDerivedBalanceHook,
        hasDepositFunction: faResourceAnalysis.caps.hasDepositHook,
        hasWithdrawFunction: faResourceAnalysis.caps.hasWithdrawHook,
        hasAdminControl: !!faResourceAnalysis.caps.owner,
        ownerAddress: faResourceAnalysis.caps.owner || undefined,
        currentSupply: faResourceAnalysis.caps.supplyCurrent || undefined,
        maxSupply: faResourceAnalysis.caps.supplyMax || undefined,
        isSupplyCapped: !!faResourceAnalysis.caps.supplyMax,
        resourcesParsedCount: faResourceAnalysis.parsedCount,
        hookModules: faResourceAnalysis.caps.hookModules,
      } : undefined,
    },
  };
}

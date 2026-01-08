// src/adapters/suprascan.ts
// SupraScan Evidence Mode Adapter
// Provides simplified interface for fetching Coin/FA details and address resources

import { suprascanGraphql, type SupraScanEnv } from "./suprascanGraphql.js";

export interface SupraScanCoinDetails {
  name?: string;
  symbol?: string;
  verified?: boolean;
  assetAddress?: string;
  decimals?: number;
  price?: string | number;
  totalSupply?: string | number;
  creatorAddress?: string;
  holders?: number;
}

export interface SupraScanFaDetails {
  faName?: string;
  faSymbol?: string;
  verified?: boolean;
  faAddress?: string;
  iconUrl?: string;
  decimals?: number;
  price?: string | number;
  totalSupply?: string | number;
  creatorAddress?: string;
  holders?: number;
  isDualNature?: boolean;
}

export interface SupraScanResource {
  type: string;
  data?: any;
}

export interface SupraScanAddressDetail {
  addressDetailSupra?: {
    resources?: string | null; // JSON string
    ownerAddress?: string | null;
    decimals?: number | null;
    totalSupply?: string | number | null;
    [key: string]: any;
  };
  isError?: boolean;
  errorType?: string | null;
}

/**
 * Resource type for parsed resources
 */
export interface Resource {
  type: string;
  data?: any;
}

/**
 * Parse resources from JSON string or array into Resource[]
 * Handles both string (JSON) and array inputs
 */
export function parseResources(resourcesJson: string | any[] | null | undefined): Resource[] {
  if (!resourcesJson) {
    return [];
  }

  // If already an array, normalize it
  if (Array.isArray(resourcesJson)) {
    return resourcesJson.map((item) => ({
      type: item.type || "",
      data: item.data,
    }));
  }

  // If string, parse JSON
  if (typeof resourcesJson === "string") {
    try {
      const parsed = JSON.parse(resourcesJson);
      if (Array.isArray(parsed)) {
        return parsed.map((item) => ({
          type: item.type || "",
          data: item.data,
        }));
      }
      return [];
    } catch (error) {
      // If parsing fails, return empty array
      return [];
    }
  }

  return [];
}

/**
 * Flags extracted from resources (matches PowerShell output fields)
 */
export interface Flags {
  // FA flags
  hasMintRef?: boolean;
  hasBurnRef?: boolean;
  hasTransferRef?: boolean;
  hasDepositHook?: boolean;
  hasWithdrawHook?: boolean;
  hasDerivedBalanceHook?: boolean;
  hasDispatchFunctions?: boolean;
  
  // Coin flags
  hasMintCap?: boolean;
  hasBurnCap?: boolean;
  hasFreezeCap?: boolean;
  hasTransferRestrictions?: boolean;
  
  // Common
  owner?: string | null;
  supplyCurrent?: string | null;
  supplyMax?: string | null;
  decimals?: number | null;
  
  // Additional metadata
  resourceCount?: number;
  resourceTypes?: string[];
}

/**
 * Extract flags from parsed resources
 * Matches PowerShell output fields for consistency
 */
export function extractFlags(resources: Resource[], kind: "fa" | "coin"): Flags {
  const flags: Flags = {
    resourceCount: resources.length,
    resourceTypes: resources.map((r) => r.type).filter(Boolean),
  };

  if (kind === "fa") {
    // Initialize FA flags
    flags.hasMintRef = false;
    flags.hasBurnRef = false;
    flags.hasTransferRef = false;
    flags.hasDepositHook = false;
    flags.hasWithdrawHook = false;
    flags.hasDerivedBalanceHook = false;
    flags.hasDispatchFunctions = false;

    // Extract FA-specific resources
    for (const resource of resources) {
      const type = resource.type || "";
      
      // ObjectCore for owner
      if (type.endsWith("::object::ObjectCore")) {
        flags.owner = resource.data?.owner || null;
      }
      
      // ConcurrentSupply for supply
      if (type.endsWith("::fungible_asset::ConcurrentSupply")) {
        if (resource.data?.current?.value != null) {
          flags.supplyCurrent = String(resource.data.current.value);
        }
        if (resource.data?.current?.max_value != null) {
          flags.supplyMax = String(resource.data.current.max_value);
        }
      }
      
      // Metadata for decimals
      if (type.endsWith("::fungible_asset::Metadata")) {
        if (resource.data?.decimals != null) {
          flags.decimals = Number(resource.data.decimals);
        }
      }
      
      // MintRef
      if (type.includes("MintRef") || type.endsWith("::fungible_asset::MintRef")) {
        flags.hasMintRef = true;
      }
      
      // BurnRef
      if (type.includes("BurnRef") || type.endsWith("::fungible_asset::BurnRef")) {
        flags.hasBurnRef = true;
      }
      
      // TransferRef
      if (type.includes("TransferRef") || type.endsWith("::fungible_asset::TransferRef")) {
        flags.hasTransferRef = true;
      }
      
      // DispatchFunctionStore for hooks
      if (type.endsWith("::fungible_asset::DispatchFunctionStore")) {
        flags.hasDispatchFunctions = true;
        const dispatch = resource.data;
        if (dispatch?.deposit_function?.vec && Array.isArray(dispatch.deposit_function.vec) && dispatch.deposit_function.vec.length > 0) {
          flags.hasDepositHook = true;
        }
        if (dispatch?.withdraw_function?.vec && Array.isArray(dispatch.withdraw_function.vec) && dispatch.withdraw_function.vec.length > 0) {
          flags.hasWithdrawHook = true;
        }
        if (dispatch?.derived_balance_function?.vec && Array.isArray(dispatch.derived_balance_function.vec) && dispatch.derived_balance_function.vec.length > 0) {
          flags.hasDerivedBalanceHook = true;
        }
      }
      
      // ManagedFungibleAsset (can contain refs)
      if (type.includes("ManagedFungibleAsset")) {
        const mfa = resource.data;
        if (mfa?.mint_ref) flags.hasMintRef = true;
        if (mfa?.burn_ref) flags.hasBurnRef = true;
        if (mfa?.transfer_ref) flags.hasTransferRef = true;
      }
    }
  } else if (kind === "coin") {
    // Initialize Coin flags
    flags.hasMintCap = false;
    flags.hasBurnCap = false;
    flags.hasFreezeCap = false;
    flags.hasTransferRestrictions = false;

    // Extract Coin-specific resources
    for (const resource of resources) {
      const type = resource.type || "";
      
      // CoinInfo for supply and capabilities
      if (type.includes("::coin::CoinInfo")) {
        const coinInfo = resource.data;
        if (coinInfo?.supply?.value != null) {
          flags.supplyCurrent = String(coinInfo.supply.value);
        }
        if (coinInfo?.decimals != null) {
          flags.decimals = Number(coinInfo.decimals);
        }
        if (coinInfo?.mint_events) {
          flags.hasMintCap = true;
        }
        if (coinInfo?.burn_events) {
          flags.hasBurnCap = true;
        }
        if (coinInfo?.freeze_events) {
          flags.hasFreezeCap = true;
        }
      }
      
      // MintCapability
      if (type.includes("MintCapability") || type.endsWith("::coin::MintCapability")) {
        flags.hasMintCap = true;
      }
      
      // BurnCapability
      if (type.includes("BurnCapability") || type.endsWith("::coin::BurnCapability")) {
        flags.hasBurnCap = true;
      }
      
      // FreezeCapability
      if (type.includes("FreezeCapability") || type.endsWith("::coin::FreezeCapability")) {
        flags.hasFreezeCap = true;
      }
      
      // TransferRestrictions
      if (type.includes("TransferRestrictions") || type.includes("transfer_restrictions")) {
        flags.hasTransferRestrictions = true;
      }
    }
  }

  return flags;
}

/**
 * Risk computation result
 */
export interface RiskResult {
  score: number; // 0-100 (higher = worse)
  labels: string[]; // Risk labels for categorization
}

/**
 * Compute risk score and labels from flags and details
 * Deterministic, JSON-serializable
 */
export function computeRisk(
  flags: Flags,
  details: SupraScanCoinDetails | SupraScanFaDetails | null,
  kind: "fa" | "coin"
): RiskResult {
  const labels: string[] = [];
  let score = 0;

  // Base risk from capabilities
  if (kind === "fa") {
    if (flags.hasMintRef) {
      score += 20;
      labels.push("has_mint_ref");
    }
    if (flags.hasBurnRef) {
      score += 15;
      labels.push("has_burn_ref");
    }
    if (flags.hasTransferRef) {
      score += 10;
      labels.push("has_transfer_ref");
    }
    if (flags.hasDepositHook) {
      score += 10;
      labels.push("has_deposit_hook");
    }
    if (flags.hasWithdrawHook) {
      score += 10;
      labels.push("has_withdraw_hook");
    }
    if (flags.hasDerivedBalanceHook) {
      score += 5;
      labels.push("has_derived_balance_hook");
    }
    if (flags.hasDispatchFunctions) {
      score += 5;
      labels.push("has_dispatch_functions");
    }
  } else if (kind === "coin") {
    if (flags.hasMintCap) {
      score += 20;
      labels.push("has_mint_cap");
    }
    if (flags.hasBurnCap) {
      score += 15;
      labels.push("has_burn_cap");
    }
    if (flags.hasFreezeCap) {
      score += 25;
      labels.push("has_freeze_cap");
    }
    if (flags.hasTransferRestrictions) {
      score += 15;
      labels.push("has_transfer_restrictions");
    }
  }

  // Risk modifiers from details
  if (details) {
    // Verified status reduces risk
    if (details.verified) {
      score = Math.max(0, score - 10);
      labels.push("verified");
    } else {
      score += 5;
      labels.push("unverified");
    }

    // High holder count suggests legitimacy (reduces risk)
    if (details.holders && details.holders > 100) {
      score = Math.max(0, score - 5);
      labels.push("high_holders");
    } else if (details.holders && details.holders === 0) {
      score += 10;
      labels.push("no_holders");
    }
  }

  // Supply-related risk
  if (flags.supplyCurrent) {
    const supply = parseFloat(flags.supplyCurrent);
    if (!isNaN(supply) && supply === 0) {
      score += 5;
      labels.push("zero_supply");
    }
  }

  // Owner presence (FA)
  if (kind === "fa" && flags.owner) {
    labels.push("has_owner");
  }

  // Clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  // Add risk tier label
  if (score >= 70) {
    labels.push("high_risk");
  } else if (score >= 40) {
    labels.push("medium_risk");
  } else if (score >= 20) {
    labels.push("low_risk");
  } else {
    labels.push("minimal_risk");
  }

  return { score, labels };
}

/**
 * Fetch Coin details from SupraScan GraphQL
 * Query: getCoinDetails(coinAddress, blockchainEnvironment)
 */
export async function getCoinDetails(
  coinAddress: string,
  blockchainEnvironment: SupraScanEnv = "mainnet"
): Promise<SupraScanCoinDetails | null> {
  const query = `
    query GetCoinDetails($coinAddress: String, $blockchainEnvironment: BlockchainEnvironment) {
      getCoinDetails(coinAddress: $coinAddress, blockchainEnvironment: $blockchainEnvironment) {
        __typename
        name
        symbol
        verified
        assetAddress
        decimals
        price
        totalSupply
        creatorAddress
        holders
      }
    }
  `;

  const variables = {
    coinAddress,
    blockchainEnvironment,
  };

  try {
    const data = await suprascanGraphql<{
      data?: {
        getCoinDetails?: SupraScanCoinDetails;
      };
      errors?: Array<{ message: string }>;
    }>(query, variables, {
      env: blockchainEnvironment,
      timeoutMs: 8000,
    });

    if (data.errors && data.errors.length > 0) {
      console.error(`[SupraScan] GraphQL errors: ${data.errors.map((e) => e.message).join(", ")}`);
      return null;
    }

    return data.data?.getCoinDetails ?? null;
  } catch (error) {
    console.error(`[SupraScan] Failed to fetch coin details: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Fetch FA details from SupraScan GraphQL
 * Query: getFaDetails(faAddress, blockchainEnvironment)
 */
export async function getFaDetails(
  faAddress: string,
  blockchainEnvironment: SupraScanEnv = "mainnet"
): Promise<SupraScanFaDetails | null> {
  const query = `
    query GetFaDetails($faAddress: String, $blockchainEnvironment: BlockchainEnvironment) {
      getFaDetails(faAddress: $faAddress, blockchainEnvironment: $blockchainEnvironment) {
        __typename
        faName
        faSymbol
        verified
        faAddress
        iconUrl
        decimals
        price
        totalSupply
        creatorAddress
        holders
        isDualNature
      }
    }
  `;

  // Normalize address (ensure 0x prefix)
  const normalizedAddress = faAddress.toLowerCase().startsWith("0x")
    ? faAddress.toLowerCase()
    : `0x${faAddress.toLowerCase()}`;

  const variables = {
    faAddress: normalizedAddress,
    blockchainEnvironment,
  };

  try {
    const data = await suprascanGraphql<{
      data?: {
        getFaDetails?: SupraScanFaDetails;
      };
      errors?: Array<{ message: string }>;
    }>(query, variables, {
      env: blockchainEnvironment,
      timeoutMs: 8000,
    });

    if (data.errors && data.errors.length > 0) {
      console.error(`[SupraScan] GraphQL errors: ${data.errors.map((e) => e.message).join(", ")}`);
      return null;
    }

    return data.data?.getFaDetails ?? null;
  } catch (error) {
    console.error(`[SupraScan] Failed to fetch FA details: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Fetch AddressDetail from SupraScan GraphQL
 * Query: addressDetail(address, page, offset, userWalletAddress, blockchainEnvironment, isAddressName)
 * Returns addressDetailSupra.resources (JSON string) parsed into array of {type, data}
 */
export async function addressDetail(
  address: string,
  blockchainEnvironment: SupraScanEnv = "mainnet",
  options: {
    page?: number;
    offset?: number;
    userWalletAddress?: string;
    isAddressName?: boolean;
  } = {}
): Promise<SupraScanAddressDetail | null> {
  // Use simplified query matching existing implementation
  // Optional parameters (page, offset, userWalletAddress) are supported but may not be used by API
  const query = `
    query AddressDetail(
      $address: String,
      $blockchainEnvironment: BlockchainEnvironment,
      $isAddressName: Boolean
    ) {
      addressDetail(
        address: $address,
        blockchainEnvironment: $blockchainEnvironment,
        isAddressName: $isAddressName
      ) {
        isError
        errorType
        addressDetailSupra {
          resources
          ownerAddress
          decimals
          totalSupply
        }
      }
    }
  `;

  // Normalize address (ensure 0x prefix)
  const normalizedAddress = address.toLowerCase().startsWith("0x")
    ? address.toLowerCase()
    : `0x${address.toLowerCase()}`;

  const variables = {
    address: normalizedAddress,
    blockchainEnvironment,
    isAddressName: options.isAddressName ?? false,
  };

  try {
    const data = await suprascanGraphql<{
      data?: {
        addressDetail?: SupraScanAddressDetail;
      };
      errors?: Array<{ message: string }>;
    }>(query, variables, {
      env: blockchainEnvironment,
      timeoutMs: 8000,
    });

    if (data.errors && data.errors.length > 0) {
      console.error(`[SupraScan] GraphQL errors: ${data.errors.map((e) => e.message).join(", ")}`);
      return null;
    }

    return data.data?.addressDetail ?? null;
  } catch (error) {
    console.error(`[SupraScan] Failed to fetch address detail: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * SupraScan GraphQL API helper for FA token and Coin token metadata
 * Public indexer fallback when RPC view calls fail or return empty
 */

import { suprascanGraphql, type SupraScanEnv } from "../adapters/suprascanGraphql.js";

export interface SupraScanFaDetails {
  faName?: string;
  faSymbol?: string;
  verified?: boolean;
  faAddress?: string;
  iconUrl?: string;
  decimals?: number | undefined;
  totalSupply?: string | number | undefined;
  creatorAddress?: string;
  holders?: number | undefined;
  isDualNature?: boolean | undefined;
  price?: string | number | undefined;
}

export interface SupraScanGraphQLResponse {
  data?: {
    getFaDetails?: SupraScanFaDetails;
  };
  errors?: Array<{ message: string }>;
}

/**
 * Fetch FA token details from SupraScan GraphQL API
 * @param faAddress - FA token address (with or without 0x prefix)
 * @param env - Blockchain environment: "mainnet" or "testnet" (default: "mainnet")
 * @returns FA details or null if fetch fails
 */
export async function fetchFaDetailsFromSupraScan(
  faAddress: string,
  env?: "mainnet" | "testnet"
): Promise<SupraScanFaDetails | null> {
  // Normalize and validate environment (must be lowercase)
  const envLower = (env || process.env.SUPRASCAN_ENV || "mainnet").toLowerCase();
  const validEnvs: SupraScanEnv[] = ["mainnet", "testnet"];
  const normalizedEnv: SupraScanEnv = validEnvs.includes(envLower as SupraScanEnv) ? (envLower as SupraScanEnv) : "mainnet";

  // Normalize address (ensure 0x prefix)
  const normalizedAddress = faAddress.toLowerCase().startsWith("0x")
    ? faAddress.toLowerCase()
    : `0x${faAddress.toLowerCase()}`;

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

  const variables = {
    faAddress: normalizedAddress,
    blockchainEnvironment: normalizedEnv, // Send lowercase, not uppercase
  };

  try {
    // Use adapter function which normalizes endpoint and handles errors
    const json = await suprascanGraphql<SupraScanGraphQLResponse>(
      query,
      variables,
      {
        env: normalizedEnv,
        timeoutMs: 8000,
      }
    );

    // Validate response shape - defensive handling
    if (!json.data || !json.data.getFaDetails) {
      return null;
    }

    const rawDetails = json.data.getFaDetails;
    
    // Normalize and parse fields safely
    const normalizedDetails: SupraScanFaDetails = {
      faName: rawDetails.faName || undefined,
      faSymbol: rawDetails.faSymbol || undefined,
      verified: rawDetails.verified !== undefined ? Boolean(rawDetails.verified) : undefined,
      faAddress: rawDetails.faAddress || undefined,
      iconUrl: rawDetails.iconUrl || undefined,
      decimals: rawDetails.decimals !== undefined && rawDetails.decimals !== null 
        ? Number(rawDetails.decimals) 
        : undefined,
      totalSupply: rawDetails.totalSupply !== undefined && rawDetails.totalSupply !== null
        ? rawDetails.totalSupply // Keep as string | number, don't coerce too early
        : undefined,
      creatorAddress: rawDetails.creatorAddress || undefined,
      holders: rawDetails.holders !== undefined && rawDetails.holders !== null
        ? Number(rawDetails.holders)
        : undefined,
      isDualNature: rawDetails.isDualNature !== undefined ? Boolean(rawDetails.isDualNature) : undefined,
      price: rawDetails.price !== undefined && rawDetails.price !== null
        ? rawDetails.price // Keep as string | number
        : undefined,
    };

    // Debug logging: print which fields were present (behind SSA_DEBUG_FA)
    const debug = process.env.SSA_DEBUG_FA === "1";
    if (debug) {
      const presentFields = Object.entries(normalizedDetails)
        .filter(([_, value]) => value !== undefined && value !== null)
        .map(([key, _]) => key)
        .join(", ");
      console.debug(`[SupraScan] getFaDetails fields present: ${presentFields || "none"}`);
    }

    return normalizedDetails;
  } catch (error) {
    // Friendly error handling - return null instead of throwing
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    if (errorMessage.includes("aborted") || errorMessage.includes("timeout")) {
      console.debug(`[SupraScan] GraphQL request timeout for ${normalizedAddress}`);
    } else {
      console.debug(`[SupraScan] GraphQL fetch failed: ${errorMessage}`);
    }
    return null;
  }
}

export interface SupraScanCoinDetails {
  name?: string; // GraphQL field: name (not coinName)
  symbol?: string; // GraphQL field: symbol (not coinSymbol)
  verified?: boolean;
  assetAddress?: string; // GraphQL field: assetAddress (not coinAddress)
  iconUrl?: string;
  decimals?: number;
  price?: string; // Price if available
  totalSupply?: string;
  creatorAddress?: string;
  holders?: number;
  isDualNature?: boolean; // True if coin is also an FA
}

/**
 * Fetch Coin token details from SupraScan GraphQL API
 * @param coinType - Coin type struct tag (e.g., "0xPUBLISHER::MODULE::STRUCT")
 * @param env - Blockchain environment: "mainnet" or "testnet" (default: "mainnet")
 * @returns Coin details or null if fetch fails
 */
export async function fetchCoinDetailsFromSupraScan(
  coinType: string,
  env?: "mainnet" | "testnet"
): Promise<SupraScanCoinDetails | null> {
  // Normalize and validate environment (must be lowercase)
  const envLower = (env || process.env.SUPRASCAN_ENV || "mainnet").toLowerCase();
  const validEnvs: SupraScanEnv[] = ["mainnet", "testnet"];
  const normalizedEnv: SupraScanEnv = validEnvs.includes(envLower as SupraScanEnv) ? (envLower as SupraScanEnv) : "mainnet";

  // Normalize coin type (ensure proper format)
  const normalizedCoinType = coinType.trim();

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
    coinAddress: normalizedCoinType,
    blockchainEnvironment: normalizedEnv, // Send lowercase, not uppercase
  };

  try {
    // Use adapter function which normalizes endpoint and handles errors
    const data = await suprascanGraphql<{
      data?: {
        getCoinDetails?: SupraScanCoinDetails;
      };
      errors?: Array<{ message: string }>;
    }>(
      query,
      variables,
      {
        env: normalizedEnv,
        timeoutMs: 8000,
      }
    );

    // Validate response shape
    if (!data.data || !data.data.getCoinDetails) {
      return null;
    }

    return data.data.getCoinDetails;
  } catch (error) {
    // Friendly error handling - return null instead of throwing
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    if (errorMessage.includes("aborted") || errorMessage.includes("timeout")) {
      console.debug(`[SupraScan] GraphQL request timeout for ${normalizedCoinType}`);
    } else {
      console.debug(`[SupraScan] GraphQL fetch failed: ${errorMessage}`);
    }
    return null;
  }
}

export interface SupraScanFaHoldersResponse {
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
  isError: boolean;
  errorType?: string | null;
}

export interface SupraScanFaHoldersGraphQLResponse {
  data?: {
    getFaHolders?: SupraScanFaHoldersResponse;
  };
  errors?: Array<{ message: string }>;
}

/**
 * Fetch FA token holders from SupraScan GraphQL API
 * @param faAddress - FA token address (with or without 0x prefix)
 * @param env - Blockchain environment: "mainnet" or "testnet"
 * @param page - Page number (default: 1)
 * @param rowsPerPage - Rows per page (default: 10)
 * @returns FA holders data or null if fetch fails
 */
export async function fetchFaHoldersFromSupraScan(
  faAddress: string,
  env: "mainnet" | "testnet",
  page: number = 1,
  rowsPerPage: number = 10
): Promise<SupraScanFaHoldersResponse | null> {
  // Normalize and validate environment (must be lowercase)
  const envLower = env.toLowerCase();
  const validEnvs: SupraScanEnv[] = ["mainnet", "testnet"];
  const normalizedEnv: SupraScanEnv = validEnvs.includes(envLower as SupraScanEnv) ? (envLower as SupraScanEnv) : "mainnet";

  // Normalize address (ensure 0x prefix)
  const normalizedAddress = faAddress.toLowerCase().startsWith("0x")
    ? faAddress.toLowerCase()
    : `0x${faAddress.toLowerCase()}`;

  const query = `
    query GetFaHolders($faAddress: String, $page: Int, $rowsPerPage: Int, $blockchainEnvironment: BlockchainEnvironment) {
      getFaHolders(faAddress: $faAddress, page: $page, rowsPerPage: $rowsPerPage, blockchainEnvironment: $blockchainEnvironment) {
        faHolders {
          address
          addressAlias
          quantity
          value
          percentage
        }
        pageNumber
        pageCount
        totalItems
        nextPage
        isError
        errorType
      }
    }
  `;

  const variables = {
    faAddress: normalizedAddress,
    page,
    rowsPerPage,
    blockchainEnvironment: normalizedEnv,
  };

  try {
    // Use adapter function which normalizes endpoint and handles errors
    const json = await suprascanGraphql<SupraScanFaHoldersGraphQLResponse>(
      query,
      variables,
      {
        env: normalizedEnv,
        timeoutMs: 8000,
      }
    );

    // Handle GraphQL errors (shouldn't happen with adapter, but check anyway)
    if (json.errors && json.errors.length > 0) {
      const errorMessages = json.errors.map((e) => e.message).join("; ");
      throw new Error(`SupraScan GraphQL errors: ${errorMessages}`);
    }

    // Validate response shape - defensive handling
    if (!json.data || !json.data.getFaHolders) {
      return null;
    }

    const rawHolders = json.data.getFaHolders;

    // Check if response indicates an error
    if (rawHolders.isError) {
      const debug = process.env.SSA_DEBUG_FA === "1";
      if (debug) {
        console.debug(
          `[SupraScan] getFaHolders returned error: ${rawHolders.errorType || "unknown"}`
        );
      }
      return null;
    }

    // Normalize and parse fields safely
    const normalizedHolders: SupraScanFaHoldersResponse = {
      faHolders: rawHolders.faHolders.map((holder) => ({
        address: holder.address || "",
        addressAlias: holder.addressAlias || null,
        quantity: holder.quantity || "0", // Keep as string
        value: holder.value || null,
        percentage:
          holder.percentage !== undefined && holder.percentage !== null
            ? Number(holder.percentage)
            : undefined,
      })),
      pageNumber: Number(rawHolders.pageNumber) || 1,
      pageCount: Number(rawHolders.pageCount) || 0,
      totalItems: Number(rawHolders.totalItems) || 0,
      nextPage: Boolean(rawHolders.nextPage),
      isError: false, // Already checked above
      errorType: null,
    };

    return normalizedHolders;
  } catch (error) {
    // Friendly error handling - return null instead of throwing
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    const debug = process.env.SSA_DEBUG_FA === "1";
    if (errorMessage.includes("aborted") || errorMessage.includes("timeout")) {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL request timeout for FA holders ${normalizedAddress}`
        );
      }
    } else {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL fetch failed for FA holders: ${errorMessage}`
        );
      }
    }
    return null;
  }
}

export interface SupraScanTransactionSummary {
  // Top-level fields (normalized from getAllTransactions)
  transactionHash: string;
  senderAddress: string;
  senderName?: string | null;
  receiverAddress?: string | null;
  receiverName?: string | null;
  transferAmount: string;
  transferAmountUsd?: string | null;
  gasSUPRA?: string | null;
  gasUSD?: string | null;
  transactionStatus: string;
  confirmationTime?: string | null;
  tokenName?: string | null;
  functionName?: string | null;
  type?: string | null;
  vmType?: string | null;
  receivers?: Array<{
    walletAddress: string;
    walletAlias?: string | null;
    isSpecialAddress?: boolean;
    isContractAddress?: boolean;
  }>;
  senders?: Array<{
    walletAddress: string;
    walletAlias?: string | null;
    isSpecialAddress?: boolean;
    isContractAddress?: boolean;
  }>;
  // Nested format (for raw GraphQL responses)
  transactionBasicInfo?: {
    transactionHash?: string;
    senderAddress?: string;
    receiverAddress?: string;
    transferAmount?: string;
    confirmationTime?: string;
    transactionStatus?: string;
    functionName?: string;
    type?: string;
  };
}

export interface SupraScanTransactionsResponse {
  transactions: SupraScanTransactionSummary[];
  pageNumber: number;
  pageCount: number;
  totalItems: number;
  nextPage: boolean;
  foundCount: number;
  isError: boolean;
  errorType?: string | null;
}

export interface SupraScanTransactionsGraphQLResponse {
  data?: {
    getAllTransactions?: SupraScanTransactionsResponse;
  };
  errors?: Array<{ message: string }>;
}

/**
 * Fetch all transactions from SupraScan GraphQL API
 * @param args - Query arguments including blockchain environment and optional filters
 * @returns Transactions data or null if fetch fails
 */
export async function fetchAllTransactionsFromSupraScan(args: {
  blockchainEnvironment: "mainnet" | "testnet";
  page?: number;
  rowsPerPage?: number;
  searchText?: string;
  address?: string;
  token?: string;
  [key: string]: any; // Allow passthrough of other filters
}): Promise<SupraScanTransactionsResponse | null> {
  // Normalize and validate environment (must be lowercase)
  const envLower = args.blockchainEnvironment.toLowerCase();
  const validEnvs: SupraScanEnv[] = ["mainnet", "testnet"];
  const normalizedEnv: SupraScanEnv = validEnvs.includes(envLower as SupraScanEnv) ? (envLower as SupraScanEnv) : "mainnet";

  const page = args.page ?? 1;
  const rowsPerPage = args.rowsPerPage ?? 10;

  // Build variables object, filtering out undefined values
  const variables: Record<string, any> = {
    blockchainEnvironment: normalizedEnv,
    page,
    rowsPerPage,
  };

  // Add optional filters if provided
  if (args.searchText !== undefined) variables.searchText = args.searchText;
  if (args.address !== undefined) variables.address = args.address;
  if (args.token !== undefined) variables.token = args.token;

  // Add any other passthrough filters
  Object.keys(args).forEach((key) => {
    if (
      !["blockchainEnvironment", "page", "rowsPerPage", "searchText", "address", "token"].includes(key) &&
      args[key] !== undefined
    ) {
      variables[key] = args[key];
    }
  });

  const query = `
    query GetAllTransactions($blockchainEnvironment: BlockchainEnvironment, $page: Int, $rowsPerPage: Int, $searchText: String, $address: String, $token: String) {
      getAllTransactions(blockchainEnvironment: $blockchainEnvironment, page: $page, rowsPerPage: $rowsPerPage, searchText: $searchText, address: $address, token: $token) {
        transactions {
          transactionBasicInfo {
            senderAddress
            senderName
            receiverAddress
            receiverName
            transferAmount
            transferAmountUsd
            confirmationTime
            confirmationTimeAgo
            gasSUPRA
            gasUSD
            transactionHash
            transactionStatus
            confirmationCount
            tokenName
            type
            functionName
            receivers {
              walletAddress
              walletAlias
              isSpecialAddress
              isContractAddress
            }
            senders {
              walletAddress
              walletAlias
              isSpecialAddress
              isContractAddress
            }
            transferDetails
            transferFADetails
            vmType
          }
          transactionAdvancedInfo {
            blockHash
            blockHeight
          }
        }
        pageNumber
        pageCount
        totalItems
        nextPage
        foundCount
        isError
        errorType
      }
    }
  `;

  try {
    // Use adapter function which normalizes endpoint and handles errors
    // Timeout is handled internally by suprascanGraphql adapter
    const json = await suprascanGraphql<SupraScanTransactionsGraphQLResponse>(
      query,
      variables,
      {
        env: normalizedEnv,
        timeoutMs: 8000,
      }
    );

    // Handle GraphQL errors (shouldn't happen with adapter, but check anyway)
    if (json.errors && json.errors.length > 0) {
      const errorMessages = json.errors.map((e) => e.message).join("; ");
      throw new Error(`SupraScan GraphQL errors: ${errorMessages}`);
    }

    // Validate response shape - defensive handling
    if (!json.data || !json.data.getAllTransactions) {
      return null;
    }

    const rawTransactions = json.data.getAllTransactions;

    // Check if response indicates an error
    if (rawTransactions.isError) {
      const debug = process.env.SSA_DEBUG_VIEW === "1";
      if (debug) {
        console.debug(
          `[SupraScan] getAllTransactions returned error: ${rawTransactions.errorType || "unknown"}`
        );
      }
      return null;
    }

    // Normalize and parse fields safely
    const normalizedTransactions: SupraScanTransactionsResponse = {
      transactions: rawTransactions.transactions.map((tx: any) => {
        const basicInfo = tx.transactionBasicInfo || {};
        return {
          transactionHash: basicInfo.transactionHash || "",
          senderAddress: basicInfo.senderAddress || "",
          senderName: basicInfo.senderName || null,
          receiverAddress: basicInfo.receiverAddress || null,
          receiverName: basicInfo.receiverName || null,
          transferAmount: basicInfo.transferAmount || "0",
          transferAmountUsd: basicInfo.transferAmountUsd || null,
          gasSUPRA: basicInfo.gasSUPRA || null,
          gasUSD: basicInfo.gasUSD || null,
          transactionStatus: basicInfo.transactionStatus || "unknown",
          confirmationTime: basicInfo.confirmationTime || null,
          tokenName: basicInfo.tokenName || null,
          functionName: basicInfo.functionName || null,
          type: basicInfo.type || null,
          vmType: basicInfo.vmType || null,
          receivers: basicInfo.receivers?.map((r: any) => ({
            walletAddress: r.walletAddress || "",
            walletAlias: r.walletAlias || null,
            isSpecialAddress: r.isSpecialAddress === true,
            isContractAddress: r.isContractAddress === true,
          })) || [],
          senders: basicInfo.senders?.map((s: any) => ({
            walletAddress: s.walletAddress || "",
            walletAlias: s.walletAlias || null,
            isSpecialAddress: s.isSpecialAddress === true,
            isContractAddress: s.isContractAddress === true,
          })) || [],
        };
      }),
      pageNumber: Number(rawTransactions.pageNumber) || 1,
      pageCount: Number(rawTransactions.pageCount) || 0,
      totalItems: Number(rawTransactions.totalItems) || 0,
      nextPage: Boolean(rawTransactions.nextPage),
      foundCount: Number(rawTransactions.foundCount) || 0,
      isError: false, // Already checked above
      errorType: null,
    };

    return normalizedTransactions;
  } catch (error) {
    // Note: timeoutId is handled internally by suprascanGraphql adapter
    // No need to clear here as it's not directly used in this function
    // Friendly error handling - return null instead of throwing
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    const debug = process.env.SSA_DEBUG_VIEW === "1";
    if (errorMessage.includes("aborted")) {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL request timeout for getAllTransactions`
        );
      }
    } else {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL fetch failed for getAllTransactions: ${errorMessage}`
        );
      }
    }
    return null;
  }
}

export interface SupraScanAddressDetail {
  addressDetailSupra?: {
    resources?: string; // JSON-encoded string
    [key: string]: any;
  };
  [key: string]: any;
}

export interface SupraScanAddressDetailGraphQLResponse {
  data?: {
    addressDetail?: SupraScanAddressDetail;
  };
  errors?: Array<{ message: string }>;
}

/**
 * Fetch address detail from SupraScan GraphQL API
 * @param address - Address to query (FA address)
 * @param env - Blockchain environment: "mainnet" or "testnet"
 * @param isAddressName - Whether address is a name (default: false)
 * @returns Address detail or null if fetch fails
 */
export async function fetchAddressDetailFromSupraScan(
  address: string,
  env: "mainnet" | "testnet" = "mainnet",
  isAddressName: boolean = false
): Promise<SupraScanAddressDetail | null> {
  const graphqlUrl =
    process.env.SUPRASCAN_GRAPHQL_URL || "https://suprascan.io/api/graphql";

  // Normalize and validate environment (must be lowercase)
  const envLower = env.toLowerCase();
  const validEnvs: SupraScanEnv[] = ["mainnet", "testnet"];
  const normalizedEnv: SupraScanEnv = validEnvs.includes(envLower as SupraScanEnv) ? (envLower as SupraScanEnv) : "mainnet";

  // Normalize address (ensure 0x prefix)
  const normalizedAddress = address.toLowerCase().startsWith("0x")
    ? address.toLowerCase()
    : `0x${address.toLowerCase()}`;

  const query = `
    query AddressDetail($address: String, $blockchainEnvironment: BlockchainEnvironment, $isAddressName: Boolean) {
      addressDetail(address: $address, blockchainEnvironment: $blockchainEnvironment, isAddressName: $isAddressName) {
        addressDetailSupra {
          resources
        }
      }
    }
  `;

  const variables = {
    address: normalizedAddress,
    blockchainEnvironment: normalizedEnv,
    isAddressName,
  };

  let timeoutId: NodeJS.Timeout | null = null;
  try {
    // Add timeout (8 seconds)
    const controller = new AbortController();
    timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(graphqlUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query,
        variables,
      }),
      signal: controller.signal,
    });

    // Clear timeout immediately after fetch completes
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `SupraScan GraphQL failed (${response.status}): ${errorText}`
      );
    }

    const json = (await response.json()) as SupraScanAddressDetailGraphQLResponse;

    // Handle GraphQL errors
    if (json.errors && json.errors.length > 0) {
      const errorMessages = json.errors.map((e) => e.message).join("; ");
      throw new Error(`SupraScan GraphQL errors: ${errorMessages}`);
    }

    // Validate response shape - defensive handling
    if (!json.data || !json.data.addressDetail) {
      return null;
    }

    return json.data.addressDetail;
  } catch (error) {
    // Always clear timeout in error case
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
    // Friendly error handling - return null instead of throwing
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    const debug = process.env.SSA_DEBUG_FA === "1" || process.env.SSA_DEBUG_VIEW === "1";
    if (errorMessage.includes("aborted")) {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL request timeout for AddressDetail ${normalizedAddress}`
        );
      }
    } else {
      if (debug) {
        console.debug(
          `[SupraScan] GraphQL fetch failed for AddressDetail: ${errorMessage}`
        );
      }
    }
    return null;
  }
}

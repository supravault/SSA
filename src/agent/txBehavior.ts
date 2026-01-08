// src/agent/txBehavior.ts
// Level 3 Behavior Evidence: Sample recent transactions and validate entry points

import { fetchAllTransactionsFromSupraScan, SupraScanTransactionSummary } from "../rpc/supraScanGraphql.js";

/**
 * Entry point identifier extracted from transaction
 */
export interface InvokedEntry {
  moduleAddress: string;
  moduleName: string;
  functionName: string;
  /** Full identifier: address::module::function */
  fullId: string;
  /** Transaction hash where this entry was invoked */
  txHash: string;
  /** Timestamp of the transaction (if available) */
  timestamp?: string;
}

/**
 * Phantom entry: an entry point invoked in transactions but not present in pinned ABI
 */
export interface PhantomEntry {
  moduleAddress: string;
  moduleName: string;
  functionName: string;
  fullId: string;
  /** Transaction hashes where this phantom entry was invoked */
  txHashes: string[];
  /** Why this is flagged as phantom */
  reason: string;
}

/**
 * Behavior evidence status
 */
export type BehaviorStatus = "sampled" | "ok_empty" | "unavailable" | "no_activity" | "error";

/**
 * Behavior evidence result from transaction sampling
 */
export interface BehaviorEvidence {
  status: BehaviorStatus;
  /** Number of transactions sampled */
  tx_count: number;
  /** All unique entry points invoked across sampled transactions */
  invoked_entries: InvokedEntry[];
  /** Entry points invoked but not present in pinned ABI */
  phantom_entries: PhantomEntry[];
  /** True if ABI is opaque/empty but transaction activity exists */
  opaque_active: boolean;
  /** Reason for opaque_active flag (if true) */
  opaque_active_reason?: string;
  /** Source used for transaction data */
  source?: string;
  /** Timestamp of sampling */
  sampled_at?: string;
  /** Error message if status is "error" or "unavailable" */
  error?: string;
  /** Addresses that were sampled for transactions */
  sampled_addresses?: string[];
  /** Number of addresses that were sampled */
  sampled_address_count?: number;
  /** Sources attempted in order */
  attempted_sources?: string[];
  /** Whether v2 endpoint was preferred */
  prefer_v2?: boolean;
  /** Details about attempted sources (keyed by source name) */
  source_details?: {
    [sourceName: string]: {
      httpStatus?: number;
      normalizedCount?: number;
      error?: string;
    };
  };
  /** Warnings about probe addresses */
  warnings?: string[];
}

/**
 * Options for sampling recent transaction behavior
 */
export interface SampleBehaviorOptions {
  /** FA object address (for FA tokens) */
  faAddress?: string;
  /** Coin type (for legacy coins) */
  coinType?: string;
  /** Module addresses to query for transactions (hook modules, coin-defining module) */
  moduleAddresses?: string[];
  /** Owner address (for FA tokens - primary tx address) */
  ownerAddress?: string;
  /** Additional addresses to probe for transactions (deduped, normalized) */
  probeAddresses?: string[];
  /** Maximum number of transactions to sample */
  limit?: number;
  /** Timeout in milliseconds */
  timeoutMs?: number;
  /** Pinned ABI entry functions for validation (keyed by moduleId) */
  pinnedEntryFunctions?: Map<string, string[]>;
  /** Whether ABI is opaque (empty or couldn't be fetched) */
  abiOpaque?: boolean;
  /** RPC URL to try for transaction data (primary source) */
  rpcUrl?: string;
  /** Prefer v2 endpoint for account transaction sampling */
  preferV2?: boolean;
}

/**
 * Parse function name from SupraScan format
 * SupraScan returns functionName in format: "module_address::module_name::function_name" or just "function_name"
 */
function parseFunctionName(functionName: string | null | undefined): {
  moduleAddress: string | null;
  moduleName: string | null;
  functionName: string | null;
} {
  if (!functionName) {
    return { moduleAddress: null, moduleName: null, functionName: null };
  }

  // Try to parse full format: 0xADDR::module::function
  const parts = functionName.split("::");
  if (parts.length >= 3) {
    return {
      moduleAddress: parts[0].toLowerCase(),
      moduleName: parts[1],
      functionName: parts.slice(2).join("::"), // Handle nested function names
    };
  }

  // If only function name, we can't determine module
  return {
    moduleAddress: null,
    moduleName: null,
    functionName: functionName,
  };
}

/**
 * Extract function name from transaction payload
 * Checks common fields: function, entry_function_id, payload.function
 */
function extractFunctionFromTx(tx: any): string | null {
  // Try various common fields
  if (tx.function && typeof tx.function === "string") {
    return tx.function;
  }
  if (tx.entry_function_id && typeof tx.entry_function_id === "string") {
    return tx.entry_function_id;
  }
  if (tx.entryFunctionId && typeof tx.entryFunctionId === "string") {
    return tx.entryFunctionId;
  }
  if (tx.payload) {
    if (typeof tx.payload === "string") {
      try {
        const parsed = JSON.parse(tx.payload);
        if (parsed.function && typeof parsed.function === "string") {
          return parsed.function;
        }
      } catch {
        // Not JSON, ignore
      }
    } else if (isRecord(tx.payload)) {
      if (typeof tx.payload.function === "string") {
        return tx.payload.function;
      }
      if (typeof tx.payload.entry_function_id === "string") {
        return tx.payload.entry_function_id;
      }
    }
  }
  if (tx.functionName && typeof tx.functionName === "string") {
    return tx.functionName;
  }
  
  return null;
}

/**
 * Normalize module address for comparison
 */
function normalizeAddress(addr: string | null | undefined): string | null {
  if (!addr) return null;
  const lower = addr.toLowerCase().trim();
  return lower.startsWith("0x") ? lower : `0x${lower}`;
}

/**
 * Type guard: check if value is a record (object with string keys)
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Safely extract an array field from a record
 */
function getArrayField(record: unknown, fieldName: string): unknown[] | undefined {
  if (!isRecord(record)) {
    return undefined;
  }
  const value = record[fieldName];
  return Array.isArray(value) ? value : undefined;
}

/**
 * Normalize v3 transaction response (expects array directly, or weird shapes like { value: [], Count: 0 })
 */
export function normalizeV3TxResponse(data: unknown): any[] {
  if (Array.isArray(data)) {
    return data;
  }
  
  // Handle weird shapes like { value: [], Count: 0 }
  if (isRecord(data)) {
    const value = getArrayField(data, "value");
    if (value) {
      return value;
    }
  }
  
  return [];
}

/**
 * Normalize v2 transaction response (expects { record: [...] } or variations)
 */
export function normalizeV2TxResponse(data: unknown): any[] {
  if (!isRecord(data)) {
    return [];
  }
  
  // Check data.record
  const record = data.record;
  
  // If record is an array, use it
  if (Array.isArray(record)) {
    return record;
  }
  
  // If record is {} or null, return empty array
  if (record === null || record === undefined || (isRecord(record) && Object.keys(record).length === 0)) {
    return [];
  }
  
  // If record is an object, check record.transactions
  if (isRecord(record)) {
    const recordTransactions = getArrayField(record, "transactions");
    if (recordTransactions) {
      return recordTransactions;
    }
    
    // Check record.data
    const recordData = getArrayField(record, "data");
    if (recordData) {
      return recordData;
    }
  }
  
  // Fallback: check top-level transactions or data fields
  const transactions = getArrayField(data, "transactions");
  if (transactions) {
    return transactions;
  }
  const dataArray = getArrayField(data, "data");
  if (dataArray) {
    return dataArray;
  }
  
  return [];
}

/**
 * Normalize transaction response from RPC endpoints (legacy compatibility)
 */
function normalizeTransactionResponse(data: unknown, isV3: boolean): any[] {
  if (isV3) {
    return normalizeV3TxResponse(data);
  } else {
    return normalizeV2TxResponse(data);
  }
}

/**
 * Try fetching from a single RPC endpoint
 */
async function tryRpcEndpoint(
  endpoint: string,
  isV3: boolean,
  limit: number,
  timeoutMs: number
): Promise<{ transactions: any[]; source: string; success: boolean; httpStatus: number; normalizedCount: number } | null> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      const transactions = isV3 ? normalizeV3TxResponse(data) : normalizeV2TxResponse(data);
      return {
        transactions: transactions.slice(0, limit),
        source: isV3 ? "rpc_accounts_v3" : "rpc_accounts_v2",
        success: true,
        httpStatus: response.status,
        normalizedCount: transactions.length,
      };
    }
    
    // If 404, try without limit param
    if (response.status === 404) {
      const endpointNoLimit = endpoint.replace(/\?limit=\d+/, "");
      const controller2 = new AbortController();
      const timeoutId2 = setTimeout(() => controller2.abort(), timeoutMs);
      
      try {
        const response2 = await fetch(endpointNoLimit, {
          method: "GET",
          headers: { "Content-Type": "application/json" },
          signal: controller2.signal,
        });
        
        clearTimeout(timeoutId2);
        
        if (response2.ok) {
          const data = await response2.json();
          const transactions = isV3 ? normalizeV3TxResponse(data) : normalizeV2TxResponse(data);
          return {
            transactions: transactions.slice(0, limit),
            source: isV3 ? "rpc_accounts_v3" : "rpc_accounts_v2",
            success: true,
            httpStatus: response2.status,
            normalizedCount: transactions.length,
          };
        }
      } catch {
        clearTimeout(timeoutId2);
      }
    }
    
    // Request succeeded but not 200/OK
    return null;
  } catch (error) {
    clearTimeout(timeoutId);
    // Network/parse error - return null
    return null;
  }
}

/**
 * Fetch transactions from RPC account endpoint
 * Tries v2 first if preferV2, else v3 first
 * Returns result with attempted sources and details
 */
async function fetchTransactionsFromRpcAccount(
  address: string,
  rpcUrl: string,
  limit: number,
  timeoutMs: number,
  preferV2: boolean
): Promise<{ 
  transactions: any[]; 
  source: string; 
  success: boolean;
  attemptedSources: string[];
  sourceDetails: { [sourceName: string]: { httpStatus?: number; normalizedCount?: number; error?: string } };
} | { 
  success: false;
  attemptedSources: string[];
  sourceDetails: { [sourceName: string]: { httpStatus?: number; normalizedCount?: number; error?: string } };
}> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const sourceDetails: { [sourceName: string]: { httpStatus?: number; normalizedCount?: number; error?: string } } = {};
  
  // Determine endpoint order based on preferV2
  const endpoints = preferV2
    ? [
        { url: `${normalizedUrl}/rpc/v2/accounts/${address}/transactions?limit=${limit}`, isV3: false },
        { url: `${normalizedUrl}/rpc/v3/accounts/${address}/transactions?limit=${limit}`, isV3: true },
      ]
    : [
        { url: `${normalizedUrl}/rpc/v3/accounts/${address}/transactions?limit=${limit}`, isV3: true },
        { url: `${normalizedUrl}/rpc/v2/accounts/${address}/transactions?limit=${limit}`, isV3: false },
      ];
  
  // Build attempted sources list upfront (for self-auditing)
  const attemptedSources = endpoints.map(e => e.isV3 ? "rpc_accounts_v3" : "rpc_accounts_v2");
  
  // Try each endpoint in order
  for (const endpoint of endpoints) {
    const sourceName = endpoint.isV3 ? "rpc_accounts_v3" : "rpc_accounts_v2";
    
    const result = await tryRpcEndpoint(endpoint.url, endpoint.isV3, limit, timeoutMs);
    
    if (result) {
      // Success - track details for this source
      sourceDetails[sourceName] = {
        httpStatus: result.httpStatus,
        normalizedCount: result.normalizedCount,
      };
      // Return with attempted sources and details
      return {
        transactions: result.transactions,
        source: result.source,
        success: true,
        attemptedSources,
        sourceDetails,
      };
    } else {
      // Failure - track error details
      sourceDetails[sourceName] = {
        error: "Request failed or returned non-200 status",
      };
    }
  }
  
  // All attempts failed - return failure result with attempted sources and details
  return {
    success: false,
    attemptedSources,
    sourceDetails,
  };
}

/**
 * Sample recent transactions and extract behavior evidence
 */
export async function sampleRecentTxBehavior(
  opts: SampleBehaviorOptions
): Promise<BehaviorEvidence> {
  const limit = opts.limit ?? 20;
  const sampledAt = new Date().toISOString();

  // Collect addresses to query (use probeAddresses if provided, otherwise build from owner/modules)
  const addressesToQuery: string[] = [];
  const warnings: string[] = [];
  const preferV2 = opts.preferV2 ?? false;
  
      // Always add owner/modules first (for FA: owner + hook modules)
      // For FA: always sample OWNER address first
      if (opts.ownerAddress) {
        const owner = normalizeAddress(opts.ownerAddress);
        if (owner && !addressesToQuery.includes(owner)) {
          addressesToQuery.push(owner);
        }
      }
      
      // For FA: also sample each HOOK module address
      if (opts.moduleAddresses) {
        for (const addr of opts.moduleAddresses) {
          const normalized = normalizeAddress(addr);
          if (normalized && !addressesToQuery.includes(normalized)) {
            addressesToQuery.push(normalized);
          }
        }
      }
      
      // Add FA address or coin publisher (fallback)
      if (opts.faAddress) {
        const fa = normalizeAddress(opts.faAddress);
        if (fa && !addressesToQuery.includes(fa)) {
          addressesToQuery.push(fa);
        }
      } else if (opts.coinType) {
        const parts = opts.coinType.split("::");
        if (parts.length >= 2) {
          const publisher = normalizeAddress(parts[0]);
          if (publisher && !addressesToQuery.includes(publisher)) {
            addressesToQuery.push(publisher);
          }
        }
      }
      
      // Validate and add probe addresses (if provided)
      if (opts.probeAddresses && opts.probeAddresses.length > 0) {
        for (const addr of opts.probeAddresses) {
          const normalized = normalizeAddress(addr);
          // Validate: must be valid 0x hex address with length 66 (0x + 64 hex chars)
          if (normalized && normalized.startsWith("0x") && normalized.length === 66 && /^0x[0-9a-f]{64}$/i.test(normalized)) {
            if (!addressesToQuery.includes(normalized)) {
              addressesToQuery.push(normalized);
            }
          } else {
            warnings.push(`Invalid probe address (not a valid 0x hex address of length 66): ${addr || "undefined"}`);
          }
        }
      }

  if (addressesToQuery.length === 0) {
    return {
      status: "error",
      tx_count: 0,
      invoked_entries: [],
      phantom_entries: [],
      opaque_active: false,
      sampled_at: sampledAt,
      error: "No address provided for transaction sampling",
    };
  }

  try {
    // Query each address and merge results (best-effort: continue on failures)
    let allTransactions: Array<{ tx: any; timestamp?: string | number; height?: number }> = [];
    let source: string = preferV2 ? "rpc_accounts_v2" : "rpc_accounts_v3";
    let rpcSuccess = false;
    const sampledAddresses: string[] = [];
    let attemptedSources: string[] = [];
    let sourceDetails: { [sourceName: string]: { httpStatus?: number; normalizedCount?: number; error?: string } } = {};
    
    if (opts.rpcUrl) {
      for (const address of addressesToQuery) {
        try {
          const rpcResult = await fetchTransactionsFromRpcAccount(
            address,
            opts.rpcUrl,
            limit * 2, // Fetch more to account for merging
            opts.timeoutMs ?? 8000,
            preferV2
          );
          
          if (rpcResult.success) {
            rpcSuccess = true;
            source = rpcResult.source;
            // Track attempted sources (use first successful attempt's attempted sources)
            if (attemptedSources.length === 0 && rpcResult.attemptedSources) {
              attemptedSources = rpcResult.attemptedSources;
            }
            // Merge source details (accumulate all attempted sources' details)
            if (rpcResult.sourceDetails) {
              sourceDetails = { ...sourceDetails, ...rpcResult.sourceDetails };
            }
            sampledAddresses.push(address);
            // Add transactions with timestamp/height for sorting
            for (const tx of rpcResult.transactions) {
              allTransactions.push({
                tx,
                timestamp: tx.timestamp || tx.created_at || tx.block_timestamp || 0,
                height: tx.height || tx.block_height || tx.version || 0,
              });
            }
          } else {
            // Track attempted sources and details even on failure
            if (attemptedSources.length === 0 && rpcResult.attemptedSources) {
              attemptedSources = rpcResult.attemptedSources;
            }
            // Merge source details from failed attempts
            if (rpcResult.sourceDetails) {
              sourceDetails = { ...sourceDetails, ...rpcResult.sourceDetails };
            }
          }
        } catch (error) {
          // Continue on failure (best-effort)
          // Don't add address to sampledAddresses if it failed
          // Track attempted sources even on failure
          if (attemptedSources.length === 0) {
            attemptedSources = preferV2 
              ? ["rpc_accounts_v2", "rpc_accounts_v3"]
              : ["rpc_accounts_v3", "rpc_accounts_v2"];
          }
        }
      }
      
      // Sort by timestamp/height (newest first) and take top N
      allTransactions.sort((a, b) => {
        // Try timestamp first
        const tsA = typeof a.timestamp === "string" ? parseInt(a.timestamp, 10) : (typeof a.timestamp === "number" ? a.timestamp : 0);
        const tsB = typeof b.timestamp === "string" ? parseInt(b.timestamp, 10) : (typeof b.timestamp === "number" ? b.timestamp : 0);
        if (tsA !== 0 || tsB !== 0) {
          return tsB - tsA; // Descending
        }
        // Fallback to height
        const hA = typeof a.height === "number" ? a.height : 0;
        const hB = typeof b.height === "number" ? b.height : 0;
        return hB - hA; // Descending
      });
      
      // Take most recent N
      allTransactions = allTransactions.slice(0, limit);
    }
    
    // Determine status based on RPC success
    if (opts.rpcUrl && rpcSuccess) {
      const transactions = allTransactions.map(item => item.tx);
      
      if (transactions.length > 0) {
        // Continue with normal processing below
      } else {
        // HTTP 200 but empty array - this is ok_empty, not unavailable
        return {
          status: "ok_empty",
          tx_count: 0,
          invoked_entries: [],
          phantom_entries: [],
          opaque_active: false,
          source,
          sampled_at: sampledAt,
          sampled_addresses: sampledAddresses.length > 0 ? sampledAddresses : undefined,
          sampled_address_count: sampledAddresses.length > 0 ? sampledAddresses.length : undefined,
          attempted_sources: attemptedSources.length > 0 ? attemptedSources : undefined,
          prefer_v2: preferV2,
          source_details: sourceDetails,
          warnings: warnings.length > 0 ? warnings : undefined,
        };
      }
    }
    
    // Fallback to SupraScan if RPC didn't succeed or returned no transactions
    if (allTransactions.length === 0) {
      if (opts.rpcUrl && !rpcSuccess) {
        // Both endpoints failed - this is unavailable
        const primaryAddress = addressesToQuery[0];
        const txResponse = await fetchAllTransactionsFromSupraScan({
          blockchainEnvironment: "mainnet",
          address: primaryAddress,
          rowsPerPage: limit,
          page: 1,
        });
        
        if (txResponse && txResponse.transactions) {
          for (const tx of txResponse.transactions) {
            allTransactions.push({
              tx,
              timestamp: tx.confirmationTime || 0,
            });
          }
          source = "suprascan";
        } else {
          // No transactions available from any source - all attempts failed
          return {
            status: "unavailable",
            tx_count: 0,
            invoked_entries: [],
            phantom_entries: [],
            opaque_active: false,
            source: preferV2 ? "rpc_accounts_v2" : "rpc_accounts_v3",
            sampled_at: sampledAt,
            error: "RPC account transaction endpoints unavailable (network/parse/non-200 errors)",
            sampled_addresses: sampledAddresses.length > 0 ? sampledAddresses : undefined,
            sampled_address_count: sampledAddresses.length > 0 ? sampledAddresses.length : undefined,
            attempted_sources: attemptedSources.length > 0 ? attemptedSources : (preferV2 ? ["rpc_accounts_v2", "rpc_accounts_v3"] : ["rpc_accounts_v3", "rpc_accounts_v2"]),
            prefer_v2: preferV2,
            source_details: Object.keys(sourceDetails).length > 0 ? sourceDetails : undefined,
            warnings: warnings.length > 0 ? warnings : undefined,
          };
        }
      } else if (opts.rpcUrl && rpcSuccess) {
        // RPC succeeded but returned empty - this is ok_empty
        return {
          status: "ok_empty",
          tx_count: 0,
          invoked_entries: [],
          phantom_entries: [],
          opaque_active: false,
          source,
          sampled_at: sampledAt,
          sampled_addresses: sampledAddresses.length > 0 ? sampledAddresses : undefined,
          sampled_address_count: sampledAddresses.length > 0 ? sampledAddresses.length : undefined,
          attempted_sources: attemptedSources.length > 0 ? attemptedSources : undefined,
          prefer_v2: preferV2,
          source_details: Object.keys(sourceDetails).length > 0 ? sourceDetails : undefined,
          warnings: warnings.length > 0 ? warnings : undefined,
        };
      }
    }
    
    const transactions = allTransactions.map(item => item.tx);

    // Extract invoked entry points from transactions
    const invokedEntries: InvokedEntry[] = [];
    const seenEntries = new Set<string>();

    for (const tx of transactions) {
      // Try to extract function name from transaction payload
      const functionName = extractFunctionFromTx(tx) || tx.functionName;
      
      if (functionName) {
        const parsed = parseFunctionName(functionName);
        
        if (parsed.functionName) {
          // If we have module info, use full ID
          if (parsed.moduleAddress && parsed.moduleName) {
            const fullId = `${parsed.moduleAddress}::${parsed.moduleName}::${parsed.functionName}`;
            
            if (!seenEntries.has(fullId)) {
              seenEntries.add(fullId);
              invokedEntries.push({
                moduleAddress: parsed.moduleAddress,
                moduleName: parsed.moduleName,
                functionName: parsed.functionName,
                fullId,
                txHash: tx.hash || tx.transactionHash || tx.txHash || "",
                timestamp: tx.timestamp || tx.created_at || tx.block_timestamp || tx.confirmationTime || undefined,
              });
            }
          } else if (parsed.functionName) {
            // Just function name without module - still record it
            const fullId = `unknown::unknown::${parsed.functionName}`;
            if (!seenEntries.has(fullId)) {
              seenEntries.add(fullId);
              invokedEntries.push({
                moduleAddress: "unknown",
                moduleName: "unknown",
                functionName: parsed.functionName,
                fullId,
                txHash: tx.hash || tx.transactionHash || tx.txHash || "",
                timestamp: tx.timestamp || tx.created_at || tx.block_timestamp || tx.confirmationTime || undefined,
              });
            }
          }
        }
      }
    }

    // Check for phantom entries (invoked but not in pinned ABI)
    const phantomEntries: PhantomEntry[] = [];
    
    if (opts.pinnedEntryFunctions && opts.pinnedEntryFunctions.size > 0) {
      // Group invoked entries by module
      const invokedByModule = new Map<string, InvokedEntry[]>();
      for (const entry of invokedEntries) {
        const moduleId = `${entry.moduleAddress}::${entry.moduleName}`;
        if (!invokedByModule.has(moduleId)) {
          invokedByModule.set(moduleId, []);
        }
        invokedByModule.get(moduleId)!.push(entry);
      }

      // Check each invoked entry against pinned ABI
      for (const [moduleId, entries] of invokedByModule) {
        const pinnedFns = opts.pinnedEntryFunctions.get(moduleId.toLowerCase());
        
        if (pinnedFns) {
          // Module has pinned ABI - check each function
          const pinnedFnsLower = pinnedFns.map(fn => fn.toLowerCase());
          
          for (const entry of entries) {
            if (!pinnedFnsLower.includes(entry.functionName.toLowerCase())) {
              // Find all tx hashes for this phantom entry
              const txHashes = transactions
                .filter(tx => {
                  const p = parseFunctionName(tx.functionName);
                  return p.moduleAddress === entry.moduleAddress &&
                         p.moduleName === entry.moduleName &&
                         p.functionName === entry.functionName;
                })
                .map(tx => tx.transactionHash);
              
              phantomEntries.push({
                moduleAddress: entry.moduleAddress,
                moduleName: entry.moduleName,
                functionName: entry.functionName,
                fullId: entry.fullId,
                txHashes,
                reason: `Entry function "${entry.functionName}" invoked in transactions but not present in pinned ABI for module ${moduleId}`,
              });
            }
          }
        } else {
          // Module not in pinned ABI at all - all entries are phantom
          for (const entry of entries) {
            const txHashes = transactions
              .filter(tx => {
                const p = parseFunctionName(tx.functionName);
                return p.moduleAddress === entry.moduleAddress &&
                       p.moduleName === entry.moduleName &&
                       p.functionName === entry.functionName;
              })
              .map(tx => tx.transactionHash);
            
            phantomEntries.push({
              moduleAddress: entry.moduleAddress,
              moduleName: entry.moduleName,
              functionName: entry.functionName,
              fullId: entry.fullId,
              txHashes,
              reason: `Module ${moduleId} not present in pinned ABI inventory`,
            });
          }
        }
      }
    }

    // Check for opaque ABI but active transactions
    let opaqueActive = false;
    let opaqueActiveReason: string | undefined;
    
    if (opts.abiOpaque && transactions.length > 0) {
      opaqueActive = true;
      opaqueActiveReason = `ABI is opaque/empty but ${transactions.length} recent transactions found involving this address`;
    } else if (opts.pinnedEntryFunctions && opts.pinnedEntryFunctions.size === 0 && invokedEntries.length > 0) {
      opaqueActive = true;
      opaqueActiveReason = `No modules in pinned ABI inventory but ${invokedEntries.length} unique entry points invoked in recent transactions`;
    }

    // Determine status: "ok" if tx_count > 0, otherwise use previous logic
    const status: BehaviorStatus = transactions.length > 0 ? "sampled" : "no_activity";
    
    return {
      status,
      tx_count: transactions.length,
      invoked_entries: invokedEntries,
      phantom_entries: phantomEntries,
      opaque_active: opaqueActive,
      opaque_active_reason: opaqueActiveReason,
      source,
      sampled_at: sampledAt,
      sampled_addresses: sampledAddresses.length > 0 ? sampledAddresses : undefined,
      sampled_address_count: sampledAddresses.length > 0 ? sampledAddresses.length : undefined,
      attempted_sources: attemptedSources.length > 0 ? attemptedSources : undefined,
      prefer_v2: preferV2,
      source_details: Object.keys(sourceDetails).length > 0 ? sourceDetails : undefined,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    
    // Don't fail verification - just mark as unavailable
    const preferV2 = opts.preferV2 ?? false;
    const source = opts.rpcUrl ? (preferV2 ? "rpc_accounts_v2" : "rpc_accounts_v3") : "suprascan";
    const attemptedSources = opts.rpcUrl 
      ? (preferV2 ? ["rpc_accounts_v2", "rpc_accounts_v3"] : ["rpc_accounts_v3", "rpc_accounts_v2"])
      : ["suprascan"];
    return {
      status: "unavailable",
      tx_count: 0,
      invoked_entries: [],
      phantom_entries: [],
      opaque_active: false,
      source,
      sampled_at: sampledAt,
      error: opts.rpcUrl
        ? (errorMsg.includes("timeout") || errorMsg.includes("aborted")
          ? "RPC account transaction endpoint timeout"
          : `RPC account transaction endpoint error: ${errorMsg}`)
        : (errorMsg.includes("timeout") || errorMsg.includes("aborted")
          ? "Transaction API timeout"
          : `Transaction API error: ${errorMsg}`),
      attempted_sources: attemptedSources,
      prefer_v2: preferV2,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }
}

/**
 * Build pinned entry functions map from MiniSurface data
 */
export function buildPinnedEntryFunctionsMap(
  abiPresence?: Array<{
    moduleId: string;
    hasAbi: boolean;
    entryFns?: number;
    exposedFns?: number;
  }>,
  hookModules?: Array<{
    module_address: string;
    module_name: string;
    function_name: string;
  }>
): Map<string, string[]> {
  const map = new Map<string, string[]>();
  
  // Note: abiPresence only contains counts, not actual function names
  // For full validation, we'd need the actual function names from the ABI
  // For now, we track which modules have ABIs (even if we don't have the function list)
  
  if (abiPresence) {
    for (const entry of abiPresence) {
      if (entry.hasAbi) {
        // Mark module as having ABI, but we don't have function names here
        // The caller should provide actual function names if available
        if (!map.has(entry.moduleId.toLowerCase())) {
          map.set(entry.moduleId.toLowerCase(), []);
        }
      }
    }
  }
  
  // Add hook module functions
  if (hookModules) {
    for (const hook of hookModules) {
      const moduleId = `${hook.module_address.toLowerCase()}::${hook.module_name}`;
      if (!map.has(moduleId)) {
        map.set(moduleId, []);
      }
      const fns = map.get(moduleId)!;
      if (!fns.includes(hook.function_name)) {
        fns.push(hook.function_name);
      }
    }
  }
  
  return map;
}


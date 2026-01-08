/**
 * SupraScan Provider for FA Verification Parity
 * Provides normalized responses for FA owner, supply, hooks, and hook module code hashes
 */

import { fetchFaDetailsFromSupraScan } from "../rpc/supraScanGraphql.js";
import { fetchAddressDetailSupra, suprascanGraphql } from "../adapters/suprascanGraphql.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";
import type { HookModule } from "../agent/verify.js";
import { normalizeAddress } from "../agent/verify.js";
import { normalizeSupply } from "../agent/verify.js";
import { normalizeHookModules } from "../agent/verify.js";
import { writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";

/**
 * Safely convert decimal supply string to base units using string math (no float)
 * Example: "968895573.712588" with decimals=6 => "968895573712588"
 */
function convertDecimalSupplyToBase(totalSupplyStr: string, decimals: number): string | null {
  if (!totalSupplyStr || decimals < 0) return null;
  
  // Remove any whitespace
  const trimmed = totalSupplyStr.trim();
  if (!trimmed) return null;
  
  // Check if it's already an integer (no decimal point)
  if (!trimmed.includes(".")) {
    // Already in base units, just pad with zeros if needed
    if (decimals === 0) return trimmed;
    return trimmed + "0".repeat(decimals);
  }
  
  // Split into integer and fractional parts
  const parts = trimmed.split(".");
  if (parts.length !== 2) return null; // Invalid format
  
  const integerPart = parts[0] || "0";
  let fractionalPart = parts[1] || "";
  
  // Pad or truncate fractional part to match decimals
  if (fractionalPart.length < decimals) {
    // Pad with zeros
    fractionalPart = fractionalPart + "0".repeat(decimals - fractionalPart.length);
  } else if (fractionalPart.length > decimals) {
    // Truncate (round down)
    fractionalPart = fractionalPart.substring(0, decimals);
  }
  
  // Combine: integerPart + fractionalPart (no decimal point)
  const baseUnits = integerPart + fractionalPart;
  
  // Remove leading zeros (but keep at least one digit)
  return baseUnits.replace(/^0+/, "") || "0";
}

/**
 * Normalized SupraScan FA evidence
 */
export interface SupraScanFAEvidence {
  owner?: string | null;
  supply?: string | null;
  hooks?: HookModule[];
  hookModuleHashes?: Array<{
    moduleId: string;
    codeHash: string | null;
    hashBasis: "bytecode" | "abi" | "none";
    source: "suprascan";
  }>;
  creatorAddress?: string | null;
  details?: {
    name?: string;
    symbol?: string;
    holders?: number;
    verified?: boolean;
    iconUrl?: string;
  };
}

/**
 * SupraScan provider response
 */
export interface SupraScanProviderResponse {
  ok: boolean;
  status?: "supported" | "unsupported_schema" | "partial" | "partial_ok" | "error";
  urlUsed: string;
  evidence?: SupraScanFAEvidence;
  error?: string;
  diagnostics?: {
    httpStatus?: number;
    topLevelKeys?: string[];
    jsonPreview?: string;
    rawPath?: string;
  };
}

const DEFAULT_GRAPHQL_URL = "https://suprascan.io/api/graphql";

/**
 * Fetch FA evidence from SupraScan with timeout and retries
 */
export async function fetchSupraScanFAEvidence(
  faAddress: string,
  timeoutMs: number = 8000,
  retries: number = 2,
  dumpRawResponse: boolean = true
): Promise<SupraScanProviderResponse> {
  const graphqlUrl = process.env.SUPRASCAN_GRAPHQL_URL || DEFAULT_GRAPHQL_URL;
  
  let lastError: Error | null = null;
  let rawResponses: Array<{ query: string; response: any; httpStatus: number }> = [];
  
  // Helper to write raw JSON dump if enabled
  const writeRawDump = (rawJson: any, httpStatus: number) => {
    if (!dumpRawResponse) return null;
    
    try {
      const dumpDir = "tmp";
      mkdirSync(dumpDir, { recursive: true });
      const dumpPath = `${dumpDir}/suprascan_raw_${faAddress.replace(/^0x/, "")}.json`;
      const dumpData = {
        faAddress,
        timestamp: new Date().toISOString(),
        httpStatus,
        urlUsed: graphqlUrl,
        rawResponse: rawJson,
      };
      writeFileSync(dumpPath, JSON.stringify(dumpData, null, 2), "utf-8");
      return dumpPath;
    } catch (error) {
      // Ignore file write errors - non-fatal
      return null;
    }
  };
  
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      // Try getFaDetails first (has totalSupply, decimals, creatorAddress)
      // We need to capture the raw response for diagnostics
      const normalizedAddress = faAddress.toLowerCase().startsWith("0x")
        ? faAddress.toLowerCase()
        : `0x${faAddress.toLowerCase()}`;
      
      const GET_FA_DETAILS_QUERY = `
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
      
      let faDetailsRaw: any = null;
      let faDetailsHttpStatus = 0;
      
      try {
        const faDetailsResponse = await suprascanGraphql<{ getFaDetails?: any }>(
          GET_FA_DETAILS_QUERY,
          {
            faAddress: normalizedAddress,
            blockchainEnvironment: "mainnet",
          },
          {
            env: "mainnet",
            timeoutMs,
          }
        );
        
        faDetailsRaw = faDetailsResponse;
        faDetailsHttpStatus = 200; // GraphQL wrapper handles HTTP, assume 200 if no error
        
        // Write raw dump
        if (dumpRawResponse) {
          const dumpPath = writeRawDump(faDetailsResponse, faDetailsHttpStatus);
          if (dumpPath) {
            rawResponses.push({ query: "getFaDetails", response: faDetailsResponse, httpStatus: faDetailsHttpStatus });
          }
        }
      } catch (graphqlError) {
        // GraphQL error - try to capture response if available
        const errorMsg = graphqlError instanceof Error ? graphqlError.message : String(graphqlError);
        lastError = graphqlError instanceof Error ? graphqlError : new Error(errorMsg);
        continue;
      }
      
      const faDetails = faDetailsRaw?.getFaDetails;
      const evidence: SupraScanFAEvidence = {};
      
      // Extract supply from getFaDetails using safe string math (no float)
      if (faDetails) {
        // Safely convert totalSupply (decimal string) to base units using decimals
        if (faDetails.totalSupply !== undefined && faDetails.totalSupply !== null) {
          const totalSupplyStr = String(faDetails.totalSupply);
          const decimals = faDetails.decimals !== undefined && faDetails.decimals !== null 
            ? Number(faDetails.decimals) 
            : 0;
          
          // Parse decimal string and convert to base units using string math
          const supplyBase = convertDecimalSupplyToBase(totalSupplyStr, decimals);
          if (supplyBase) {
            evidence.supply = supplyBase;
          }
        }
        
        // Extract informational details
        if (faDetails.faName || faDetails.faSymbol || faDetails.holders !== undefined || faDetails.verified !== undefined || faDetails.iconUrl) {
          evidence.details = {
            name: faDetails.faName || undefined,
            symbol: faDetails.faSymbol || undefined,
            holders: faDetails.holders !== undefined && faDetails.holders !== null ? Number(faDetails.holders) : undefined,
            verified: faDetails.verified !== undefined ? Boolean(faDetails.verified) : undefined,
            iconUrl: faDetails.iconUrl || undefined,
          };
        }
        
        // Extract creatorAddress (informational, NOT owner)
        if (faDetails.creatorAddress) {
          evidence.creatorAddress = normalizeAddress(faDetails.creatorAddress);
        }
      }
      
      // Also try addressDetail for resources (owner, hooks, capabilities)
      let owner: string | null = null;
      let hooks: HookModule[] = [];
      let addressDetailRaw: any = null;
      let addressDetailHttpStatus = 0;
      
      try {
        const addressDetailResponse = await fetchAddressDetailSupra(faAddress, "mainnet", { timeoutMs });
        addressDetailRaw = addressDetailResponse;
        addressDetailHttpStatus = 200; // fetchAddressDetailSupra handles HTTP internally
        
        // Write raw dump for addressDetail
        if (dumpRawResponse && addressDetailResponse) {
          const dumpPath = writeRawDump(addressDetailResponse, addressDetailHttpStatus);
          if (dumpPath) {
            rawResponses.push({ query: "addressDetail", response: addressDetailResponse, httpStatus: addressDetailHttpStatus });
          }
        }
        
        if (addressDetailResponse?.addressDetailSupra?.resources) {
          try {
            const analysis = analyzeFaResources(addressDetailResponse.addressDetailSupra.resources);
            owner = normalizeAddress(analysis.caps.owner || addressDetailResponse.addressDetailSupra.ownerAddress);
            
            if (analysis.caps.hookModules) {
              for (const h of analysis.caps.hookModules) {
                hooks.push({
                  module_address: h.module_address,
                  module_name: h.module_name,
                  function_name: h.function_name,
                });
              }
            }
          } catch (parseError) {
            // Resources parse failed - schema mismatch
          }
        } else if (addressDetailResponse?.addressDetailSupra?.ownerAddress) {
          owner = normalizeAddress(addressDetailResponse.addressDetailSupra.ownerAddress);
        }
      } catch (detailError) {
        // addressDetail failed - continue
      }
      
      if (owner) {
        evidence.owner = owner;
      }
      
      if (hooks.length > 0) {
        evidence.hooks = normalizeHookModules(hooks);
      }
      
      // TODO: Fetch hook module code hashes if SupraScan exposes bytecode/module hash
      // For now, we don't have this capability from SupraScan
      // If SupraScan adds this in the future, we can query it here
      
      // If we have at least one piece of evidence, return success
      if (evidence.owner || evidence.supply || evidence.hooks) {
        const hasAll = evidence.owner && evidence.supply && evidence.hooks;
        const hasSupplyOnly = evidence.supply && !evidence.owner && !evidence.hooks;
        // Use "partial_ok" when we have supply but not owner/hooks (partial mapping from getFaDetails)
        const status = hasAll ? "supported" : (hasSupplyOnly ? "partial_ok" : "partial");
        return {
          ok: true,
          status,
          urlUsed: graphqlUrl,
          evidence,
          diagnostics: dumpRawResponse && rawResponses.length > 0 ? {
            rawPath: `tmp/suprascan_raw_${faAddress.replace(/^0x/, "")}.json`,
          } : undefined,
        };
      }
      
      // HTTP 200 but no mappable fields - schema mismatch
      // Return diagnostics instead of error
      const allRawResponses = faDetailsRaw || addressDetailRaw || {};
      const topLevelKeys = Object.keys(allRawResponses);
      const jsonPreview = JSON.stringify(allRawResponses).substring(0, 2000);
      const dumpPath = writeRawDump(allRawResponses, faDetailsHttpStatus || addressDetailHttpStatus || 200);
      
      return {
        ok: false,
        status: "unsupported_schema",
        urlUsed: graphqlUrl,
        error: "SupraScan returned HTTP 200 but no mappable fields (owner/supply/hooks) found",
        diagnostics: {
          httpStatus: faDetailsHttpStatus || addressDetailHttpStatus || 200,
          topLevelKeys,
          jsonPreview,
          rawPath: dumpPath || undefined,
        },
      };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      // If not the last attempt, wait a bit before retrying
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
  }
  
  // All attempts failed - network/parse errors
  const errorMsg = lastError?.message || "Unknown error";
  return {
    ok: false,
    status: "error",
    urlUsed: graphqlUrl,
    error: errorMsg.includes("timeout") || errorMsg.includes("aborted")
      ? "SupraScan GraphQL timeout"
      : `SupraScan GraphQL error: ${errorMsg}`,
  };
}


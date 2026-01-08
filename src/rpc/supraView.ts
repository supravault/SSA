/**
 * Supra view call helper
 * Uses raw RPC POST /rpc/v1/view endpoint directly
 * No SDK dependency required
 */

import { viewFunctionRawRpc } from "./viewRpc.js";

export interface SupraViewOptions {
  rpcUrl: string;
  fullFn: string;
  args?: string[];
  typeArgs?: string[];
}

/**
 * Call Supra view function using raw RPC
 * Uses POST {RPC_URL}/rpc/v1/view endpoint
 * 
 * @param options - View call options
 * @returns Normalized result (extracts result field if present, otherwise returns as-is)
 */
export async function supraView(options: SupraViewOptions): Promise<any> {
  const { rpcUrl, fullFn, args = [], typeArgs = [] } = options;

  try {
    const rpcResult = await viewFunctionRawRpc(rpcUrl, fullFn, args, typeArgs);
    return normalizeViewResult(rpcResult.result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Supra view call failed for ${fullFn}: ${errorMessage}`);
  }
}

/**
 * Normalize view result
 * - If response is { result: ... }, return result
 * - If response is array, return array
 * - Otherwise return response as-is
 */
function normalizeViewResult(response: any): any {
  if (response === null || response === undefined) {
    return response;
  }

  // If it's an object with a result field, extract it
  if (typeof response === "object" && !Array.isArray(response) && "result" in response) {
    return response.result;
  }

  // If it's an array, return as-is
  if (Array.isArray(response)) {
    return response;
  }

  // Otherwise return as-is
  return response;
}


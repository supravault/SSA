/**
 * Supra MoveVM REST API v3/v2 Resources endpoints
 * For fetching FA metadata/supply resources
 */

import { rpcFetchWithFallback, type RpcClientOptions } from "./supraRpcClient.js";

export interface SupraResourceV3 {
  type: string;
  data?: any;
  [key: string]: any;
}

export interface SupraResourcesV3Response {
  resources?: SupraResourceV3[];
  data?: SupraResourceV3[]; // Alternative response shape
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Fetch resources for an address
 * GET /rpc/v3/accounts/{address}/resources (fallback to v2)
 */
export async function fetchAccountResourcesV3(
  address: string,
  options: RpcClientOptions
): Promise<SupraResourcesV3Response> {
  try {
    const { response, version } = await rpcFetchWithFallback(address, "/resources", options);

    if (response.status === 404) {
      return { resources: [] };
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    // Handle different response shapes
    const resources = data.resources || data.data || (Array.isArray(data) ? data : []);
    
    return {
      resources: Array.isArray(resources) ? resources : [],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch resources (v3/v2): ${errorMessage}`);
  }
}

/**
 * Fetch specific resource by type
 * GET /rpc/v3/accounts/{address}/resources/{resource_type} (fallback to v2)
 */
export async function fetchAccountResourceV3(
  address: string,
  resourceType: string,
  options: RpcClientOptions
): Promise<SupraResourceV3 | null> {
  try {
    const { response, version } = await rpcFetchWithFallback(
      address,
      `/resources/${encodeURIComponent(resourceType)}`,
      options
    );

    if (response.status === 404) {
      return null;
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return null;
    }

    return data.resource || data.data || data || null;
  } catch (error) {
    // Return null on error (resource may not exist)
    return null;
  }
}


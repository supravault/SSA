/**
 * Supra REST API v1 Resources endpoints
 * Uses /rpc/v1/accounts/{address}/resources endpoints
 */

export interface SupraResource {
  type: string;
  data?: any;
  [key: string]: any;
}

export interface SupraResourcesResponse {
  resources?: SupraResource[];
  data?: SupraResource[]; // Alternative response shape
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Fetch resources for an address
 * GET {RPC_URL}/rpc/v1/accounts/{address}/resources
 */
export async function fetchResourcesV1(
  rpcUrl: string,
  address: string
): Promise<SupraResourcesResponse> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  // Ensure address has 0x prefix
  const normalizedAddress = address.startsWith("0x") ? address : `0x${address}`;
  const endpoint = `${normalizedUrl}/rpc/v1/accounts/${normalizedAddress}/resources`;

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });

    if (!response.ok) {
      // If 404, return empty resources list
      if (response.status === 404) {
        return { resources: [] };
      }
      const errorText = await response.text();
      throw new Error(`Supra RPC v1 resources failed (${response.status}): ${errorText} (endpoint: ${endpoint})`);
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    // Handle different response shapes
    const resources = data.resources || data.data || data || [];
    
    return { 
      resources: Array.isArray(resources) ? resources : [],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch resources from Supra RPC v1: ${errorMessage}`);
  }
}


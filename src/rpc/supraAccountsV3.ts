/**
 * Supra MoveVM REST API v3/v2 endpoints for module discovery and bytecode/ABI fetching
 * Canonical endpoints: v3-first with v2 fallback
 */

import { rpcFetchWithFallback, type RpcClientOptions } from "./supraRpcClient.js";

export interface SupraModuleV3 {
  name?: string; // May be missing in list responses
  bytecode?: string; // Base64 or hex encoded
  abi?: {
    address: string;
    name: string;
    friends?: string[];
    exposed_functions?: Array<{
      name: string;
      visibility: string;
      is_entry: boolean;
      params?: any[];
      return?: any[];
    }>;
    structs?: Array<{
      name: string;
      fields?: Array<{ name: string; type: string }>;
    }>;
  };
}

export interface SupraModuleListV3Response {
  modules?: SupraModuleV3[];
  data?: SupraModuleV3[]; // Alternative response shape
  error?: {
    code: number;
    message: string;
  };
}

export interface SupraModuleV3Response {
  module?: SupraModuleV3;
  data?: SupraModuleV3; // Alternative response shape
  bytecode?: string; // Direct bytecode field
  abi?: any; // Direct ABI field
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Fetch list of modules for an address
 * GET /rpc/v3/accounts/{address}/modules (fallback to v2)
 * 
 * Expected response: array of module objects with bytecode + ABI
 */
export async function fetchAccountModulesV3(
  address: string,
  options: RpcClientOptions
): Promise<SupraModuleListV3Response> {
  try {
    const { response, version } = await rpcFetchWithFallback(address, "/modules", options);

    if (response.status === 404) {
      return { modules: [] };
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    // Handle different response shapes
    const modules = data.modules || data.data || (Array.isArray(data) ? data : []);
    
    return {
      modules: Array.isArray(modules) ? modules : [],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module list (v3/v2): ${errorMessage}`);
  }
}

/**
 * Fetch specific module bytecode and ABI
 * GET /rpc/v3/accounts/{address}/modules/{module_name} (fallback to v2)
 * 
 * Expected response:
 * {
 *   "bytecode": "...",
 *   "abi": {
 *     "address": "...",
 *     "name": "...",
 *     "exposed_functions": [...],
 *     "structs": [...]
 *   }
 * }
 */
export async function fetchAccountModuleV3(
  address: string,
  moduleName: string,
  options: RpcClientOptions
): Promise<SupraModuleV3Response> {
  try {
    const { response, version } = await rpcFetchWithFallback(
      address,
      `/modules/${moduleName}`,
      options
    );

    if (response.status === 404) {
      return {}; // Module not found
    }

    const contentType = response.headers.get("content-type") || "";

    // Handle JSON response
    if (contentType.includes("application/json")) {
      const data = (await response.json()) as any;

      if (data?.error) {
        return { error: data.error };
      }

      // Extract module data (handle various response shapes)
      const module = data.module || data.data || data;
      
      // Ensure module has name
      if (module && !module.name) {
        module.name = moduleName;
      }

      return { module };
    }

    // Handle octet-stream/BCS bytecode (future support)
    if (contentType.includes("application/octet-stream") || contentType.includes("application/bcs")) {
      const buffer = await response.arrayBuffer();
      // Convert ArrayBuffer to hex string
      const bytes = new Uint8Array(buffer);
      const bytecodeHex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      return {
        module: {
          name: moduleName,
          bytecode: `0x${bytecodeHex}`,
        },
      };
    }

    // Fallback: try to parse as JSON anyway
    const data = (await response.json()) as any;
    const module = data.module || data.data || data;
    if (module && !module.name) {
      module.name = moduleName;
    }
    return { module };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module ${moduleName} (v3/v2): ${errorMessage}`);
  }
}


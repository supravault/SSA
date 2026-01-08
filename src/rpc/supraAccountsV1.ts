/**
 * Supra REST API v1 Accounts endpoints for module fetching
 * Uses /rpc/v1/accounts/{address}/modules endpoints
 */

export interface SupraModuleV1 {
  name: string;
  bytecode?: string; // Hex string "0x..." or base64
  abi?: any; // ABI/metadata object
  code?: string; // Alternative field name for bytecode
  move_abi?: any; // Alternative field name for ABI
  exposed_functions?: any[]; // Alternative ABI structure
  entry_functions?: any[]; // Alternative ABI structure
}

export interface SupraModuleListV1Response {
  modules?: SupraModuleV1[];
  data?: SupraModuleV1[]; // Alternative response shape
  cursor?: string; // Pagination cursor
  has_more?: boolean; // Pagination flag
  error?: {
    code: number;
    message: string;
  };
}

export interface SupraModuleV1Response {
  module?: SupraModuleV1;
  data?: SupraModuleV1; // Alternative response shape
  bytecode?: string; // Direct bytecode field
  abi?: any; // Direct ABI field
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Fetch list of modules for an address
 * GET {RPC_URL}/rpc/v1/accounts/{address}/modules
 */
export async function fetchModuleListV1(
  rpcUrl: string,
  address: string
): Promise<SupraModuleListV1Response> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const endpoint = `${normalizedUrl}/rpc/v1/accounts/${address}/modules`;

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });

    if (!response.ok) {
      // If 404, return empty modules list
      if (response.status === 404) {
        return { modules: [] };
      }
      const errorText = await response.text();
      throw new Error(`Supra RPC v1 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`);
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    // Handle different response shapes
    const modules = data.modules || data.data || data || [];
    
    return { 
      modules: Array.isArray(modules) ? modules : [],
      cursor: data.cursor,
      has_more: data.has_more,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module list from Supra RPC v1: ${errorMessage}`);
  }
}

/**
 * Fetch specific module bytecode and ABI
 * GET {RPC_URL}/rpc/v1/accounts/{address}/modules/{module_name}
 */
export async function fetchModuleV1(
  rpcUrl: string,
  address: string,
  moduleName: string
): Promise<SupraModuleV1Response> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const endpoint = `${normalizedUrl}/rpc/v1/accounts/${address}/modules/${moduleName}`;

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });

    if (!response.ok) {
      // If 404, module doesn't exist - return empty response
      if (response.status === 404) {
        return {};
      }
      const errorText = await response.text();
      throw new Error(`Supra RPC v1 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`);
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    // Handle different response shapes
    const module = data.module || data.data || data;
    
    // Extract bytecode from various possible field names
    let bytecode: string | undefined;
    if (module?.bytecode) {
      bytecode = module.bytecode;
    } else if (module?.code) {
      bytecode = module.code;
    } else if (data.bytecode) {
      bytecode = data.bytecode;
    }

    // Extract ABI from various possible field names
    let abi: any | undefined;
    if (module?.abi) {
      abi = module.abi;
    } else if (module?.move_abi) {
      abi = module.move_abi;
    } else if (module?.exposed_functions || module?.entry_functions) {
      // Build ABI-like structure from exposed/entry functions
      abi = {
        exposed_functions: module.exposed_functions || [],
        entry_functions: module.entry_functions || [],
      };
    } else if (data.abi) {
      abi = data.abi;
    }

    return {
      module: {
        name: moduleName,
        ...(bytecode && { bytecode }),
        ...(abi && { abi }),
      },
      ...(bytecode && { bytecode }),
      ...(abi && { abi }),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module from Supra RPC v1: ${errorMessage}`);
  }
}

/**
 * Fetch all modules for an address (handles pagination)
 */
export async function fetchAllModulesV1(
  rpcUrl: string,
  address: string
): Promise<SupraModuleV1[]> {
  const allModules: SupraModuleV1[] = [];
  let cursor: string | undefined;
  let hasMore = true;
  let pageCount = 0;
  const maxPages = 10; // Safety limit

  while (hasMore && pageCount < maxPages) {
    const endpoint = `${rpcUrl.replace(/\/+$/, "")}/rpc/v1/accounts/${address}/modules`;
    const url = cursor ? `${endpoint}?cursor=${cursor}` : endpoint;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        if (response.status === 404) {
          break;
        }
        const errorText = await response.text();
        throw new Error(`Supra RPC v1 failed (${response.status}): ${errorText}`);
      }

      const data = (await response.json()) as any;

      if (data?.error) {
        console.warn(`RPC v1 pagination error: ${data.error.message || JSON.stringify(data.error)}`);
        break;
      }

      const modules = data.modules || data.data || data || [];
      if (Array.isArray(modules)) {
        allModules.push(...modules);
      }

      cursor = data.cursor;
      hasMore = data.has_more === true && !!cursor;
      pageCount++;
    } catch (error) {
      console.warn(`RPC v1 pagination failed at page ${pageCount + 1}: ${error instanceof Error ? error.message : String(error)}`);
      break;
    }
  }

  if (pageCount >= maxPages) {
    console.warn(`RPC v1 module list pagination stopped at ${maxPages} pages (safety limit)`);
  }

  return allModules;
}


/**
 * Supra RPC v3 endpoints for module bytecode fetching
 * Uses Supra MoveVM REST API v3 endpoints
 */

export interface SupraModuleInfo {
  name: string;
  bytecode?: string; // Base64 or hex encoded bytecode
  abi?: any; // Module ABI if available
}

export interface SupraModuleListResponse {
  modules?: SupraModuleInfo[];
  error?: {
    code: number;
    message: string;
  };
}

export interface SupraModuleResponse {
  module?: SupraModuleInfo;
  error?: {
    code: number;
    message: string;
  };
}

/**
 * Fetch list of modules for an address
 * GET /rpc/v3/accounts/{address}/modules
 */
export async function fetchModuleList(
  rpcUrl: string,
  address: string
): Promise<SupraModuleListResponse> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const endpoint = `${normalizedUrl}/rpc/v3/accounts/${address}/modules`;

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Supra RPC v3 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`);
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    return { modules: data.modules || data };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module list from Supra RPC v3: ${errorMessage}`);
  }
}

/**
 * Fetch specific module bytecode and metadata
 * GET /rpc/v3/accounts/{address}/modules/{module_name}
 */
export async function fetchModuleBytecode(
  rpcUrl: string,
  address: string,
  moduleName: string
): Promise<SupraModuleResponse> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const endpoint = `${normalizedUrl}/rpc/v3/accounts/${address}/modules/${moduleName}`;

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
      throw new Error(`Supra RPC v3 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`);
    }

    const contentType = response.headers.get("content-type") || "";

    // Handle JSON response
    if (contentType.includes("application/json")) {
      const data = (await response.json()) as any;

      if (data?.error) {
        return { error: data.error };
      }

      return { module: data.module || data };
    }

    // Handle octet-stream/BCS bytecode (future support)
    if (contentType.includes("application/octet-stream") || contentType.includes("application/bcs")) {
      const buffer = await response.arrayBuffer();
      const bytecodeHex = Buffer.from(buffer).toString("hex");
      return {
        module: {
          name: moduleName,
          bytecode: bytecodeHex,
        },
      };
    }

    // Fallback: try to parse as JSON anyway
    const data = (await response.json()) as any;
    return { module: data.module || data };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to fetch module bytecode from Supra RPC v3: ${errorMessage}`);
  }
}


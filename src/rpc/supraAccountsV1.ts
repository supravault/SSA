/**
 * Supra REST API v1 Accounts endpoints for module fetching
 * Uses /rpc/v1/accounts/{address}/modules endpoints
 *
 * IMPORTANT:
 * Supra mainnet RPC commonly returns the module list in this shape:
 * {
 *   "Modules": {
 *     "modules": [
 *        ["0x...::module_name", { "address": "...", "name": "module_name" }],
 *        ...
 *     ],
 *     "cursor": "...",          // optional
 *     "has_more": true|false    // optional
 *   }
 * }
 *
 * Some deployments may wrap further (e.g. data.Modules.Modules.modules) or return:
 * - { modules: [...] }
 * - { data: [...] }
 * - direct array [...]
 *
 * The previous implementation only checked data.modules / data.data / data (array),
 * which caused wallet module enumeration to return an empty list.
 */

export interface SupraModuleV1 {
  name: string;

  // Optional metadata (often only present in module detail endpoint)
  bytecode?: string; // Hex string "0x..." or base64
  abi?: any; // ABI/metadata object
  code?: string; // Alternative field name for bytecode
  move_abi?: any; // Alternative field name for ABI
  exposed_functions?: any[]; // Alternative ABI structure
  entry_functions?: any[]; // Alternative ABI structure

  // Convenience fields (not always returned by RPC)
  module_id?: string; // e.g. "0xabc::staking_v24"
  address?: string; // module address (no 0x maybe)
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
 * Try to normalize the v1 module list response into SupraModuleV1[]
 *
 * Supported shapes:
 * 1) { Modules: { modules: [ [ "0x..::name", { address, name } ], ... ], cursor?, has_more? } }
 * 1b){ Modules: { Modules: { modules: [...] } } }  // seen in some wrappers
 * 2) { modules: [...] } / { data: [...] } / direct array [...]
 */
function extractModuleListFromV1Response(data: any): {
  modules: SupraModuleV1[];
  cursor?: string;
  has_more?: boolean;
} {
  const tupleList =
    // Primary observed shape
    (Array.isArray(data?.Modules?.modules) && data.Modules.modules) ||
    // Some deployments double-nest
    (Array.isArray(data?.Modules?.Modules?.modules) && data.Modules.Modules.modules) ||
    // Alternate common shapes
    (Array.isArray(data?.modules) && data.modules) ||
    (Array.isArray(data?.data) && data.data) ||
    // Direct array fallback
    (Array.isArray(data) && data) ||
    [];

  const normalized: SupraModuleV1[] = [];
  const seen = new Set<string>();

  // Detect tuple list: [ [string, object], ... ]
  const isTupleList =
    Array.isArray(tupleList) &&
    tupleList.length > 0 &&
    Array.isArray(tupleList[0]) &&
    typeof tupleList[0][0] === "string";

  if (isTupleList) {
    for (const item of tupleList) {
      if (!Array.isArray(item) || typeof item[0] !== "string") continue;

      const module_id = item[0] as string; // "0x..::staking_v10"
      if (!module_id || seen.has(module_id)) continue;

      const meta = (typeof item[1] === "object" && item[1] != null ? item[1] : {}) as any;

      const parts = module_id.split("::");
      const addr = parts[0] || meta.address || "";
      const name = parts[1] || meta.name || "";

      if (!name) continue;

      seen.add(module_id);
      normalized.push({
        name,
        module_id,
        address: (meta.address || addr).toString().replace(/^0x/i, ""),
      });
    }

    const cursor = data?.Modules?.cursor ?? data?.Modules?.Modules?.cursor ?? data?.cursor;
    const has_more = data?.Modules?.has_more ?? data?.Modules?.Modules?.has_more ?? data?.has_more;

    return { modules: normalized, cursor, has_more };
  }

  // Else assume it's already an array of objects
  if (Array.isArray(tupleList)) {
    for (const m of tupleList) {
      if (!m || typeof m !== "object") continue;

      const name = (m as any).name || (m as any).module_name || "";
      if (!name) continue;

      const module_id = (m as any).module_id || (m as any).id || "";
      if (module_id && seen.has(module_id)) continue;
      if (module_id) seen.add(module_id);

      normalized.push({
        ...(m as any),
        name,
      });
    }
  }

  const cursor = data?.cursor ?? data?.Modules?.cursor ?? data?.Modules?.Modules?.cursor;
  const has_more = data?.has_more ?? data?.Modules?.has_more ?? data?.Modules?.Modules?.has_more;

  return { modules: normalized, cursor, has_more };
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
      throw new Error(
        `Supra RPC v1 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`
      );
    }

    const data = (await response.json()) as any;

    if (data?.error) {
      return { error: data.error };
    }

    const extracted = extractModuleListFromV1Response(data);

    return {
      modules: extracted.modules,
      cursor: extracted.cursor,
      has_more: extracted.has_more,
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
      throw new Error(
        `Supra RPC v1 failed (${response.status}): ${errorText} (endpoint: ${endpoint})`
      );
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
 * Fetch all modules for an address (handles pagination best-effort)
 *
 * Note:
 * - Many Supra RPC deployments return the full module list in one response (no cursor/has_more).
 * - Some may expose cursor/has_more at either the top level or inside data.Modules.
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
    const base = `${rpcUrl.replace(/\/+$/, "")}/rpc/v1/accounts/${address}/modules`;
    const url = cursor ? `${base}?cursor=${encodeURIComponent(cursor)}` : base;

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
        console.warn(
          `RPC v1 pagination error: ${data.error.message || JSON.stringify(data.error)}`
        );
        break;
      }

      const extracted = extractModuleListFromV1Response(data);
      if (extracted.modules.length > 0) {
        // de-dupe across pages
        const seen = new Set(allModules.map((m) => m.module_id || `${m.address}::${m.name}`));
        for (const m of extracted.modules) {
          const key = m.module_id || `${m.address}::${m.name}`;
          if (!seen.has(key)) {
            seen.add(key);
            allModules.push(m);
          }
        }
      }

      cursor = extracted.cursor;
      hasMore = extracted.has_more === true && !!cursor;

      pageCount++;

      // If no cursor/has_more, done in one request
      if (!cursor) {
        hasMore = false;
      }
    } catch (error) {
      console.warn(
        `RPC v1 pagination failed at page ${pageCount + 1}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      break;
    }
  }

  if (pageCount >= maxPages) {
    console.warn(`RPC v1 module list pagination stopped at ${maxPages} pages (safety limit)`);
  }

  return allModules;
}




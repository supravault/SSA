/**
 * Fetch module artifact (bytecode/ABI) for hash pinning
 * Safe wrapper that never throws - returns null if unavailable
 */

import { fetchAccountModuleV3 } from "./supraAccountsV3.js";
import { fetchModuleV1 } from "./supraAccountsV1.js";
import type { RpcClientOptions } from "./supraRpcClient.js";

export interface ModuleArtifact {
  moduleId: string;
  bytecodeHex?: string | null;
  abi?: any | null;
  fetchedFrom: "rpc_v3" | "rpc_v1" | "unknown";
}

/**
 * Extract bytecode from various response shapes
 */
function extractBytecode(module: any): string | null {
  if (!module) return null;
  
  // Try various field names
  if (module.bytecode) {
    return module.bytecode;
  }
  if (module.code) {
    return module.code;
  }
  
  return null;
}

/**
 * Extract ABI from various response shapes
 */
function extractAbi(module: any): any | null {
  if (!module) return null;
  
  if (module.abi) {
    return module.abi;
  }
  if (module.move_abi) {
    return module.move_abi;
  }
  // If exposed_functions or entry_functions exist, build ABI-like structure
  if (module.exposed_functions || module.entry_functions) {
    return {
      exposed_functions: module.exposed_functions || [],
      entry_functions: module.entry_functions || [],
    };
  }
  
  return null;
}

/**
 * Get module artifact (bytecode preferred, ABI fallback)
 * Tries RPC v3 first, then v1, never throws
 */
export async function getModuleArtifact(
  rpcUrl: string,
  moduleAddress: string,
  moduleName: string,
  rpcOptions?: Partial<RpcClientOptions>
): Promise<ModuleArtifact> {
  const moduleId = `${moduleAddress}::${moduleName}`;
  
  const opts: RpcClientOptions = {
    rpcUrl,
    timeout: rpcOptions?.timeout || 8000,
    retries: rpcOptions?.retries || 1,
    retryDelay: rpcOptions?.retryDelay || 500,
  };

  // Try RPC v3 first
  try {
    const v3Result = await fetchAccountModuleV3(moduleAddress, moduleName, opts);
    
    if (v3Result.module) {
      const bytecode = extractBytecode(v3Result.module);
      const abi = extractAbi(v3Result.module);
      
      return {
        moduleId,
        bytecodeHex: bytecode || null,
        abi: abi || null,
        fetchedFrom: "rpc_v3",
      };
    }
  } catch (error) {
    // Continue to v1 fallback
  }

  // Fallback to RPC v1
  try {
    const v1Result = await fetchModuleV1(rpcUrl, moduleAddress, moduleName);
    
    if (v1Result.module) {
      const bytecode = extractBytecode(v1Result.module);
      const abi = extractAbi(v1Result.module);
      
      return {
        moduleId,
        bytecodeHex: bytecode || null,
        abi: abi || null,
        fetchedFrom: "rpc_v1",
      };
    }
  } catch (error) {
    // Return unknown if both fail
  }

  // Neither succeeded
  return {
    moduleId,
    bytecodeHex: null,
    abi: null,
    fetchedFrom: "unknown",
  };
}


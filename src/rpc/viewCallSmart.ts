/**
 * Environment-aware view call resolver
 * Prefers Railway proxy, falls back to direct RPC
 */

import { supraView } from "./supraView.js";

export interface ViewCallSmartOptions {
  proxyBase?: string; // Railway proxy base URL (e.g., "https://your-app.railway.app")
  rpcUrl: string; // Direct RPC URL fallback
  fqn: string; // Full qualified name: "0xADDR::module::function"
  args?: string[];
  typeArgs?: string[];
}

/**
 * Smart view call that prefers proxy, falls back to direct RPC
 * 
 * @param options - View call options
 * @returns Normalized result (array/scalar as needed)
 */
export async function viewCallSmart(options: ViewCallSmartOptions): Promise<any> {
  const { proxyBase, rpcUrl, fqn, args = [], typeArgs = [] } = options;

  // Try proxy first if available
  if (proxyBase) {
    try {
      const normalizedProxy = proxyBase.replace(/\/+$/, "");
      const proxyUrl = `${normalizedProxy}/api/view`;

      // Build query string
      const params = new URLSearchParams({ fn: fqn });
      if (args.length > 0) {
        params.set("args", args.join(","));
      }

      const response = await fetch(`${proxyUrl}?${params.toString()}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (response.ok) {
        const data = (await response.json()) as any;
        if (data?.ok && data?.result !== undefined) {
          return normalizeViewResult(data.result);
        }
        // If proxy returns ok:false, consume body and fall through to direct RPC
        // Ensure response body is consumed to prevent dangling handles
        if (!response.bodyUsed) {
          await response.text().catch(() => {});
        }
      } else {
        // Consume error response body to prevent dangling handles
        await response.text().catch(() => {});
      }
    } catch (error) {
      console.warn(
        `Proxy call failed, falling back to direct RPC: ${error instanceof Error ? error.message : String(error)}`
      );
      // Fall through to direct RPC
    }
  }

  // Fallback to direct RPC (or use if no proxy)
  return await supraView({
    rpcUrl,
    fullFn: fqn,
    args,
    typeArgs,
  });
}

/**
 * Normalize view result to array/scalar as needed
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


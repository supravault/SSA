/**
 * Supra RPC Client with retry, timeout, and structured error handling
 * Supports v3-first with v2 fallback
 */

export interface RpcClientOptions {
  rpcUrl: string;
  timeout?: number; // milliseconds, default 10000
  retries?: number; // default 2
  retryDelay?: number; // milliseconds, default 500
}

export interface RpcError {
  code: number;
  message: string;
  endpoint: string;
  version?: "v2" | "v3";
}

/**
 * RPC client wrapper with retry and timeout
 */
export async function rpcFetch(
  endpoint: string,
  options: RpcClientOptions = { rpcUrl: "" }
): Promise<Response> {
  const {
    timeout = 10000,
    retries = 2,
    retryDelay = 500,
  } = options;

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    let timeoutId: NodeJS.Timeout | null = null;
    try {
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(endpoint, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
      });

      // Clear timeout immediately after fetch completes
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }

      // If successful, return immediately
      if (response.ok) {
        return response;
      }

      // If 404, don't retry
      if (response.status === 404) {
        return response;
      }

      // For other errors, throw to trigger retry
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    } catch (error) {
      // Always clear timeout in error case
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }

      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry on abort (timeout) or 404
      if (lastError.name === "AbortError" || lastError.message.includes("404")) {
        throw lastError;
      }

      // If this was the last attempt, throw
      if (attempt === retries) {
        throw lastError;
      }

      // Wait before retry
      await new Promise((resolve) => setTimeout(resolve, retryDelay * (attempt + 1)));
    }
  }

  throw lastError || new Error("RPC fetch failed");
}

/**
 * Fetch with v3-first, v2 fallback
 */
export async function rpcFetchWithFallback(
  address: string,
  path: string,
  options: RpcClientOptions
): Promise<{ response: Response; version: "v2" | "v3" }> {
  const normalizedUrl = options.rpcUrl.replace(/\/+$/, "");
  
  // Try v3 first
  const v3Endpoint = `${normalizedUrl}/rpc/v3/accounts/${address}${path}`;
  
  try {
    const response = await rpcFetch(v3Endpoint, options);
    if (response.ok) {
      return { response, version: "v3" };
    }
    // If 404, try v2 fallback
    if (response.status === 404) {
      // Fall through to v2
    } else {
      // Other error, try v2 anyway
    }
  } catch (error) {
    // v3 failed, try v2 fallback
  }

  // Fallback to v2
  const v2Endpoint = `${normalizedUrl}/rpc/v2/accounts/${address}${path}`;
  try {
    const response = await rpcFetch(v2Endpoint, options);
    return { response, version: "v2" };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`Both v3 and v2 RPC failed: ${errorMessage}`);
  }
}


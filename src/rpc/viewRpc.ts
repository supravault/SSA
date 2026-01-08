/**
 * Supra view RPC fallback
 * Calls POST {RPC_URL}/rpc/v1/view with Supra view payload
 */

export interface ViewRpcResult {
  result: any;
  fetch_method: "raw_rpc";
}

/**
 * Call Supra view function via raw RPC
 * @param rpcUrl - Base RPC URL (will be normalized)
 * @param fullFn - Full function ID: "0xADDR::module::function"
 * @param args - Function arguments array (optional, plain strings only)
 * @param typeArgs - Type arguments array (optional)
 * @returns Parsed JSON result
 * @throws Error on non-2xx responses with response text
 */
export async function viewFunctionRawRpc(
  rpcUrl: string,
  fullFn: string,
  args: string[] = [],
  typeArgs: string[] = []
): Promise<ViewRpcResult> {
  // Normalize RPC URL (strip trailing slashes)
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const endpoint = `${normalizedUrl}/rpc/v1/view`;

  // Debug toggle: print request payload when SSA_DEBUG_VIEW=1 or DEBUG_VIEW=1
  const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.DEBUG_VIEW === "1";
  
  // Build payload (ensure valid JSON with string keys)
  const payload = {
    function: fullFn,
    type_arguments: typeArgs,
    arguments: args, // Plain strings only, no object encoding
  };
  
  // Validate payload: ensure all arguments are strings (not objects/maps)
  const validatedArgs = args.map((arg) => {
    if (typeof arg === "string") {
      return arg;
    }
    // If somehow an object was passed, convert to JSON string
    return JSON.stringify(arg);
  });
  
  const finalPayload = {
    function: fullFn,
    type_arguments: typeArgs,
    arguments: validatedArgs,
  };
  
  const payloadJson = JSON.stringify(finalPayload);
  
  if (debug) {
    console.log(`[viewRpc] POST ${endpoint}`);
    console.log(`[viewRpc] Payload: ${payloadJson}`);
    console.log(`[viewRpc] fn=${fullFn} type_args=${JSON.stringify(typeArgs)} args=${JSON.stringify(validatedArgs)}`);
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: payloadJson,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Supra view RPC failed (${response.status}): ${errorText} (endpoint: ${endpoint})`
    );
  }

  const data = (await response.json()) as any;

  // Handle error response
  if (data?.error) {
    throw new Error(
      `Supra view RPC error: ${data.error?.message || JSON.stringify(data.error)} (endpoint: ${endpoint})`
    );
  }

  return {
    result: data?.result !== undefined ? data.result : data,
    fetch_method: "raw_rpc",
  };
}

/**
 * Helper function for posting view calls
 * @param rpcUrl - Base RPC URL
 * @param fullFn - Full function ID: "0xADDR::module::function"
 * @param args - Function arguments array (optional)
 * @param typeArgs - Type arguments array (optional)
 * @returns Parsed result
 */
export async function postView(
  rpcUrl: string,
  fullFn: string,
  args: string[] = [],
  typeArgs: string[] = []
): Promise<any> {
  const result = await viewFunctionRawRpc(rpcUrl, fullFn, args, typeArgs);
  return result.result;
}

// Example usage (commented out - no actual network call in tests):
// const result = await postView(
//   "https://rpc.supra.com",
//   "0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3::staking_v24::total_staked"
// );
// console.log("View result:", result);


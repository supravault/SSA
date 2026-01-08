/**
 * View Call Negotiator for FA views
 * Tests different payload shapes to find the correct calling convention
 */

import { viewFunctionRawRpc } from "./viewRpc.js";

export interface ViewCallShape {
  name: string;
  typeArgs: string[];
  args: string[];
}

export interface NegotiatedShape {
  shape: ViewCallShape;
  success: boolean;
  error?: string;
}

/**
 * Negotiate the correct view call shape by testing multiple payload conventions
 * @param rpcUrl - Base RPC URL
 * @param functionName - Full function name (e.g., "0x1::fungible_asset::symbol")
 * @param coinType - Move struct tag (e.g., "0x...::module::TYPE")
 * @param faAddress - FA address (optional, for testing)
 * @returns The first successful shape, or null if all fail
 */
export async function negotiateViewCallShape(
  rpcUrl: string,
  functionName: string,
  coinType: string,
  faAddress?: string
): Promise<NegotiatedShape | null> {
  const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.DEBUG_VIEW === "1";
  
  // Test shapes in order of likelihood
  const testShapes: ViewCallShape[] = [
    {
      name: "type_args_only",
      typeArgs: [coinType],
      args: [],
    },
    {
      name: "args_only",
      typeArgs: [],
      args: [coinType],
    },
    {
      name: "both_type_and_args",
      typeArgs: [coinType],
      args: [coinType],
    },
  ];
  
  // If FA address is provided, also test with FA address as argument
  if (faAddress) {
    testShapes.push(
      {
        name: "type_args_with_fa_address",
        typeArgs: [coinType],
        args: [faAddress],
      },
      {
        name: "fa_address_only",
        typeArgs: [],
        args: [faAddress],
      }
    );
  }

  for (const shape of testShapes) {
    try {
      if (debug) {
        console.log(`[ViewNegotiator] Testing shape: ${shape.name} (typeArgs=${shape.typeArgs.length}, args=${shape.args.length})`);
      }
      
      const result = await viewFunctionRawRpc(
        rpcUrl,
        functionName,
        shape.args,
        shape.typeArgs
      );
      
      // Check if result is valid (not null/undefined)
      if (result?.result !== null && result?.result !== undefined) {
        if (debug) {
          console.log(`[ViewNegotiator] ✅ Shape ${shape.name} succeeded`);
        }
        return {
          shape,
          success: true,
        };
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      if (debug) {
        console.log(`[ViewNegotiator] ❌ Shape ${shape.name} failed: ${errorMsg}`);
      }
      // Continue to next shape
    }
  }

  // All shapes failed
  if (debug) {
    console.log(`[ViewNegotiator] ❌ All shapes failed for ${functionName}`);
  }
  return null;
}



import { viewCallSmart } from "./viewCallSmart.js";

/**
 * Required views for scanning (minimum set)
 */
export const REQUIRED_VIEWS = ["pool_stats", "total_staked"];

/**
 * V24 queue views (newer API)
 */
export const V24_QUEUE_VIEWS = [
  "view_withdraw_requests",
  "view_claim_requests",
];

/**
 * Legacy queue views (older API)
 */
export const LEGACY_QUEUE_VIEWS = [
  "withdraw_queue_length",
  "withdraw_queue_at",
  "claim_queue_length",
  "claim_queue_at",
];

/**
 * Optional non-queue views
 */
export const OPTIONAL_VIEWS: string[] = [];

/**
 * Views that require a user address as argument
 */
export const USER_REQUIRED_VIEWS = [
  "view_withdrawal_amount_of",
  "view_claim_amount_of",
];

/**
 * Check if a view requires a user address
 */
export function requiresUserAddress(viewName: string): boolean {
  return USER_REQUIRED_VIEWS.includes(viewName);
}

/**
 * Check if error indicates function not found
 */
function isFunctionNotFoundError(error: string): boolean {
  const lower = error.toLowerCase();
  return (
    lower.includes("could not find entry function") ||
    lower.includes("function not found") ||
    (lower.includes("entry function") && lower.includes("not found"))
  );
}

/**
 * Probe a view function (call with empty args)
 */
async function probeView(
  fullFn: string,
  rpcUrl: string,
  proxyBase?: string
): Promise<{ success: boolean; result?: any; error?: string }> {
  try {
    const result = await viewCallSmart({
      proxyBase,
      rpcUrl,
      fqn: fullFn,
      args: [],
      typeArgs: [],
    });
    return { success: true, result };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, error: errorMessage };
  }
}

export async function fetchModuleViewData(
  options: FetchModuleViewDataOptions
): Promise<ModuleViewData> {
  const { rpcUrl, moduleId, proxyBase, allowedViews = [], userAddress } = options;
  const viewResults: Record<string, any> = {};
  const viewErrors: ViewError[] = [];
  const probedViews: Record<string, any> = {};
  const fullModuleId = `${moduleId.address}::${moduleId.module_name}`;

  let fetchMethod: "proxy" | "rpc" | "raw_rpc" = "raw_rpc";
  let skippedUserViews: string[] = [];
  let queueMode: QueueMode = "none";

  // If custom allowed views specified, use them directly (skip probing)
  if (allowedViews.length > 0) {
    // Direct mode: call all specified views
    for (const viewFn of allowedViews) {
      const fullFn = `${fullModuleId}::${viewFn}`;
      
      if (requiresUserAddress(viewFn) && !userAddress) {
        skippedUserViews.push(viewFn);
        continue;
      }

      const args = requiresUserAddress(viewFn) && userAddress ? [userAddress] : [];

      try {
        const result = await viewCallSmart({
          proxyBase,
          rpcUrl,
          fqn: fullFn,
          args,
          typeArgs: [],
        });
        viewResults[viewFn] = result;
        if (proxyBase && !fetchMethod.includes("proxy")) {
          fetchMethod = "proxy";
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        viewErrors.push({
          viewName: viewFn,
          functionId: fullFn,
          error: errorMessage,
          type: "error",
        });
      }
    }

    return {
      viewResults,
      viewErrors,
      fetch_method: fetchMethod,
      skippedUserViews,
      unsupportedViews: [],
      queueMode: "none", // Unknown in custom mode
      probedViews: {},
    };
  }

  // Standard mode: probe queue capability first
  // Step 1: Probe v24 queue views
  const v24ProbeResults: Record<string, { success: boolean; error?: string }> = {};
  let v24ProbeSuccess = true;

  for (const viewFn of V24_QUEUE_VIEWS) {
    const fullFn = `${fullModuleId}::${viewFn}`;
    const probe = await probeView(fullFn, rpcUrl, proxyBase);
    v24ProbeResults[viewFn] = { success: probe.success, error: probe.error };
    if (probe.success) {
      probedViews[viewFn] = probe.result; // Cache result
      viewResults[viewFn] = probe.result; // Cache result
      if (proxyBase && !fetchMethod.includes("proxy")) {
        fetchMethod = "proxy";
      }
    } else {
      v24ProbeSuccess = false;
      // Only record as error if it's NOT a "function not found" error
      if (!isFunctionNotFoundError(probe.error || "")) {
        viewErrors.push({
          viewName: viewFn,
          functionId: fullFn,
          error: probe.error || "Unknown error",
          type: "error",
        });
      }
    }
  }

  // Step 2: Determine queue mode
  if (v24ProbeSuccess) {
    queueMode = "v24";
    // v24 views already cached, no need to call again
  } else {
    // Try legacy queue probes
    const legacyProbeResults: Record<string, { success: boolean; error?: string }> = {};
    let legacyProbeSuccess = true;

    for (const viewFn of ["withdraw_queue_length", "claim_queue_length"]) {
      const fullFn = `${fullModuleId}::${viewFn}`;
      const probe = await probeView(fullFn, rpcUrl, proxyBase);
      legacyProbeResults[viewFn] = { success: probe.success, error: probe.error };
      if (probe.success) {
        probedViews[viewFn] = probe.result;
        viewResults[viewFn] = probe.result;
        if (proxyBase && !fetchMethod.includes("proxy")) {
          fetchMethod = "proxy";
        }
      } else {
        legacyProbeSuccess = false;
        if (!isFunctionNotFoundError(probe.error || "")) {
          viewErrors.push({
            viewName: viewFn,
            functionId: fullFn,
            error: probe.error || "Unknown error",
            type: "error",
          });
        }
      }
    }

    if (legacyProbeSuccess) {
      queueMode = "legacy";
      // Call legacy queue_at views if length probes succeeded
      for (const viewFn of ["withdraw_queue_at", "claim_queue_at"]) {
        const fullFn = `${fullModuleId}::${viewFn}`;
        try {
          const result = await viewCallSmart({
            proxyBase,
            rpcUrl,
            fqn: fullFn,
            args: ["0"], // Probe with index 0
            typeArgs: [],
          });
          viewResults[viewFn] = result;
          if (proxyBase && !fetchMethod.includes("proxy")) {
            fetchMethod = "proxy";
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          // Only record if not "function not found"
          if (!isFunctionNotFoundError(errorMessage)) {
            viewErrors.push({
              viewName: viewFn,
              functionId: fullFn,
              error: errorMessage,
              type: "error",
            });
          }
        }
      }
    } else {
      queueMode = "none";
    }
  }

  // Step 3: Call required views
  for (const viewFn of REQUIRED_VIEWS) {
    const fullFn = `${fullModuleId}::${viewFn}`;
    try {
      const result = await viewCallSmart({
        proxyBase,
        rpcUrl,
        fqn: fullFn,
        args: [],
        typeArgs: [],
      });
      viewResults[viewFn] = result;
      if (proxyBase && !fetchMethod.includes("proxy")) {
        fetchMethod = "proxy";
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      viewErrors.push({
        viewName: viewFn,
        functionId: fullFn,
        error: errorMessage,
        type: "error",
      });
    }
  }

  // Step 4: Call user-required views if user address provided
  for (const viewFn of USER_REQUIRED_VIEWS) {
    if (!userAddress) {
      skippedUserViews.push(viewFn);
      continue;
    }

    const fullFn = `${fullModuleId}::${viewFn}`;
    try {
      const result = await viewCallSmart({
        proxyBase,
        rpcUrl,
        fqn: fullFn,
        args: [userAddress],
        typeArgs: [],
      });
      viewResults[viewFn] = result;
      if (proxyBase && !fetchMethod.includes("proxy")) {
        fetchMethod = "proxy";
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      viewErrors.push({
        viewName: viewFn,
        functionId: fullFn,
        error: errorMessage,
        type: "error",
      });
    }
  }

  // Separate errors from unsupported views (queue mode mismatch)
  const trueErrors: ViewError[] = [];
  const unsupportedViews: string[] = [];

  for (const err of viewErrors) {
    // If v24 mode, mark legacy queue errors as unsupported
    if (queueMode === "v24" && LEGACY_QUEUE_VIEWS.includes(err.viewName)) {
      unsupportedViews.push(err.viewName);
      trueErrors.push({
        ...err,
        type: "unsupported",
        error: `Function not found for v24 queue mode (legacy function)`,
      });
    }
    // If legacy mode, mark v24 queue errors as unsupported
    else if (queueMode === "legacy" && V24_QUEUE_VIEWS.includes(err.viewName)) {
      unsupportedViews.push(err.viewName);
      trueErrors.push({
        ...err,
        type: "unsupported",
        error: `Function not found for legacy queue mode (v24 function)`,
      });
    }
    // Keep true errors
    else {
      trueErrors.push(err);
    }
  }

  // Check for user-required views that were skipped (no TARGET_USER)
  for (const viewFn of skippedUserViews) {
    trueErrors.push({
      viewName: viewFn,
      functionId: `${fullModuleId}::${viewFn}`,
      error: "TARGET_USER not provided",
      type: "skipped",
    });
  }

  return {
    viewResults,
    viewErrors: trueErrors,
    fetch_method: fetchMethod,
    skippedUserViews,
    unsupportedViews,
    queueMode,
    probedViews,
  };
}

/**
 * Extract strings from bytecode (best-effort)
 * Looks for printable ASCII strings
 */
export function extractStringsFromBytecode(bytecode: Buffer): string[] {
  const strings: string[] = [];
  const minLength = 4; // Minimum string length to consider
  let currentString = "";

  for (let i = 0; i < bytecode.length; i++) {
    const byte = bytecode[i];
    // Printable ASCII range (32-126)
    if (byte >= 32 && byte <= 126) {
      currentString += String.fromCharCode(byte);
    } else {
      if (currentString.length >= minLength) {
        strings.push(currentString);
      }
      currentString = "";
    }
  }

  if (currentString.length >= minLength) {
    strings.push(currentString);
  }

  return strings;
}

export function extractFunctionNames(abi: any): string[] {
  if (!abi || typeof abi !== "object") {
    return [];
  }

  const functions: string[] = [];

  // Try common ABI structures
  if (Array.isArray(abi.functions)) {
    for (const fn of abi.functions) {
      if (typeof fn.name === "string") {
        functions.push(fn.name);
      }
    }
  }

  if (Array.isArray(abi.entry_functions)) {
    for (const fn of abi.entry_functions) {
      if (typeof fn.name === "string") {
        functions.push(fn.name);
      }
    }
  }

  // If ABI is an array of function objects
  if (Array.isArray(abi)) {
    for (const item of abi) {
      if (item?.name && typeof item.name === "string") {
        functions.push(item.name);
      }
    }
  }

  return [...new Set(functions)]; // Deduplicate
}

/**
 * Extract entry functions from ABI
 */
export function extractEntryFunctions(abi: any): string[] {
  if (!abi || typeof abi !== "object") {
    return [];
  }

  const entries: string[] = [];

  if (Array.isArray(abi.entry_functions)) {
    for (const fn of abi.entry_functions) {
      if (typeof fn.name === "string") {
        entries.push(fn.name);
      }
    }
  }

  // Also check for functions marked as entry
  if (Array.isArray(abi.functions)) {
    for (const fn of abi.functions) {
      if (fn.is_entry === true || fn.visibility === "entry" || fn.visibility === "public") {
        if (typeof fn.name === "string") {
          entries.push(fn.name);
        }
      }
    }
  }

  return [...new Set(entries)]; // Deduplicate
}

/**
 * Schema-flexible extraction of exposed/public functions from ABI
 * Supports common ABI shapes: abi.exposed_functions, abi.functions, abi.abi.exposed_functions, etc.
 */
export function extractExposedFunctions(abi: any): string[] {
  if (!abi || typeof abi !== "object") {
    return [];
  }

  const functions: string[] = [];
  const seen = new Set<string>();

  // Helper to add function name if not already seen
  const addFunction = (name: string | undefined | null) => {
    if (name && typeof name === "string" && !seen.has(name)) {
      seen.add(name);
      functions.push(name);
    }
  };

  // Extract from exposed_functions array (direct - can be strings or objects)
  if (Array.isArray(abi.exposed_functions)) {
    for (const fn of abi.exposed_functions) {
      if (typeof fn === "string") {
        addFunction(fn);
      } else if (fn && typeof fn === "object") {
        addFunction(fn.name);
      }
    }
  }

  // Extract from functions array (check visibility)
  if (Array.isArray(abi.functions)) {
    for (const fn of abi.functions) {
      if (fn && typeof fn === "object") {
        // Include public, friend, or entry functions
        const visibility = fn.visibility || fn.visibility_type;
        const isEntry = fn.is_entry === true || fn.entry === true;
        if (visibility === "public" || visibility === "friend" || isEntry) {
          addFunction(fn.name);
        }
      }
    }
  }

  // Extract from nested abi.abi.exposed_functions
  if (abi.abi && typeof abi.abi === "object") {
    if (Array.isArray(abi.abi.exposed_functions)) {
      for (const fn of abi.abi.exposed_functions) {
        if (typeof fn === "string") {
          addFunction(fn);
        } else if (fn && typeof fn === "object") {
          addFunction(fn.name);
        }
      }
    }
    
    // Extract from nested abi.abi.functions
    if (Array.isArray(abi.abi.functions)) {
      for (const fn of abi.abi.functions) {
        if (fn && typeof fn === "object") {
          const visibility = fn.visibility || fn.visibility_type;
          const isEntry = fn.is_entry === true || fn.entry === true;
          if (visibility === "public" || visibility === "friend" || isEntry) {
            addFunction(fn.name);
          }
        }
      }
    }
  }

  // Note: We don't extract entry_functions here as they're handled separately by extractEntryFunctions
  // This function focuses on non-entry exposed/public functions

  return functions;
}

/**
 * Build ArtifactView from view-based inspection
 * Uses view results to infer function names and patterns
 */
export function buildArtifactViewFromViews(
  moduleId: ModuleId,
  viewResults: Record<string, any>
): ArtifactView {
  // Extract function names from view results keys
  const functionNames = Object.keys(viewResults);

  // Infer entry functions from view function names
  // Views are typically read-only, but we can detect patterns
  const entryFunctions = functionNames.filter(
    (fn) =>
      fn.startsWith("view_") ||
      fn.includes("_of") ||
      fn.includes("stats") ||
      fn.includes("length")
  );

  // Extract strings from view results (best-effort)
  const strings: string[] = [];
  for (const [key, value] of Object.entries(viewResults)) {
    if (typeof value === "string") {
      strings.push(value);
    } else if (typeof value === "object" && value !== null) {
      // Try to extract string fields from objects
      try {
        const jsonStr = JSON.stringify(value);
        // Extract potential function names or patterns
        const matches = jsonStr.match(/"([a-z_][a-z0-9_]*)"/gi);
        if (matches) {
          strings.push(...matches.map((m) => m.slice(1, -1)));
        }
      } catch {
        // Ignore JSON stringify errors
      }
    }
  }

  return {
    moduleId,
    bytecode: null, // Not available via view calls
    abi: null, // Not available via view calls
    functionNames,
    entryFunctions,
    strings,
    metadata: viewResults, // Store view results as metadata
  };
}

// Type definitions
export type QueueMode = "v24" | "legacy" | "none";

export interface ViewError {
  viewName: string;
  functionId: string;
  error: string;
  type?: "error" | "skipped" | "unsupported";
}

export interface ModuleViewData {
  viewResults: Record<string, any>;
  viewErrors: ViewError[];
  fetch_method: "proxy" | "rpc" | "raw_rpc";
  skippedUserViews: string[];
  unsupportedViews: string[];
  queueMode: QueueMode;
  probedViews: Record<string, any>;
}

export interface FetchModuleViewDataOptions {
  rpcUrl: string;
  moduleId: ModuleId;
  proxyBase?: string;
  allowedViews?: string[];
  userAddress?: string;
}

import type { ModuleId, ArtifactView } from "../core/types.js";

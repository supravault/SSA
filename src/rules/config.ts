/**
 * Safe entrypoint exceptions for Supra staking modules
 * These are expected patterns in staking flows and should not trigger CRITICAL findings
 */

/**
 * Safe entrypoint patterns that are expected in staking modules
 * These functions typically have proper access control via request/fulfill pattern
 */
export const SAFE_ENTRYPOINT_EXCEPTIONS = [
  "stake",
  "stake_fa",
  "unstake",
  "withdraw_request",
  "claim_request",
  "withdraw",
  "claim",
  "fulfill_withdraw",
  "fulfill_claim",
  "view_",
  "get_",
  "query_",
  "read_",
];

/**
 * Safe asset outflow patterns for staking modules
 * These are expected in staking flows with proper access control
 */
export const SAFE_OUTFLOW_EXCEPTIONS = [
  "withdraw_request",
  "claim_request",
  "fulfill_withdraw",
  "fulfill_claim",
  "unstake",
  "view_",
  "get_",
];

/**
 * Get safe exceptions with optional override from environment
 */
export function getSafeExceptions(): {
  entrypoints: string[];
  outflows: string[];
} {
  const overrideEnv = process.env.OVERRIDE_SAFE_EXCEPTIONS;
  const overrideList = overrideEnv
    ? overrideEnv.split(",").map((s) => s.trim().toLowerCase())
    : [];

  return {
    entrypoints: [...SAFE_ENTRYPOINT_EXCEPTIONS, ...overrideList],
    outflows: [...SAFE_OUTFLOW_EXCEPTIONS, ...overrideList],
  };
}

/**
 * Check if a function name matches a safe exception pattern
 */
export function isSafeException(
  functionName: string,
  type: "entrypoint" | "outflow"
): boolean {
  const exceptions = getSafeExceptions();
  const patterns = type === "entrypoint" ? exceptions.entrypoints : exceptions.outflows;
  const fnLower = functionName.toLowerCase();

  return patterns.some((pattern) => fnLower.includes(pattern));
}


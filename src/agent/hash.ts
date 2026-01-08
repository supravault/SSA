/**
 * Level 3 Agent/Watcher Mode Hashing Utilities
 * Hash computation for module surfaces and overall state
 */

import { createHash } from "crypto";

/**
 * Compute hash from function names array
 * Sorts names for deterministic hashing
 * Uses pipe separator for consistency
 */
export function surfaceHashFromFnNames(fnNames: string[]): string {
  const sorted = [...fnNames].sort();
  const combined = sorted.join("|");
  return createHash("sha256").update(combined).digest("hex").substring(0, 16);
}

/**
 * Compute overall hash from map of moduleId -> hash
 * Sorts by moduleId for deterministic hashing
 */
export function overallHashFromMap(map: Record<string, string>): string {
  const entries = Object.entries(map)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${v}`);
  const combined = entries.join("|");
  return createHash("sha256").update(combined).digest("hex").substring(0, 16);
}


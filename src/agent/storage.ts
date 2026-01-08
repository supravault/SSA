/**
 * Level 3 Agent/Watcher Mode Storage Utilities
 * File I/O for snapshot persistence
 */

import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from "fs";
import { dirname, join } from "path";

/**
 * Ensure directory exists, creating it if necessary
 */
export function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/**
 * Read JSON file, returning null if file doesn't exist or is invalid
 * Note: This function returns null for both "file doesn't exist" and "parse error" cases.
 * Use existsSync separately if you need to distinguish between these cases.
 * 
 * Handles UTF-8 BOM (Byte Order Mark) that PowerShell Set-Content may add.
 */
export function readJsonFile<T>(path: string): T | null {
  try {
    if (!existsSync(path)) {
      return null;
    }
    const raw = readFileSync(path, "utf-8");
    // Strip UTF-8 BOM (U+FEFF) if present (PowerShell Set-Content adds this)
    const text = raw.replace(/^\uFEFF/, "");
    return JSON.parse(text) as T;
  } catch (error) {
    // File exists but invalid JSON - return null (caller should check existsSync to distinguish)
    return null;
  }
}

/**
 * Write JSON file atomically (write to temp file then rename)
 * Writes UTF-8 without BOM (Node.js default behavior - never adds BOM).
 */
export function writeJsonAtomic(path: string, data: unknown): void {
  const tempPath = `${path}.tmp`;
  try {
    // Ensure directory exists
    ensureDir(dirname(path));
    
    // Write to temp file (UTF-8 without BOM - Node.js never adds BOM by default)
    writeFileSync(tempPath, JSON.stringify(data, null, 2), "utf-8");
    
    // Atomic rename
    renameSync(tempPath, path);
  } catch (error) {
    // Clean up temp file on error
    try {
      if (existsSync(tempPath)) {
        writeFileSync(tempPath, "", "utf-8"); // Clear it
      }
    } catch {
      // Ignore cleanup errors
    }
    throw error;
  }
}

/**
 * Sanitize filename part (strip non [a-zA-Z0-9._-], collapse)
 */
export function sanitizeFilenamePart(str: string): string {
  if (!str) return "UNKNOWN";
  return str
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
}

/**
 * Get snapshot path for coin
 * Format: state/coin_<address>__<module>__<symbol>.json
 */
export function snapshotPathForCoin(
  stateDir: string,
  coinType: string,
  moduleName?: string,
  symbol?: string
): string {
  // Extract publisher address from coinType (before first ::)
  const parts = coinType.split("::");
  const address = parts[0] || "UNKNOWN";
  const module = moduleName || parts[1] || "UNKNOWN";
  const sym = symbol || parts[2] || "UNKNOWN";
  
  const sanitizedAddr = sanitizeFilenamePart(address);
  const sanitizedModule = sanitizeFilenamePart(module);
  const sanitizedSymbol = sanitizeFilenamePart(sym);
  
  return join(stateDir, `coin_${sanitizedAddr}__${sanitizedModule}__${sanitizedSymbol}.json`);
}

/**
 * Get snapshot path for FA
 * Format: state/fa_<fa_address>.json
 */
export function snapshotPathForFA(stateDir: string, faAddress: string): string {
  const sanitized = sanitizeFilenamePart(faAddress);
  return join(stateDir, `fa_${sanitized}.json`);
}

/**
 * Get ping snapshot path for FA
 * Format: state/ping/fa/<fa_address>.json
 */
export function pingSnapshotPathForFA(stateDir: string, faAddress: string): string {
  const sanitized = sanitizeFilenamePart(faAddress);
  const pingDir = join(stateDir, "ping", "fa");
  ensureDir(pingDir);
  return join(pingDir, `${sanitized}.json`);
}

/**
 * Get ping snapshot path for Coin
 * Format: state/ping/coin/<sanitized_coin_type>.json
 */
export function pingSnapshotPathForCoin(stateDir: string, coinType: string): string {
  // Sanitize coin type: replace :: with __, strip 0x prefix for filename safety
  let sanitized = coinType
    .replace(/::/g, "__")
    .replace(/^0x/, "")
    .replace(/[^a-zA-Z0-9._-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "");
  
  if (!sanitized || sanitized.length === 0) {
    sanitized = "UNKNOWN";
  }
  
  const pingDir = join(stateDir, "ping", "coin");
  ensureDir(pingDir);
  return join(pingDir, `${sanitized}.json`);
}


/**
 * Module Hash Pinning Utilities
 * Deterministic hashing for module bytecode/ABI to detect stealth upgrades
 */

import { createHash } from "crypto";
import { sha256 } from "./hash.js";

/**
 * Normalize module ID: lowercase address + exact module name
 */
export function normalizeModuleId(moduleId: string): string {
  const parts = moduleId.split("::");
  if (parts.length !== 2) {
    return moduleId.toLowerCase();
  }
  const [address, moduleName] = parts;
  return `${address.toLowerCase()}::${moduleName}`;
}

/**
 * Stable JSON stringify with sorted keys for deterministic hashing
 */
export function stableJson(obj: any): string {
  if (obj === null || obj === undefined) {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map((item) => stableJson(item)).join(",")}]`;
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    const entries = keys.map((key) => `"${key}":${stableJson(obj[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(obj);
}

/**
 * SHA256 hex hash of bytes or string
 */
export function sha256Hex(input: string | Buffer): string {
  return sha256(input);
}

/**
 * Hash module artifact (bytecode preferred, ABI fallback)
 * Returns hash string or null if neither available
 */
export function hashModuleArtifact(artifact: {
  bytecodeHex?: string | null;
  abi?: any | null;
}): { hash: string; basis: "bytecode" | "abi" | "none" } | null {
  // Prefer bytecode if available
  if (artifact.bytecodeHex) {
    // Normalize: remove 0x prefix, lowercase
    let normalized = artifact.bytecodeHex;
    if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
      normalized = normalized.slice(2);
    }
    normalized = normalized.toLowerCase();
    const hash = sha256Hex(Buffer.from(normalized, "hex"));
    return { hash, basis: "bytecode" };
  }

  // Fallback to ABI
  if (artifact.abi) {
    const abiJson = stableJson(artifact.abi);
    const hash = sha256Hex(abiJson);
    return { hash, basis: "abi" };
  }

  return null;
}

/**
 * Compute aggregate hash from sorted module pins
 */
export function aggregateModulePinsHash(
  pins: Array<{
    moduleId: string;
    codeHash: string | null;
    hashBasis: "bytecode" | "abi" | "none";
  }>
): string {
  // Sort by moduleId for determinism
  const sorted = [...pins].sort((a, b) => a.moduleId.localeCompare(b.moduleId));
  const entries = sorted.map((pin) => {
    const hashPart = pin.codeHash || "none";
    return `${pin.moduleId}:${hashPart}:${pin.hashBasis}`;
  });
  const combined = entries.join("|");
  return sha256Hex(combined);
}


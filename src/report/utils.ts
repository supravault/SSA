// src/report/utils.ts
// Utility functions for PDF report generation

import { readFileSync, existsSync } from "fs";

/**
 * Format address in short form (first 6 chars + last 5 chars)
 * Example: 0x8fd1550a61055c1406e04d1a0ddf7049d00c889b59f6823f21ca7d842e1eaf3c
 * Result: 0x8fd1…eaf3c
 */
export function formatAddressShort(address: string): string {
  if (!address || address.length < 11) {
    return address;
  }
  if (address.length <= 11) {
    return address;
  }
  const prefix = address.substring(0, 6);
  const suffix = address.substring(address.length - 5);
  return `${prefix}…${suffix}`;
}

/**
 * Format address in grouped form with spaces and line breaks
 * @param address - Full address string
 * @param groupSize - Number of characters per group (default: 4)
 * @param groupsPerLine - Number of groups per line (default: 6)
 * @returns Formatted address string with spaces and newlines
 * 
 * Example: 0x8fd1550a61055c1406e04d1a0ddf7049d00c889b59f6823f21ca7d842e1eaf3c
 * Result:
 *   0x8f d1 55 0a 61 05
 *   5c 14 06 e0 4d 1a
 *   0d df 70 49 d0 0c
 *   ...
 */
export function formatAddressGrouped(
  address: string,
  groupSize: number = 4,
  groupsPerLine: number = 6
): string {
  if (!address) {
    return "";
  }

  // Remove 0x prefix if present, we'll add it back
  let cleanAddr = address;
  let hasPrefix = false;
  if (address.toLowerCase().startsWith("0x")) {
    cleanAddr = address.substring(2);
    hasPrefix = true;
  }

  // Group into chunks
  const groups: string[] = [];
  for (let i = 0; i < cleanAddr.length; i += groupSize) {
    groups.push(cleanAddr.substring(i, i + groupSize));
  }

  // Add prefix to first group
  if (hasPrefix && groups.length > 0) {
    groups[0] = `0x${groups[0]}`;
  }

  // Combine into lines
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += groupsPerLine) {
    const lineGroups = groups.slice(i, i + groupsPerLine);
    lines.push(lineGroups.join(" "));
  }

  return lines.join("\n");
}

/**
 * Safely read JSON file, stripping BOM and zero-width characters
 */
export function safeJsonRead(filePath: string): any {
  if (!existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  
  let content = readFileSync(filePath, "utf-8");
  
  // Strip BOM (U+FEFF) and other zero-width characters
  content = content.replace(/^\uFEFF/, ""); // BOM at start
  content = content.replace(/[\u200B-\u200D\uFEFF]/g, ""); // Zero-width spaces, BOM anywhere
  
  // Trim leading/trailing whitespace
  content = content.trim();
  
  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Failed to parse JSON from ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

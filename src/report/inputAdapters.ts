// src/report/inputAdapters.ts
// Input adapter schemas for wallet/FA/coin/project normalization
// Ensures consistent structure across different scan types and agent-verify normalization

import type { ScanResult } from "../core/types.js";

/**
 * Canonical scan target representation (normalized across all scan types)
 */
export interface CanonicalTarget {
  kind: "wallet" | "coin" | "fa" | "project";
  address?: string; // Wallet address, FA address, or coin publisher address
  identifier: string; // Module ID, FA address, coin type, or wallet address
  module_address?: string; // For module scans
  module_name?: string; // For module scans
  coin_type?: string; // For coin scans
  fa_address?: string; // For FA scans
}

/**
 * Normalize scan result to canonical target format
 */
export function normalizeTarget(scan: ScanResult): CanonicalTarget {
  const target = scan.target;
  const meta = scan.meta as any;

  // Determine scan kind from target or metadata
  let kind: "wallet" | "coin" | "fa" | "project";
  if (target.module_name === "" || target.module_name === "fa_token" || target.module_name === "coin_token") {
    // Wallet scan or FA/Coin token scan
    if (meta?.wallet_modules !== undefined) {
      kind = "wallet";
    } else if (meta?.fa_metadata) {
      kind = "fa";
    } else if (meta?.coin_metadata) {
      kind = "coin";
    } else {
      kind = "project"; // Fallback for unknown
    }
  } else if (meta?.fa_metadata) {
    kind = "fa";
  } else if (meta?.coin_metadata) {
    kind = "coin";
  } else if (meta?.wallet_modules !== undefined) {
    kind = "wallet";
  } else {
    kind = "project"; // Default for module scans
  }

  const result: CanonicalTarget = {
    kind,
    identifier: target.module_id || target.module_address || "",
  };

  // Extract address based on kind
  if (kind === "wallet") {
    result.address = target.module_address || target.address;
  } else if (kind === "fa") {
    result.fa_address = target.module_address || meta?.fa_metadata?.address;
    result.address = result.fa_address;
  } else if (kind === "coin") {
    const coinMetadata = meta?.coin_metadata;
    result.coin_type = coinMetadata?.coinType || target.module_id;
    result.address = coinMetadata?.publisherAddress || target.module_address;
  } else {
    // project/module
    result.module_address = target.module_address;
    result.module_name = target.module_name;
    result.address = target.module_address;
  }

  return result;
}

/**
 * Input adapter schema for wallet scans
 */
export interface WalletScanAdapter {
  kind: "wallet";
  address: string;
  modules: Array<{
    address: string;
    name: string;
    module_id: string;
  }>;
  scan_level: number; // 1-3 only
  timestamp_iso: string;
}

/**
 * Input adapter schema for FA scans
 */
export interface FAScanAdapter {
  kind: "fa";
  fa_address: string;
  creator_address?: string;
  scan_level: number; // 1-5
  timestamp_iso: string;
}

/**
 * Input adapter schema for coin scans
 */
export interface CoinScanAdapter {
  kind: "coin";
  coin_type: string;
  publisher_address: string;
  creator_address?: string;
  scan_level: number; // 1-5
  timestamp_iso: string;
}

/**
 * Input adapter schema for project/module scans
 */
export interface ProjectScanAdapter {
  kind: "project";
  module_address: string;
  module_name: string;
  module_id: string;
  scan_level: number; // 1-5
  timestamp_iso: string;
}

/**
 * Agent-verify normalization: Normalize scan result to adapter format
 */
export function normalizeToAdapter(scan: ScanResult): WalletScanAdapter | FAScanAdapter | CoinScanAdapter | ProjectScanAdapter {
  const canonical = normalizeTarget(scan);
  const meta = scan.meta as any;

  // Map scan_level from ScanLevel to number
  const levelMap: Record<string, number> = {
    quick: 1,
    standard: 2,
    full: 3,
    monitor: 4,
  };
  const scanLevel = levelMap[scan.scan_level] || 1;

  if (canonical.kind === "wallet") {
    const modules = (meta?.wallet_modules || []).map((m: any) => ({
      address: m.module_address || canonical.address || "",
      name: m.module_name || "",
      module_id: `${m.module_address || canonical.address || ""}::${m.module_name || ""}`,
    }));
    return {
      kind: "wallet",
      address: canonical.address || "",
      modules,
      scan_level: scanLevel,
      timestamp_iso: scan.timestamp_iso,
    };
  } else if (canonical.kind === "fa") {
    return {
      kind: "fa",
      fa_address: canonical.fa_address || canonical.address || "",
      creator_address: meta?.fa_metadata?.creator || meta?.fa_metadata?.ownerOnChain,
      scan_level: scanLevel,
      timestamp_iso: scan.timestamp_iso,
    };
  } else if (canonical.kind === "coin") {
    return {
      kind: "coin",
      coin_type: canonical.coin_type || "",
      publisher_address: canonical.address || "",
      creator_address: meta?.coin_metadata?.creator || meta?.coin_creator_account?.address,
      scan_level: scanLevel,
      timestamp_iso: scan.timestamp_iso,
    };
  } else {
    // project
    return {
      kind: "project",
      module_address: canonical.module_address || "",
      module_name: canonical.module_name || "",
      module_id: canonical.identifier,
      scan_level: scanLevel,
      timestamp_iso: scan.timestamp_iso,
    };
  }
}

/**
 * Extract asset list for cover page (normalized across scan types)
 */
export function extractAssetList(scans: ScanResult[]): Array<{ type: string; identifier: string }> {
  return scans.map((scan) => {
    const canonical = normalizeTarget(scan);
    return {
      type: canonical.kind.toUpperCase(),
      identifier: canonical.identifier,
    };
  });
}

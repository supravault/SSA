// src/analyzers/coin/analyzeCoinResources.ts

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence?: any;
  recommendation?: string;
}

export interface CoinCapabilities {
  hasMintCap: boolean;
  hasBurnCap: boolean;
  hasFreezeCap: boolean;
  hasTransferRestrictions: boolean;
  owner?: string | null;
  admin?: string | null;
  supplyCurrentBase?: string | null;
  supplyMaxBase?: string | null;
  decimals?: number | null;
  supplyCurrentFormatted?: string | null;
  supplyUnknown: boolean;
}

type ResourceItem = { type: string; data: any };

function safeJsonParseArray(s: string): ResourceItem[] | null {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? (v as ResourceItem[]) : null;
  } catch {
    return null;
  }
}

function pickResource(resources: ResourceItem[], endsWith: string): ResourceItem | undefined {
  return resources.find((r) => typeof r?.type === "string" && r.type.endsWith(endsWith));
}

function pickResourceContains(resources: ResourceItem[], contains: string): ResourceItem | undefined {
  return resources.find((r) => typeof r?.type === "string" && r.type.includes(contains));
}

/**
 * Analyze legacy coin resources to extract capabilities
 */
export function analyzeCoinResources(
  resourcesJsonString: string,
  coinType: string
): {
  findings: Finding[];
  caps: CoinCapabilities;
  parsedCount: number;
  resourceTypes: string[];
  supplyNormalizationFailed: boolean;
} {
  const findings: Finding[] = [];
  const caps: CoinCapabilities = {
    hasMintCap: false,
    hasBurnCap: false,
    hasFreezeCap: false,
    hasTransferRestrictions: false,
    owner: null,
    admin: null,
    supplyCurrentBase: null,
    supplyMaxBase: null,
    decimals: null,
    supplyCurrentFormatted: null,
    supplyUnknown: true,
  };

  const resources = safeJsonParseArray(resourcesJsonString);
  if (!resources) {
    return { findings: [], caps, parsedCount: 0, resourceTypes: [], supplyNormalizationFailed: false };
  }

  const resourceTypes = resources.map((r) => r.type).filter(Boolean);

  // Extract coin type components for matching
  const coinTypeParts = coinType.split("::");
  const coinStructName = coinTypeParts.length === 3 ? coinTypeParts[2] : null;

  /**
   * Recursively extract numeric value from nested structures (vec/aggregator/integer/value)
   */
  /**
   * Normalize legacy coin supply value to a plain numeric string.
   * Handles nested structures like vec -> aggregator -> integer -> value
   */
  function normalizeLegacySupply(value: unknown): string | null {
    if (value === null || value === undefined) {
      return null;
    }
    
    // If it's already a number, convert to string
    if (typeof value === "number") {
      // Handle BigInt-compatible numbers (avoid scientific notation)
      if (Number.isInteger(value) && value >= 0) {
        return String(value);
      }
      return null;
    }
    
    // If it's already a string, validate and return
    if (typeof value === "string") {
      // Check if it's a valid numeric string (digits only, no decimals for base units)
      if (/^\d+$/.test(value.trim())) {
        return value.trim();
      }
      // Try to parse as number and convert back to string if valid
      const parsed = parseFloat(value.trim());
      if (!isNaN(parsed) && parsed >= 0 && Number.isInteger(parsed)) {
        return String(parsed);
      }
      return null;
    }
    
    // If it's an object, recursively unwrap common shapes
    if (typeof value === "object" && value !== null) {
      // Handle arrays (vec)
      if (Array.isArray(value)) {
        if (value.length > 0) {
          const extracted = normalizeLegacySupply(value[0]);
          if (extracted) return extracted;
        }
        return null;
      }
      
      // Direct value field
      if ("value" in value && value.value !== undefined && value.value !== null) {
        const extracted = normalizeLegacySupply(value.value);
        if (extracted) return extracted;
      }
      
      // vec -> aggregator -> integer -> value pattern
      if ("vec" in value && Array.isArray(value.vec) && value.vec.length > 0) {
        const extracted = normalizeLegacySupply(value.vec[0]);
        if (extracted) return extracted;
      }
      
      // aggregator -> integer -> value pattern
      if ("aggregator" in value && typeof value.aggregator === "object" && value.aggregator !== null) {
        const extracted = normalizeLegacySupply(value.aggregator);
        if (extracted) return extracted;
      }
      
      // integer -> value pattern (can be object or array)
      if ("integer" in value) {
        if (typeof value.integer === "object" && value.integer !== null) {
          const extracted = normalizeLegacySupply(value.integer);
          if (extracted) return extracted;
        }
      }
      
      // Try magnitude field
      if ("magnitude" in value && value.magnitude !== undefined && value.magnitude !== null) {
        const extracted = normalizeLegacySupply(value.magnitude);
        if (extracted) return extracted;
      }
      
      // Try to find any numeric field by name pattern
      for (const [key, val] of Object.entries(value)) {
        const keyLower = key.toLowerCase();
        if (keyLower.includes("value") || keyLower.includes("amount") || keyLower.includes("supply") || keyLower.includes("total")) {
          const extracted = normalizeLegacySupply(val);
          if (extracted) return extracted;
        }
      }
      
      // Last resort: recursively check all object values
      for (const val of Object.values(value)) {
        if (val !== null && typeof val === "object") {
          const extracted = normalizeLegacySupply(val);
          if (extracted) return extracted;
        }
      }
    }
    
    return null;
  }
  
  // Keep extractNumericValue as an alias for backward compatibility
  const extractNumericValue = normalizeLegacySupply;

  // Track supply normalization failures for coverage reporting
  let supplyNormalizationFailed = false;
  
  // Look for CoinInfo resource
  const coinInfo = pickResourceContains(resources, "::coin::CoinInfo");
  if (coinInfo?.data) {
    // Check for supply info - normalize numeric value from nested structures
    const supplyValue = coinInfo.data.supply || coinInfo.data.total_supply || coinInfo.data.value;
    if (supplyValue !== undefined && supplyValue !== null) {
      const normalizedValue = normalizeLegacySupply(supplyValue);
      if (normalizedValue) {
        caps.supplyCurrentBase = normalizedValue;
        caps.supplyUnknown = false;
      } else {
        // Normalization failed - mark for coverage reporting
        supplyNormalizationFailed = true;
        caps.supplyCurrentBase = null;
      }
    }
    
    // Extract max supply (normalize as well)
    if (coinInfo.data.max_supply !== undefined && coinInfo.data.max_supply !== null) {
      const normalizedMax = normalizeLegacySupply(coinInfo.data.max_supply);
      if (normalizedMax) {
        caps.supplyMaxBase = normalizedMax;
      }
    }
    
    // Extract decimals (default to 6 if not found, common for Move coins)
    if (coinInfo.data.decimals !== undefined && coinInfo.data.decimals !== null) {
      caps.decimals = typeof coinInfo.data.decimals === "number" ? coinInfo.data.decimals : Number(coinInfo.data.decimals);
    } else {
      // Default to 6 if not specified (common for Move coins)
      caps.decimals = 6;
    }
    
    // Format supply with decimals if available
    if (caps.supplyCurrentBase && caps.decimals !== null && caps.decimals !== undefined) {
      try {
        const baseValue = BigInt(caps.supplyCurrentBase);
        const divisor = BigInt(10 ** caps.decimals);
        const wholePart = baseValue / divisor;
        const fractionalPart = baseValue % divisor;
        if (fractionalPart === BigInt(0)) {
          caps.supplyCurrentFormatted = wholePart.toString();
        } else {
          caps.supplyCurrentFormatted = `${wholePart}.${fractionalPart.toString().padStart(caps.decimals, "0")}`;
        }
      } catch {
        // If formatting fails, just use base value
        caps.supplyCurrentFormatted = caps.supplyCurrentBase;
      }
    }
    
    // Check for owner/admin in CoinInfo
    if (coinInfo.data.owner) {
      caps.owner = String(coinInfo.data.owner);
    }
    if (coinInfo.data.admin) {
      caps.admin = String(coinInfo.data.admin);
    }
  }

  // Look for CoinStore resource (indicates transfer restrictions potentially)
  const coinStore = pickResourceContains(resources, "::coin::CoinStore");
  if (coinStore) {
    // CoinStore exists - check for freeze/restriction indicators
    if (coinStore.data?.frozen !== undefined || coinStore.data?.is_frozen) {
      caps.hasTransferRestrictions = true;
    }
    if (coinStore.data?.denylist || coinStore.data?.blacklist) {
      caps.hasTransferRestrictions = true;
    }
  }

  // Look for MintCap
  const mintCap = pickResourceContains(resources, "::coin::MintCapability") || pickResourceContains(resources, "MintCap");
  if (mintCap) {
    caps.hasMintCap = true;
    if (mintCap.data?.owner) {
      caps.owner = String(mintCap.data.owner);
    }
  }

  // Look for BurnCap
  const burnCap = pickResourceContains(resources, "::coin::BurnCapability") || pickResourceContains(resources, "BurnCap");
  if (burnCap) {
    caps.hasBurnCap = true;
  }

  // Look for FreezeCap
  const freezeCap = pickResourceContains(resources, "::coin::FreezeCapability") || pickResourceContains(resources, "FreezeCap");
  if (freezeCap) {
    caps.hasFreezeCap = true;
    if (freezeCap.data?.owner) {
      caps.owner = String(freezeCap.data.owner);
    }
  }

  // Look for other capability patterns
  const capabilityPatterns = [
    { pattern: "SignerCapability", cap: "admin" },
    { pattern: "AdminCapability", cap: "admin" },
    { pattern: "OwnerCapability", cap: "owner" },
  ];

  for (const { pattern, cap } of capabilityPatterns) {
    const capResource = pickResourceContains(resources, pattern);
    if (capResource) {
      if (cap === "admin") {
        caps.admin = capResource.data?.admin || capResource.data?.owner || "present";
      } else if (cap === "owner") {
        caps.owner = capResource.data?.owner || "present";
      }
    }
  }

  // Look for pause/denylist/restriction resources
  const restrictionPatterns = ["PauseCapability", "Denylist", "Blacklist", "Restriction"];
  for (const pattern of restrictionPatterns) {
    const restriction = pickResourceContains(resources, pattern);
    if (restriction) {
      caps.hasTransferRestrictions = true;
    }
  }

  // Emit Level 1 findings
  if (caps.hasMintCap) {
    findings.push({
      id: "COIN-MINT-001",
      severity: "MEDIUM",
      title: "MintCap present (supply can be increased)",
      detail: "MintCapability resource found. Supply is not provably immutable.",
      evidence: { hasMintCap: true },
      recommendation: "If minting is not intended, verify mint authority is properly controlled or remove MintCap.",
    });
  }

  if (caps.hasBurnCap) {
    findings.push({
      id: "COIN-BURN-001",
      severity: "INFO",
      title: "BurnCap present",
      detail: "BurnCapability resource found. Burning may be possible.",
      evidence: { hasBurnCap: true },
      recommendation: "If burn is used for deflation/buyback, document the burn policy.",
    });
  }

  if (caps.hasFreezeCap || caps.hasTransferRestrictions) {
    findings.push({
      id: "COIN-FREEZE-001",
      severity: "MEDIUM",
      title: "FreezeCap or transfer restrictions present",
      detail: "FreezeCapability or transfer restriction resources found. Token transfers may be frozen or restricted.",
      evidence: {
        hasFreezeCap: caps.hasFreezeCap,
        hasTransferRestrictions: caps.hasTransferRestrictions,
      },
      recommendation: "Review freeze/restriction authority. Unauthorized freezes could lock user funds.",
    });
  }

  if (caps.owner || caps.admin) {
    findings.push({
      id: "COIN-OWNER-001",
      severity: "INFO",
      title: "Owner/admin present",
      detail: `Owner/admin resources found. ${caps.owner ? `Owner: ${caps.owner}` : ""} ${caps.admin ? `Admin: ${caps.admin}` : ""}`,
      evidence: { owner: caps.owner, admin: caps.admin },
      recommendation: "Treat owner/admin as an admin surface. Verify owner/admin is trusted.",
    });
  }

  return {
    findings,
    caps,
    parsedCount: resources.length,
    resourceTypes,
    supplyNormalizationFailed,
  };
}



// src/analyzers/fa/analyzeFaResources.ts

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH";

export interface Finding {
  id: string;              // e.g. FA-MINT-001
  severity: Severity;
  title: string;
  detail: string;
  evidence?: any;
  recommendation?: string;
}

export interface FaResourceCapabilities {
  hasMintRef: boolean;
  hasBurnRef: boolean;
  hasTransferRef: boolean;

  hasDepositHook: boolean;
  hasWithdrawHook: boolean;
  hasDerivedBalanceHook: boolean;

  owner?: string | null;

  supplyCurrent?: string | null; // raw string from resource
  supplyMax?: string | null;     // raw string from resource

  // Ref holder addresses (Level 2+)
  mintRefHolder?: string | null;
  burnRefHolder?: string | null;
  transferRefHolder?: string | null;

  // for debugging / UI
  hookModules?: Array<{ module_address: string; module_name: string; function_name: string }>;
  
  // Structured hook targets from DispatchFunctionStore (authoritative)
  hooks?: {
    deposit_hook?: { module_address: string; module_name: string; function_name: string };
    withdraw_hook?: { module_address: string; module_name: string; function_name: string };
    transfer_hook?: { module_address: string; module_name: string; function_name: string };
    pre_transfer_hook?: { module_address: string; module_name: string; function_name: string };
    post_transfer_hook?: { module_address: string; module_name: string; function_name: string };
    derived_balance_hook?: { module_address: string; module_name: string; function_name: string };
  };
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

function getTypeShort(typeTag: string): string {
  // "0x1::fungible_asset::Metadata" -> "fungible_asset::Metadata"
  const parts = typeTag.split("::");
  if (parts.length >= 3) return `${parts[1]}::${parts[2]}`;
  return typeTag;
}

function pickResource(resources: ResourceItem[], endsWith: string): ResourceItem | undefined {
  return resources.find(r => typeof r?.type === "string" && r.type.endsWith(endsWith));
}

export function analyzeFaResources(resourcesJsonString: string): {
  findings: Finding[];
  caps: FaResourceCapabilities;
  parsedCount: number;
} {
  const findings: Finding[] = [];
  const caps: FaResourceCapabilities = {
    hasMintRef: false,
    hasBurnRef: false,
    hasTransferRef: false,

    hasDepositHook: false,
    hasWithdrawHook: false,
    hasDerivedBalanceHook: false,

    owner: null,
    supplyCurrent: null,
    supplyMax: null,

    mintRefHolder: null,
    burnRefHolder: null,
    transferRefHolder: null,

    hookModules: [],
    hooks: undefined,
  };

  const resources = safeJsonParseArray(resourcesJsonString);
  if (!resources) {
    // Don't emit findings for unparseable resources - this is expected in some cases
    // (e.g., when SupraScan doesn't have resources for this address)
    // Return empty findings instead of flagging as an error
    return { findings: [], caps, parsedCount: 0 };
  }

  // --- Core resources ---
  const objCore = pickResource(resources, "::object::ObjectCore");
  if (objCore?.data?.owner) {
    caps.owner = String(objCore.data.owner);
  }

  const supply = pickResource(resources, "::fungible_asset::ConcurrentSupply");
  if (supply?.data?.current) {
    caps.supplyMax = supply.data.current?.max_value != null ? String(supply.data.current.max_value) : null;
    caps.supplyCurrent = supply.data.current?.value != null ? String(supply.data.current.value) : null;
  }

  // Dispatch hooks - extract all hook targets from DispatchFunctionStore
  const dispatch = pickResource(resources, "::fungible_asset::DispatchFunctionStore");
  if (dispatch?.data) {
    const depVec = dispatch.data.deposit_function?.vec ?? [];
    const wdrVec = dispatch.data.withdraw_function?.vec ?? [];
    const derVec = dispatch.data.derived_balance_function?.vec ?? [];
    // Check for transfer hook (if present)
    const trfVec = dispatch.data.transfer_function?.vec ?? [];
    // Check for pre/post hooks (if present)
    const preVec = dispatch.data.pre_transfer_function?.vec ?? [];
    const postVec = dispatch.data.post_transfer_function?.vec ?? [];

    caps.hasDepositHook = Array.isArray(depVec) && depVec.length > 0;
    caps.hasWithdrawHook = Array.isArray(wdrVec) && wdrVec.length > 0;
    caps.hasDerivedBalanceHook = Array.isArray(derVec) && derVec.length > 0;

    // Extract all hook targets with their types
    const allHooks: Array<{ type: string; hook: any }> = [];
    if (depVec.length > 0) {
      depVec.forEach((h: any) => allHooks.push({ type: "deposit", hook: h }));
    }
    if (wdrVec.length > 0) {
      wdrVec.forEach((h: any) => allHooks.push({ type: "withdraw", hook: h }));
    }
    if (derVec.length > 0) {
      derVec.forEach((h: any) => allHooks.push({ type: "derived_balance", hook: h }));
    }
    if (trfVec.length > 0) {
      trfVec.forEach((h: any) => allHooks.push({ type: "transfer", hook: h }));
    }
    if (preVec.length > 0) {
      preVec.forEach((h: any) => allHooks.push({ type: "pre_transfer", hook: h }));
    }
    if (postVec.length > 0) {
      postVec.forEach((h: any) => allHooks.push({ type: "post_transfer", hook: h }));
    }

    // Build structured hooks object and hookModules array
    caps.hooks = {};
    for (const { type, hook } of allHooks) {
      if (hook?.module_address && hook?.module_name && hook?.function_name) {
        const hookTarget = {
          module_address: String(hook.module_address),
          module_name: String(hook.module_name),
          function_name: String(hook.function_name),
        };
        
        // Add to hookModules array (for backward compatibility)
        caps.hookModules!.push(hookTarget);
        
        // Add to structured hooks object
        if (type === "deposit") {
          caps.hooks.deposit_hook = hookTarget;
        } else if (type === "withdraw") {
          caps.hooks.withdraw_hook = hookTarget;
        } else if (type === "transfer") {
          caps.hooks.transfer_hook = hookTarget;
        } else if (type === "pre_transfer") {
          caps.hooks.pre_transfer_hook = hookTarget;
        } else if (type === "post_transfer") {
          caps.hooks.post_transfer_hook = hookTarget;
        } else if (type === "derived_balance") {
          caps.hooks.derived_balance_hook = hookTarget;
        }
      }
    }
    
    // Clean up empty hooks object
    if (Object.keys(caps.hooks).length === 0) {
      caps.hooks = undefined;
    }
  }

  /**
   * Extract address from ref object (tries common field names)
   */
  function extractRefHolderAddress(ref: any): string | null {
    if (!ref || typeof ref !== "object") {
      return null;
    }
    
    // Try common field names that might contain holder/owner/controller addresses
    const addressFields = ["holder", "owner", "controller", "address", "account", "object_id", "id"];
    for (const field of addressFields) {
      if (ref[field] && typeof ref[field] === "string" && ref[field].startsWith("0x")) {
        return ref[field];
      }
    }
    
    // Try nested objects
    if (ref.inner && typeof ref.inner === "object") {
      const innerAddr = extractRefHolderAddress(ref.inner);
      if (innerAddr) return innerAddr;
    }
    
    // Try vec[0] if it's an array-like structure
    if (ref.vec && Array.isArray(ref.vec) && ref.vec.length > 0) {
      const vecAddr = extractRefHolderAddress(ref.vec[0]);
      if (vecAddr) return vecAddr;
    }
    
    return null;
  }

  // Managed FA refs (this is the big one for SVLT)
  // Your SVLT resources show:
  // 0xa4a4...::dispatchable_fa_store::ManagedFungibleAsset { mint_ref, burn_ref, transfer_ref }
  const managed = resources.find(r => typeof r?.type === "string" && r.type.includes("::dispatchable_fa_store::ManagedFungibleAsset"));
  if (managed?.data) {
    caps.hasMintRef = !!managed.data.mint_ref;
    caps.hasBurnRef = !!managed.data.burn_ref;
    caps.hasTransferRef = !!managed.data.transfer_ref;
    
    // Extract holder addresses from refs
    if (managed.data.mint_ref) {
      caps.mintRefHolder = extractRefHolderAddress(managed.data.mint_ref);
    }
    if (managed.data.burn_ref) {
      caps.burnRefHolder = extractRefHolderAddress(managed.data.burn_ref);
    }
    if (managed.data.transfer_ref) {
      caps.transferRefHolder = extractRefHolderAddress(managed.data.transfer_ref);
    }
  }
  
  // Also check for refs in other resource types (e.g., direct MintRef/BurnRef/TransferRef resources)
  // These might be stored as separate resources at specific addresses
  const mintRefResource = pickResource(resources, "::fungible_asset::MintRef");
  if (mintRefResource && !caps.mintRefHolder) {
    // The resource type itself contains the address: 0xADDRESS::fungible_asset::MintRef
    const typeParts = mintRefResource.type?.split("::");
    if (typeParts && typeParts.length > 0 && typeParts[0].startsWith("0x")) {
      caps.mintRefHolder = typeParts[0];
    } else {
      // Try extracting from data
      caps.mintRefHolder = extractRefHolderAddress(mintRefResource.data);
    }
  }
  
  const burnRefResource = pickResource(resources, "::fungible_asset::BurnRef");
  if (burnRefResource && !caps.burnRefHolder) {
    const typeParts = burnRefResource.type?.split("::");
    if (typeParts && typeParts.length > 0 && typeParts[0].startsWith("0x")) {
      caps.burnRefHolder = typeParts[0];
    } else {
      caps.burnRefHolder = extractRefHolderAddress(burnRefResource.data);
    }
  }
  
  const transferRefResource = pickResource(resources, "::fungible_asset::TransferRef");
  if (transferRefResource && !caps.transferRefHolder) {
    const typeParts = transferRefResource.type?.split("::");
    if (typeParts && typeParts.length > 0 && typeParts[0].startsWith("0x")) {
      caps.transferRefHolder = typeParts[0];
    } else {
      caps.transferRefHolder = extractRefHolderAddress(transferRefResource.data);
    }
  }

  // --- Findings mapping (simple + immediately useful) ---

  // Mint - only emit if mint_ref is detected (don't emit "no mint" finding)
  if (caps.hasMintRef) {
    findings.push({
      id: "FA-MINT-001",
      severity: "MEDIUM",
      title: "Mint reference present (supply can be increased)",
      detail:
        "This FA exposes a mint reference in resources (e.g., ManagedFungibleAsset.mint_ref). Supply is not provably immutable.",
      evidence: { hasMintRef: true },
      recommendation:
        "If this is intended (admin-mintable token), document it. If not intended, rotate/lock mint authority or migrate to an immutable supply design.",
    });
  }

  // Burn
  if (caps.hasBurnRef) {
    findings.push({
      id: "FA-BURN-001",
      severity: "INFO",
      title: "Burn reference present",
      detail:
        "This FA exposes a burn reference in resources (e.g., ManagedFungibleAsset.burn_ref). Burning may be possible by an authority.",
      evidence: { hasBurnRef: true },
      recommendation:
        "If burn is used for deflation/buyback, document the burn policy and how authority is controlled.",
    });
  }

  // Hooks
  if (caps.hasDepositHook || caps.hasWithdrawHook || caps.hasDerivedBalanceHook) {
    const hooks = caps.hookModules ?? [];
    findings.push({
      id: "FA-HOOKS-001",
      severity: "MEDIUM",
      title: "FA has dispatch hooks (custom transfer/deposit/withdraw logic)",
      detail:
        "DispatchFunctionStore contains hook functions. Transfers/deposits/withdrawals may execute additional Move code.",
      evidence: {
        deposit: caps.hasDepositHook,
        withdraw: caps.hasWithdrawHook,
        derivedBalance: caps.hasDerivedBalanceHook,
        hooks,
      },
      recommendation:
        "Fetch and analyze the hook modules/functions (module_address/module_name/function_name) to verify no blacklisting, fee siphons, or transfer restrictions.",
    });
  }

  // Owner
  if (caps.owner) {
    findings.push({
      id: "FA-OWNER-001",
      severity: "INFO",
      title: "FA object owner present",
      detail:
        "ObjectCore.owner exists. Depending on framework rules, the owner may have administrative abilities (e.g., managing refs / upgrades / dispatch settings).",
      evidence: { owner: caps.owner },
      recommendation:
        "Treat owner as an admin surface. If high-assurance is needed, verify the owner is a trusted module/account (multisig/DAO) and whether owner can rotate refs.",
    });
  }

  // Supply
  if (caps.supplyCurrent || caps.supplyMax) {
    findings.push({
      id: "FA-SUPPLY-001",
      severity: "INFO",
      title: "Supply info detected",
      detail:
        "ConcurrentSupply resource was found. Current and max supply values are available in resources.",
      evidence: { current: caps.supplyCurrent, max: caps.supplyMax },
    });
  }

  // Extra: Only flag as opaque if we parsed resources AND they don't match expected patterns
  // Don't flag as opaque if resources array is empty - that's expected for framework-managed FAs
  const strongSignals =
    caps.hasMintRef || caps.hasBurnRef || caps.hasDepositHook || caps.hasWithdrawHook || !!caps.owner || !!caps.supplyCurrent;
  // Only emit opaque finding if we have resources but they don't match expected patterns
  // This helps distinguish between "no resources" (framework-managed) vs "unexpected resources" (custom architecture)
  if (!strongSignals && resources.length > 5) {
    // Only flag if we have a significant number of resources but none match expected patterns
    findings.push({
      id: "FA-OPAQUE-001",
      severity: "MEDIUM",
      title: "FA resources did not expose expected authority/supply fields",
      detail:
        "AddressDetail resources parsed, but did not match expected patterns (ManagedFungibleAsset / DispatchFunctionStore / ObjectCore / ConcurrentSupply).",
      evidence: { parsedTypes: resources.slice(0, 20).map(r => getTypeShort(String(r.type))) },
      recommendation:
        "Capture additional SupraScan data (or extend analyzer patterns) to support this FA architecture.",
    });
  }

  return { findings, caps, parsedCount: resources.length };
}


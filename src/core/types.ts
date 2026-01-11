/**
 * Core data types for SSA Scanner
 */

export type ScanLevel = "quick" | "standard" | "full" | "monitor";
export type Verdict = "pass" | "warn" | "fail" | "inconclusive";
export type VerdictTier = "verified" | "metadata" | "inconclusive" | "fail";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EvidenceKind = "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic";

export interface ModuleId {
  address: string;
  module_name: string;
}

export interface Target {
  chain: "supra";
  module_address: string;
  module_name: string;
  module_id: string; // `${address}::${module_name}`
  address?: string; // Optional wallet/address identifier (deprecated, use id)
  id?: string; // Optional target ID (canonical identifier)
  kind?: "wallet" | "fa" | "coin" | "project"; // Scan kind for normalization
}

export interface Evidence {
  kind: EvidenceKind;
  matched: string[]; // keywords/patterns matched
  locations?: Array<{ fn?: string; note: string }>;
  raw_excerpt?: string; // short excerpt if available
}

export interface Finding {
  id: string; // e.g., "SVSSA-MOVE-001"
  title: string;
  severity: Severity;
  confidence: number; // 0-1
  description: string;
  recommendation: string;
  evidence: Evidence;
  references?: string[]; // links or rule docs (optional)
}

export interface BadgeEligibility {
  scanned: boolean;
  no_critical: boolean;
  security_verified: boolean;
  continuously_monitored: boolean;
  reasons: string[]; // human-readable reasons for ineligible
  expires_at_iso?: string; // if eligible
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Scanner capability summary.
 * Note: viewOnly is not part of Capabilities — it belongs to RuleCapabilities.
 *
 * NEW: module profile fields added to support profile-aware scanning (staking vs generic).
 *
 * Important: we keep BOTH naming styles for compatibility:
 * - camelCase fields (moduleProfile, moduleProfileReason) for in-code ergonomics
 * - snake_case fields (module_profile, module_profile_reason) for report meta alignment
 */
export interface Capabilities {
  poolStats: boolean;
  totalStaked: boolean;
  queue: boolean;
  userViews: boolean;

  // NEW (optional): profile-aware scanning (camelCase)
  moduleProfile?: "staking" | "generic";
  moduleProfileReason?: string;

  // NEW (optional): profile-aware scanning (snake_case, compatibility)
  module_profile?: "staking" | "generic";
  module_profile_reason?: string;
}

export interface Summary {
  risk_score: number; // 0-100 (higher = worse)
  verdict: Verdict;
  severity_counts: SeverityCounts;
  badge_eligibility: BadgeEligibility;
  capabilities: Capabilities;
  assurance_level?: "metadata_only" | "adjacent_code_inspected" | "code_verified";
}

export interface Engine {
  name: "ssa-scanner";
  version: string; // from package.json
  ruleset_version: string; // e.g., "move-ruleset-0.1.0" (required for consistency)
}

export interface Artifact {
  fetch_method: "rpc" | "raw_rpc";
  bytecode_b64?: string; // if available
  abi_json?: any; // if available
  source_text?: string; // Move source code if available
  artifact_hash: string; // sha256 over canonical artifact bytes
  binding_note: string; // explanation of what hash binds to
  metadata?: any; // view results or other metadata (optional)

  // Preferred normalized field name (kept)
  artifact_origin?: {
    kind: "supra_ide_export" | "manual" | "supra_rpc_v1" | "supra_rpc_v3";
    path: string;
  };

  /**
   * Backward compatible alias for artifact_origin.
   * Some older code paths referenced Artifact.artifactOrigin.
   */
  artifactOrigin?: {
    kind: "supra_ide_export" | "manual" | "supra_rpc_v1" | "supra_rpc_v3";
    path: string;
  };
}

export interface ScanResult {
  request_id: string;
  target: Target;
  scan_level: ScanLevel;
  timestamp_iso: string;
  engine: Engine;
  artifact: Artifact;
  summary: Summary;
  findings: Finding[];
  meta: {
    scan_options: any;
    rpc_url: string;
    duration_ms: number;
    previous_artifact_hash?: string;

    // SupraScan Evidence Mode - stable schema for GitHub commit + diffing
    suprascan?: {
      summary?: {
        // Coin details (from getCoinDetails) or FA details (from getFaDetails)
        name?: string; // Coin: name, FA: faName
        symbol?: string; // Coin: symbol, FA: faSymbol
        verified?: boolean;
        assetAddress?: string; // Coin: assetAddress, FA: faAddress
        iconUrl?: string; // FA only
        decimals?: number;
        price?: string | number;
        totalSupply?: string | number;
        creatorAddress?: string;
        holders?: number;
        isDualNature?: boolean; // FA only
      };
      resources?: Array<{
        // Parsed from addressDetailSupra.resources (JSON string) -> array of {type, data}
        type: string;
        data?: any;
      }>;
      creatorResources?: Array<{
        // Parsed from addressDetailSupra.resources for creator address
        type: string;
        data?: any;
      }>;
    };

    view_results?: Record<string, any>; // View results used for scanning (optional)
    view_errors?: Array<{
      viewName: string;
      functionId: string;
      error: string;
      type?: "error" | "skipped" | "unsupported"; // error = true failure, skipped = no TARGET_USER, unsupported = queue mode mismatch
    }>;
    skipped_user_views?: string[];
    target_user?: string;
    queue_mode?: "v24" | "legacy" | "none";
    rule_capabilities?: RuleCapabilities;
    verdict_reason?: string;

    wallet_modules?: any[];
    verification_report?: any;
    artifact_mode?: ArtifactMode;
    artifact_loaded?: boolean;

    tx_preview?: Array<{
      transactionHash: string;
      senderAddress: string;
      senderName?: string | null;
      receiverAddress?: string | null;
      receiverName?: string | null;
      transferAmount: string;
      transferAmountUsd?: string | null;
      gasSUPRA?: string | null;
      gasUSD?: string | null;
      transactionStatus: string;
      confirmationTime?: string | null;
      tokenName?: string | null;
      functionName?: string | null;
      type?: string | null;
      vmType?: string | null;
      receivers?: Array<{
        walletAddress: string;
        walletAlias?: string | null;
        isSpecialAddress?: boolean;
        isContractAddress?: boolean;
      }>;
      senders?: Array<{
        walletAddress: string;
        walletAlias?: string | null;
        isSpecialAddress?: boolean;
        isContractAddress?: boolean;
      }>;
    }>;

    artifact_components?: {
      hasSource: boolean;
      hasAbi: boolean;
      hasBytecode: boolean;
      origin: { kind: "supra_ide_export" | "manual" | "supra_rpc_v3"; path: string };
      onChainBytecodeFetched?: boolean;
      moduleIdMatch?: boolean;
    };

    // -----------------------------
    // NEW: Module profiling metadata (report-level meta)
    // -----------------------------
    module_profile?: "staking" | "generic";
    module_profile_reason?: string;

    /**
     * For profile-aware scanners that compute an "effective" view allowlist
     * (e.g., staking profile => required views + queue probes).
     */
    allowed_views_effective?: string[] | undefined;

    // FA-specific metadata
    fa_metadata?: {
      address: string;
      creator?: string;
      symbol?: string;
      decimals?: number;
      totalSupply?: string | number; // Legacy: kept for backward compatibility
      holdersCount?: number;
      name?: string;
      fetchMethod?: string;
      fetchError?: string;
      iconUrl?: string;
      verified?: boolean;
      price?: string | number;
      isDualNature?: boolean;

      supplyOnChainRpc?: string | number;
      supplyIndexerGraphql?: string | number;
      ownerOnChain?: string;

      capabilitiesSummary?: {
        hasMintRef: boolean;
        hasBurnRef: boolean;
        hasTransferRef: boolean;
        hasDepositHook: boolean;
        hasWithdrawHook: boolean;
        hasDispatchFunctions: boolean;
      };

      supplyParityCheck?: {
        driftDetected: boolean;
        tolerance?: string | number;
        rpcSupply?: string | number;
        graphqlSupply?: string | number;
        difference?: string | number;
        differencePercentage?: number;
        likelyCause?: string;
      };

      fa_details?: {
        faName?: string;
        faSymbol?: string;
        decimals?: number;
        holders?: number;
        verified?: boolean;
        price?: string | number;
        totalSupply?: string | number;
        creatorAddress?: string;
      };

      fa_address_resources?: {
        address: string;
        resources?: string;
        owner?: string;
        supplyCurrent?: string;
        supplyCurrentDecimalAdjusted?: string | number;
        capabilities?: {
          hasMintRef: boolean;
          hasBurnRef: boolean;
          hasTransferRef: boolean;
          hasDepositHook: boolean;
          hasWithdrawHook: boolean;
          hasDispatchFunctions: boolean;
        };
      };

      creator_address_resources?: {
        address: string;
        resources?: string;
        owner?: string;
        capabilities?: {
          hasMintRef: boolean;
          hasBurnRef: boolean;
          hasTransferRef: boolean;
          hasDepositHook: boolean;
          hasWithdrawHook: boolean;
          hasDispatchFunctions: boolean;
        };
        modulesPublished?: string[];
        modulesPublishedCount?: number;
      };

      fa_address_transactions?: {
        address: string;
        transactions?: Array<{
          transactionHash?: string;
          senderAddress?: string;
          receiverAddress?: string;
          transferAmount?: string;
          confirmationTime?: string;
          transactionStatus?: string;
          functionName?: string;
          type?: string;
        }>;
        totalItems?: number;
        foundCount?: number;
      };

      creator_address_transactions?: {
        address: string;
        transactions?: Array<{
          transactionHash?: string;
          senderAddress?: string;
          receiverAddress?: string;
          transferAmount?: string;
          confirmationTime?: string;
          transactionStatus?: string;
          functionName?: string;
          type?: string;
        }>;
        totalItems?: number;
        foundCount?: number;
      };
    };

    fa_modules?: string[];
    fa_holders_preview?: Array<{
      address: string;
      addressAlias?: string | null;
      quantity: string;
      value?: string | null;
      percentage?: number;
    }>;
    fa_holders_stats?: {
      totalItems: number;
      pageCount: number;
      pageNumber: number;
      nextPage: boolean;
    };

    fa_resource_analysis?: {
      hasMintRef: boolean;
      hasBurnRef: boolean;
      hasTransferRef: boolean;
      hasDispatchFunctions: boolean;
      hasDepositFunction: boolean;
      hasWithdrawFunction: boolean;
      hasAdminControl: boolean;
      ownerAddress?: string;
      currentSupply?: string | number;
      maxSupply?: string | number | null;
      isSupplyCapped: boolean;
      resourcesParsedCount?: number;
      hookModules?: Array<{ module_address: string; module_name: string; function_name: string }>;
    };

    fa_cross_checks?: {
      creatorAddressMatch?: boolean;
      creatorAddressMismatchReason?: string;
      supplyMetadataClaimsMatch?: boolean;
      supplyMetadataMismatchReason?: string;
      verifiedVsCapabilitiesCheck?: {
        verified?: boolean;
        hasCapabilities: boolean;
        holders?: number;
        capabilitiesPresent: {
          hasMintRef: boolean;
          hasBurnRef: boolean;
          hasTransferRef: boolean;
          hasDepositHook: boolean;
          hasWithdrawHook: boolean;
          hasDispatchFunctions: boolean;
        };
        mismatch?: string;
      };
      ownerMatch?: boolean;
      ownerMismatchReason?: string;
    };

    creator_module_scans?: Array<{
      moduleId: string;
      scanResult: ScanResult;
      bytecode_present?: boolean;
      abi_present?: boolean;
      module_scan_summary?: {
        verdict: Verdict;
        risk_score: number;
        findings_count: number;
      };
    }>;
    creator_modules_scanned?: number;
    metadata_verified?: boolean;
    code_verified?: boolean;
    has_custom_modules?: boolean;
    verdict_tier?: VerdictTier;

    fa_rpc_plan?: {
      provider_chain?: string[];
      v1_resources?: { url?: string; used: boolean };
      v1_view?: { url?: string; attempts?: string[]; used: boolean };
      suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
      resources_endpoint?: string;
      resources_success?: boolean;
      framework_views_enabled?: boolean;
      framework_views_success?: boolean;
      suprascan_graphql_success?: boolean;
    };

    fa_dual_nature_coin_scan?: {
      coin_type?: string;
      scan_result?: ScanResult;
      code_verified?: boolean;
      verdict?: Verdict;
    };

    creator_modules_inspected?: boolean;

    // Coin-specific metadata
    coin_metadata?: {
      coinType: string;
      publisherAddress: string;
      moduleName: string;
      structName: string;
      name?: string;
      symbol?: string;
      decimals?: number;
      totalSupply?: string | number;
      creator?: string;
      holdersCount?: number;
      fetchMethod?: string;
      fetchError?: string;
      iconUrl?: string;
      verified?: boolean;
      price?: string | number;
      isDualNature?: boolean;
      faAddress?: string;

      supplyOnChainRpc?: string | number;
      supplyIndexerGraphql?: string | number;

      supplyParityCheck?: {
        driftDetected: boolean;
        tolerance?: string | number;
        rpcSupply?: string | number;
        graphqlSupply?: string | number;
        difference?: string | number;
        differencePercentage?: number;
        likelyCause?: string;
      };

      coin_details?: {
        name?: string;
        symbol?: string;
        decimals?: number;
        verified?: boolean;
        holders?: number;
        creatorAddress?: string;
        totalSupply?: string | number;
        price?: string | number;
        assetAddress?: string;
        iconUrl?: string;
      };

      coin_publisher_address_resources?: any;
      coin_creator_address_resources?: any;
      coin_creator_address_transactions?: any;
      rpcPlan?: any;
    };

    // Level 4: Creator/Publisher Account Facts
    coin_creator_account?: {
      address: string;
      accountStatus?: "active" | "inactive" | "unknown";
      transactionCount?: number;
      modulesPublished?: string[];
      modulesPublishedCount?: number;
      suspiciousAdminCapabilities?: Array<{
        module: string;
        capability: string;
        severity: Severity;
      }>;
      ownershipLinks?: Array<{
        relatedAddress: string;
        relationship: string;
      }>;
      deploySignals?: Array<{
        timestamp?: string;
        transactionHash?: string;
        module?: string;
      }>;
      upgradeSignals?: Array<{
        timestamp?: string;
        transactionHash?: string;
        module?: string;
        fromVersion?: string;
        toVersion?: string;
      }>;
    };

    // Level 4: Separate resource views for Coin (paired evidence bundle)
    coin_details?: {
      name?: string;
      symbol?: string;
      decimals?: number;
      holders?: number;
      verified?: boolean;
      price?: string | number;
      totalSupply?: string | number;
      creatorAddress?: string;
      assetAddress?: string;
    };

    coin_publisher_address_resources?: {
      address: string;
      resources?: string;
      owner?: string;
      supplyCurrent?: string;
      capabilities?: {
        hasMintCap: boolean;
        hasBurnCap: boolean;
        hasFreezeCap: boolean;
        hasTransferRestrictions: boolean;
        owner?: string;
        admin?: string;
      };
    };

    coin_creator_address_resources?: {
      address: string;
      resources?: string;
      owner?: string;
      capabilities?: {
        hasMintCap: boolean;
        hasBurnCap: boolean;
        hasFreezeCap: boolean;
        hasTransferRestrictions: boolean;
        owner?: string;
        admin?: string;
      };
      modulesPublished?: string[];
      modulesPublishedCount?: number;
    };

    coin_creator_address_transactions?: {
      address: string;
      transactions?: Array<{
        transactionHash?: string;
        senderAddress?: string;
        receiverAddress?: string;
        transferAmount?: string;
        confirmationTime?: string;
        transactionStatus?: string;
        functionName?: string;
        type?: string;
      }>;
      totalItems?: number;
      foundCount?: number;
    };

    coin_cross_checks?: {
      moduleAddressMatchesCreator?: boolean;
      relationshipExplanation?: string;
      supplyMetadataClaimsMatch?: boolean;
      supplyMetadataMismatchReason?: string;
      opaqueAbiButTradable?: boolean;
      opaqueAbiExplanation?: string;
    };

    coin_modules_exist?: boolean;
    coin_bytecode_fetched?: boolean;
    coin_publisher_modules?: string[];
    coin_publisher_modules_count?: number;
    coin_scanned_modules_count?: number;

    coin_rpc_plan?: {
      provider_chain?: string[];
      v3_modules?: { url?: string; used: boolean };
      suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
      framework_views_enabled?: boolean;
      framework_views_success?: boolean;
      suprascan_graphql_success?: boolean;
      bytecode_fetch_success?: boolean;
    };

    security_verified?: boolean;
    surface_report?: SurfaceAreaReport;
  };
}

/**
 * Level 1: Surface Area Report
 * Deterministic enumeration and visibility accounting
 */
export interface SurfaceAreaReport {
  kind: "coin" | "fa";

  publisher?: string;

  modules_total?: number;
  modules_list?: string[];

  entry_functions_total?: number;
  entry_functions_by_module?: Record<string, string[]>;
  exposed_functions_empty_modules?: string[];

  capability_hits_total?: number;
  capability_hits_by_module?: Record<string, string[]>;

  opaque_abi?: {
    flagged: boolean;
    severity: "medium";
    reason: string;
    signal_tradable?: string;
    affected_modules?: string[];
  };

  fa_surface?: {
    surface_known: boolean;
    reason: string;
    control_modules?: string[];
    scanned_modules?: string[];
  };

  // SupraScan evidence (when available)
  suprascan_evidence?: {
    flags?: {
      // FA flags
      hasMintRef?: boolean;
      hasBurnRef?: boolean;
      hasTransferRef?: boolean;
      hasDepositHook?: boolean;
      hasWithdrawHook?: boolean;
      hasDerivedBalanceHook?: boolean;
      hasDispatchFunctions?: boolean;
      // Coin flags
      hasMintCap?: boolean;
      hasBurnCap?: boolean;
      hasFreezeCap?: boolean;
      hasTransferRestrictions?: boolean;
      // Common
      owner?: string | null;
      supplyCurrent?: string | null;
      supplyMax?: string | null;
      decimals?: number | null;
      resourceCount?: number;
      resourceTypes?: string[];
    };
    risk?: {
      score: number; // 0-100
      labels: string[];
    };
  };
}

/**
 * Internal artifact view used by rules
 */
export interface ArtifactView {
  moduleId: ModuleId;
  bytecode: Buffer | null;
  abi: any | null;
  functionNames: string[]; // derived from abi if possible
  entryFunctions: string[]; // if abi provides entry markers
  strings: string[]; // best-effort extraction from bytecode
  metadata: any; // best-effort
}

export type ArtifactMode =
  | "view_only"
  | "view_plus_onchain_module"
  | "hybrid_local"
  | "artifact_only";

export interface RuleCapabilities {
  viewOnly: boolean;
  hasAbi: boolean;
  hasBytecodeOrSource: boolean;
  artifactMode: ArtifactMode;
}

/**
 * Rule execution context
 */
export interface RuleContext {
  artifact: ArtifactView;
  scanLevel: ScanLevel;
  capabilities?: RuleCapabilities; // Optional to support test scenarios, but normalized in executeRules
}




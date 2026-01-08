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

export interface Capabilities {
  poolStats: boolean;
  totalStaked: boolean;
  queue: boolean;
  userViews: boolean;
  // viewOnly is not part of Capabilities - it belongs to RuleCapabilities
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
  artifact_origin?: {
    kind: "supra_ide_export" | "manual" | "supra_rpc_v1" | "supra_rpc_v3";
    path: string;
  };
  artifactOrigin?: {
    kind: "supra_ide_export" | "manual" | "supra_rpc_v1" | "supra_rpc_v3";
    path: string;
  }; // Alias for artifact_origin (normalized in code)
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
    }>; // Failed/skipped/unsupported view calls
    skipped_user_views?: string[]; // Views skipped due to missing user address
    target_user?: string; // User address used for user-specific views (if any)
    queue_mode?: "v24" | "legacy" | "none"; // Detected queue capability mode
    rule_capabilities?: RuleCapabilities; // Capabilities available to rules
    verdict_reason?: string; // Explanation for INCONCLUSIVE or other verdicts
    wallet_modules?: any[]; // Optional wallet modules list
    verification_report?: any; // Optional verification report
    artifact_mode?: ArtifactMode; // "view_only" | "artifact_only" | "hybrid"
    artifact_loaded?: boolean; // Whether local artifact was loaded
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
    }>; // Transaction preview (agent-mode only)
    artifact_components?: {
      hasSource: boolean;
      hasAbi: boolean;
      hasBytecode: boolean;
      origin: { kind: "supra_ide_export" | "manual" | "supra_rpc_v3"; path: string };
      onChainBytecodeFetched?: boolean;
      moduleIdMatch?: boolean; // Whether local artifact module ID matches scan target
    };
    // FA-specific metadata
    fa_metadata?: {
      address: string;
      creator?: string;
      symbol?: string;
      decimals?: number;
      totalSupply?: string | number; // Legacy: kept for backward compatibility
      holdersCount?: number;
      name?: string;
      fetchMethod?: string; // "supra_framework_fa_views" | "supra_rpc_v1_resources" | "suprascan_graphql"
      fetchError?: string;
      // Optional SupraScan-specific fields
      iconUrl?: string;
      verified?: boolean;
      price?: string | number;
      isDualNature?: boolean;
      // Level 4: Dual supply tracking (never overwrite, always show both)
      supplyOnChainRpc?: string | number; // On-chain supply from ConcurrentSupply (canonical, decimal-adjusted)
      supplyIndexerGraphql?: string | number; // Indexer-reported supply from GetFaDetails (economic/UI, already decimal-adjusted)
      ownerOnChain?: string; // Owner from ObjectCore.owner (canonical)
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
        tolerance?: string | number; // Tolerance used for comparison
        rpcSupply?: string | number;
        graphqlSupply?: string | number;
        difference?: string | number; // Absolute difference
        differencePercentage?: number; // Percentage difference
        likelyCause?: string; // Explanation: "decimals", "burned_escrow", "indexer_lag", "dual_nature_asset", "unknown"
      };
      // Level 4: Separate resource views (paired evidence bundle)
      fa_details?: {
        // From GetFaDetails(faAddress)
        faName?: string;
        faSymbol?: string;
        decimals?: number;
        holders?: number;
        verified?: boolean;
        price?: string | number;
        totalSupply?: string | number; // Already decimal-adjusted from indexer
        creatorAddress?: string;
      };
      fa_address_resources?: {
        // From AddressDetail(faAddress) - FA metadata object resources
        address: string;
        resources?: string; // Raw resources JSON string
        owner?: string; // ObjectCore.owner
        supplyCurrent?: string; // ConcurrentSupply.current.value (raw base units)
        supplyCurrentDecimalAdjusted?: string | number; // Decimal-adjusted supply
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
        // From AddressDetail(creatorAddress) - IF creatorAddress differs from faAddress
        address: string;
        resources?: string; // Raw resources JSON string
        owner?: string;
        capabilities?: {
          hasMintRef: boolean;
          hasBurnRef: boolean;
          hasTransferRef: boolean;
          hasDepositHook: boolean;
          hasWithdrawHook: boolean;
          hasDispatchFunctions: boolean;
        };
        modulesPublished?: string[]; // Modules at creator address
        modulesPublishedCount?: number;
      };
      // Level 4: Transaction evidence (supporting evidence)
      fa_address_transactions?: {
        // From GetAllTransactions(faAddress) - last N transactions
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
        // From GetAllTransactions(creatorAddress) - last N transactions
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
    fa_modules?: string[]; // List of module names discovered at FA address
    fa_holders_preview?: Array<{
      address: string;
      addressAlias?: string | null;
      quantity: string;
      value?: string | null;
      percentage?: number;
    }>; // Top 10 holders (page 1)
    fa_holders_stats?: {
      totalItems: number;
      pageCount: number;
      pageNumber: number;
      nextPage: boolean;
    }; // Holder pagination stats
    fa_resource_analysis?: {
      hasMintRef: boolean;
      hasBurnRef: boolean;
      hasTransferRef: boolean;
      hasDispatchFunctions: boolean;
      hasDepositFunction: boolean;
      hasWithdrawFunction: boolean;
      hasAdminControl: boolean;
      ownerAddress?: string;
      currentSupply?: string | number; // Raw base units from ConcurrentSupply.current.value
      maxSupply?: string | number | null;
      isSupplyCapped: boolean;
      resourcesParsedCount?: number;
      hookModules?: Array<{ module_address: string; module_name: string; function_name: string }>;
    }; // FA resource analysis (Level-1 control surface verification)
    // Level 4: FA Cross-checks - "claims vs on-chain reality"
    // Cross-check GetFaDetails (token-facing metadata & stats) vs AddressDetail (actual on-chain resource surface + capability refs)
    fa_cross_checks?: {
      // Cross-check 1: creatorAddress (details) vs ObjectCore.owner (resources)
      creatorAddressMatch?: boolean; // GetFaDetails.creatorAddress vs AddressDetail.resources.ObjectCore.owner
      creatorAddressMismatchReason?: string;
      // Cross-check 2: totalSupply (details) vs ConcurrentSupply.current.value (resources)
      supplyMetadataClaimsMatch?: boolean; // GetFaDetails.totalSupply vs AddressDetail.resources.ConcurrentSupply.current.value (decimal-adjusted)
      supplyMetadataMismatchReason?: string;
      // Cross-check 3: verified/holders (details) vs "capabilities present" (resources)
      verifiedVsCapabilitiesCheck?: {
        verified?: boolean; // GetFaDetails.verified
        hasCapabilities: boolean; // Whether capabilities are present in AddressDetail.resources
        holders?: number; // GetFaDetails.holders
        capabilitiesPresent: {
          hasMintRef: boolean;
          hasBurnRef: boolean;
          hasTransferRef: boolean;
          hasDepositHook: boolean;
          hasWithdrawHook: boolean;
          hasDispatchFunctions: boolean;
        };
        mismatch?: string; // Explanation if verified status doesn't align with capabilities
      };
      // Legacy field names for backward compatibility
      ownerMatch?: boolean; // Alias for creatorAddressMatch
      ownerMismatchReason?: string; // Alias for creatorAddressMismatchReason
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
    }>; // Scans of creator's FA-control modules
    creator_modules_scanned?: number; // Count of scanned creator modules
    metadata_verified?: boolean; // FA metadata verified (via views/resources/indexer)
    code_verified?: boolean; // Framework-managed (0x1 verified + resources) OR custom modules scanned
    has_custom_modules?: boolean; // Whether creator address has custom modules (non-empty modules list)
    verdict_tier?: VerdictTier; // Explicit verdict tier for clarity
    fa_rpc_plan?: {
      provider_chain?: string[]; // e.g., ["resources", "framework_views", "suprascan_graphql"]
      v1_resources?: { url?: string; used: boolean };
      v1_view?: { url?: string; attempts?: string[]; used: boolean };
      suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
      resources_endpoint?: string; // Legacy field
      resources_success?: boolean; // Legacy field
      framework_views_enabled?: boolean; // Legacy field
      framework_views_success?: boolean; // Legacy field
      suprascan_graphql_success?: boolean; // Legacy field
    }; // FA scan RPC plan debug info
    fa_dual_nature_coin_scan?: {
      coin_type?: string;
      scan_result?: ScanResult;
      code_verified?: boolean;
      verdict?: Verdict;
    }; // Dual-nature coin scan result (if FA is also a coin)
    creator_modules_inspected?: boolean; // Whether creator modules were inspected
    // Coin-specific metadata
    coin_metadata?: {
      coinType: string;
      publisherAddress: string;
      moduleName: string;
      structName: string;
      name?: string;
      symbol?: string;
      decimals?: number;
      totalSupply?: string | number; // Legacy: kept for backward compatibility
      creator?: string;
      holdersCount?: number;
      fetchMethod?: string;
      fetchError?: string;
      iconUrl?: string;
      verified?: boolean;
      price?: string | number;
      isDualNature?: boolean; // True if coin is also an FA
      faAddress?: string; // FA address if dual-nature
      // Level 4: Dual supply tracking (never overwrite, always show both)
      supplyOnChainRpc?: string | number; // On-chain supply from RPC (canonical, decimal-adjusted)
      supplyIndexerGraphql?: string | number; // Indexer-reported supply from GraphQL (economic/UI)
      supplyParityCheck?: {
        driftDetected: boolean;
        tolerance?: string | number; // Tolerance used for comparison
        rpcSupply?: string | number;
        graphqlSupply?: string | number;
        difference?: string | number; // Absolute difference
        differencePercentage?: number; // Percentage difference
        likelyCause?: string; // Explanation: "decimals", "burned_escrow", "indexer_lag", "dual_nature_asset", "unknown"
      };
      // Level 4: Separate resource views for Coin (paired evidence bundle) - also stored in coin_metadata
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
        address: string; // Creator/publisher account address (0x...)
        accountStatus?: "active" | "inactive" | "unknown";
        transactionCount?: number; // Total transaction count
        modulesPublished?: string[]; // List of module names published at this address
        modulesPublishedCount?: number;
        suspiciousAdminCapabilities?: Array<{
          module: string;
          capability: string;
          severity: Severity;
        }>;
        ownershipLinks?: Array<{
          relatedAddress: string;
          relationship: string; // "owns", "deployed_by", "upgraded_by", etc.
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
        // From GetCoinDetails(coinType) - IMPORTANT: Field names match actual GraphQL API
        name?: string; // GraphQL field: name (NOT coinName)
        symbol?: string; // GraphQL field: symbol (NOT coinSymbol)
        decimals?: number;
        holders?: number;
        verified?: boolean;
        price?: string | number;
        totalSupply?: string | number; // Indexer-reported supply
        creatorAddress?: string;
        assetAddress?: string; // GraphQL field: assetAddress (NOT coinAddress)
      };
      coin_publisher_address_resources?: {
        // From AddressDetail(publisherAddress) - publisher wallet resources with CoinInfo<T>
        address: string;
        resources?: string; // Raw resources JSON string (addressDetailSupra.resources)
        owner?: string; // ObjectCore.owner (canonical owner)
        supplyCurrent?: string; // CoinInfo<T>.supply.value (raw base units)
        capabilities?: {
          hasMintCap: boolean; // Mint/burn/transfer refs from resources
          hasBurnCap: boolean;
          hasFreezeCap: boolean;
          hasTransferRestrictions: boolean;
          owner?: string;
          admin?: string;
        };
      };
      coin_creator_address_resources?: {
        // From AddressDetail(creatorAddress) - creator wallet resources
        address: string;
        resources?: string; // Raw resources JSON string (addressDetailSupra.resources)
        owner?: string;
        capabilities?: {
          hasMintCap: boolean;
          hasBurnCap: boolean;
          hasFreezeCap: boolean;
          hasTransferRestrictions: boolean;
          owner?: string;
          admin?: string;
        };
        modulesPublished?: string[]; // Modules at creator address
        modulesPublishedCount?: number;
      };
      // Level 4: Transaction evidence (supporting evidence)
      coin_creator_address_transactions?: {
        // From GetAllTransactions(creatorAddress) - last N transactions
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
    // Level 4: Cross-checks
    coin_cross_checks?: {
      moduleAddressMatchesCreator?: boolean; // coin's module address == creator?
      relationshipExplanation?: string; // Explanation if module address != creator
      supplyMetadataClaimsMatch?: boolean; // GraphQL claims vs on-chain resources
      supplyMetadataMismatchReason?: string;
      opaqueAbiButTradable?: boolean; // "opaque ABI" but tradable, etc.
      opaqueAbiExplanation?: string;
    };
    coin_modules_exist?: boolean; // Whether modules exist at publisher address
    coin_bytecode_fetched?: boolean; // Whether bytecode was fetched
    coin_publisher_modules?: string[]; // List of all module names at publisher address
    coin_publisher_modules_count?: number; // Total count of modules at publisher address
    coin_scanned_modules_count?: number; // Count of modules scanned with bytecode/ABI
    coin_rpc_plan?: {
      provider_chain?: string[];
      v3_modules?: { url?: string; used: boolean };
      suprascan_graphql?: { url?: string; queryName?: string; used: boolean };
      framework_views_enabled?: boolean; // Legacy field
      framework_views_success?: boolean; // Legacy field
      suprascan_graphql_success?: boolean; // Legacy field
      bytecode_fetch_success?: boolean; // Legacy field
    }; // Coin scan RPC plan debug info
    security_verified?: boolean; // True only when bytecode analyzed and no high/critical findings
    surface_report?: SurfaceAreaReport; // Level 1: Surface area enumeration report
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

export type ArtifactMode = "view_only" | "view_plus_onchain_module" | "hybrid_local" | "artifact_only";

export interface RuleCapabilities {
  viewOnly: boolean; // Only view results available, no ABI/bytecode
  hasAbi: boolean; // ABI is available
  hasBytecodeOrSource: boolean; // Bytecode or source-derived strings available
  artifactMode: ArtifactMode; // "view_only" | "view_plus_onchain_module" | "hybrid_local" | "artifact_only"
}

/**
 * Rule execution context
 */
export interface RuleContext {
  artifact: ArtifactView;
  scanLevel: ScanLevel;
  capabilities?: RuleCapabilities; // Optional to support test scenarios, but normalized in executeRules
}


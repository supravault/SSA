/**
 * Level 3 Agent/Watcher Mode Types
 * Snapshot schema and diff output types
 */

export type Severity = "info" | "medium" | "high" | "critical";

export type ChangeType =
  | "SUPPLY_CHANGED"
  | "SUPPLY_CHANGED_LARGE"
  | "SUPPLY_CHANGED_SMALL"
  | "SUPPLY_MAX_CHANGED"
  | "OWNER_CHANGED"
  | "ADMIN_CHANGED"
  | "CAPABILITIES_CHANGED"
  | "PRIVILEGE_ESCALATION"
  | "HOOKS_CHANGED"
  | "HOOK_MODULE_CODE_CHANGED"
  | "COIN_MODULE_CODE_CHANGED"
  | "MODULE_ADDED"
  | "MODULE_REMOVED"
  | "ABI_SURFACE_CHANGED"
  | "COVERAGE_CHANGED"
  | "FINDINGS_CHANGED"
  | "FINDING_ADDED"
  | "FINDING_REMOVED"
  | "PRIVILEGES_CHANGED"
  | "INVARIANTS_CHANGED";

export interface SnapshotMeta {
  schema_version: string;
  timestamp_iso: string;
  rpc_url: string;
  scanner_version: string;
}

export interface CoinIdentity {
  coinType: string;
  publisherAddress: string;
  moduleName: string;
  symbol?: string;
}

export interface FAIdentity {
  faAddress: string;
  objectOwner?: string | null;
}

export interface SupplyData {
  supplyCurrentBase?: string | null;
  decimals?: number | null;
  supplyCurrentFormatted?: string | null;
  supplyMaxBase?: string | null; // FA only
}

export interface CoinCapabilities {
  hasMintCap: boolean;
  hasBurnCap: boolean;
  hasFreezeCap: boolean;
  hasTransferRestrictions: boolean;
}

export interface FACapabilities {
  hasMintRef: boolean;
  hasBurnRef: boolean;
  hasTransferRef: boolean;
  hasDepositHook: boolean;
  hasWithdrawHook: boolean;
  hasDerivedBalanceHook: boolean;
}

export interface ModuleInfo {
  moduleId: string; // fully qualified: address::module_name
  abi_fetched: boolean;
  entry_fn_names: string[];
  exposed_fn_names: string[];
}

export interface ControlSurface {
  relevantModules: string[]; // fully qualified module IDs
  modules: Record<string, ModuleInfo>; // keyed by moduleId
}

export interface FAHookTarget {
  module_address: string;
  module_name: string;
  function_name: string;
  risk?: "high" | "medium" | "low";
}

export interface HookModulePin {
  module_address: string;
  module_name: string;
  moduleId: string;
  codeHash: string | null;
  hashBasis: "bytecode" | "abi" | "none";
  fetchedFrom: "rpc_v3" | "rpc_v1" | "unknown";
}

export interface ModulePin {
  module_address: string;
  module_name: string;
  moduleId: string;
  codeHash: string | null;
  hashBasis: "bytecode" | "abi" | "none";
  fetchedFrom: "rpc_v3" | "rpc_v1" | "unknown";
  role?: "coin_defining" | "rpc_v3_list" | "publisher_module";
}

export interface FAControlSurface extends ControlSurface {
  hookModules: Array<{ module_address: string; module_name: string; function_name: string }>;
  hooks?: {
    deposit_hook?: FAHookTarget;
    withdraw_hook?: FAHookTarget;
    transfer_hook?: FAHookTarget;
    pre_transfer_hook?: FAHookTarget;
    post_transfer_hook?: FAHookTarget;
    derived_balance_hook?: FAHookTarget;
  };
  hookModulePins?: HookModulePin[];
  ownerModulesCount?: number;
}

export interface CoinControlSurface extends ControlSurface {
  modulePins?: ModulePin[];
}

export interface Coverage {
  coverage: "complete" | "partial";
  reasons: string[];
}

export interface FindingSummary {
  id: string;
  severity: Severity;
  title?: string;
}

export interface PrivilegeReport {
  byClass: Record<string, Array<{
    class: string;
    fnName: string;
    moduleId: string;
    evidence?: any;
  }>>;
  all: Array<{
    class: string;
    fnName: string;
    moduleId: string;
    evidence?: any;
  }>;
  hasOpaqueControl: boolean;
}

export interface InvariantReport {
  items: Array<{
    id: string;
    status: "ok" | "warning" | "violation" | "unknown";
    title: string;
    detail: string;
    evidence?: any;
  }>;
  overall: "ok" | "warning" | "violation" | "unknown";
}

export interface EvidenceBundle {
  sourcesUsed: Array<"rpc_v3" | "rpc_v1" | "rpc_v3_2" | "suprascan">;
  parity: Array<{
    id: string;
    status: "match" | "mismatch" | "unknown";
    detail: string;
    evidence?: any;
  }>;
}

/**
 * FA Indexer Parity Record - typed evidence for SupraScan corroboration
 * Used to explicitly document why indexer parity is or isn't available
 */
export type IndexerParityStatus = "supported" | "partial" | "unsupported" | "unsupported_schema" | "error" | "not_requested";

export interface IndexerParityRecord {
  status: IndexerParityStatus;
  reason: string;
  /** Which fields were compared (when supported) */
  fieldsCompared?: ("owner" | "supply" | "supplyMax" | "hooks")[];
  /** Evidence tier achieved: multi_rpc when unsupported, multi_rpc_plus_indexer when supported */
  evidenceTierImpact: "multi_rpc" | "multi_rpc_plus_indexer";
          /** Detailed parity results for each field */
          details?: {
            ownerParity?: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" | "n/a";
            supplyParity?: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" | "n/a";
            supplyMaxParity?: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" | "n/a";
            hooksParity?: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" | "n/a";
            hookHashParity?: "match" | "mismatch" | "unknown" | "insufficient" | "unsupported" | "n/a";
          };
  /** Mismatches found between RPC and SupraScan */
  mismatches?: Array<{
    field: "owner" | "supply" | "hooks" | "hookHash";
    rpcValue: any;
    suprascanValue: any;
    reason: string;
  }>;
}

export interface SnapshotBase {
  meta: SnapshotMeta;
  identity: CoinIdentity | FAIdentity;
  supply: SupplyData;
  capabilities: CoinCapabilities | FACapabilities;
  control_surface: ControlSurface | FAControlSurface;
  coverage: Coverage;
  findings: FindingSummary[];
  hashes: {
    moduleSurfaceHash: Record<string, string>; // keyed by moduleId
    overallSurfaceHash: string;
    hookModulesSurfaceHash?: string; // FA only
    modulePinsHash?: string; // COIN only
  };
  privileges?: PrivilegeReport;
  invariants?: InvariantReport;
  evidence?: EvidenceBundle;
}

export interface CoinSnapshot extends SnapshotBase {
  identity: CoinIdentity;
  capabilities: CoinCapabilities;
  control_surface: CoinControlSurface;
}

export interface FASnapshot extends SnapshotBase {
  identity: FAIdentity;
  capabilities: FACapabilities;
  control_surface: FAControlSurface;
}

export interface ChangeItem {
  type: ChangeType;
  severity: Severity;
  before: any;
  after: any;
  evidence?: any;
}

export interface AgentHints {
  requiresMultiRpc?: boolean;
  requiresTxCorrelation?: boolean;
  escalationReason?: string;
}

export interface DiffResult {
  changed: boolean;
  changes: ChangeItem[];
  agentHints?: AgentHints;
}

/**
 * Risk signal identifiers - stable strings for agent consumption
 */
export type RiskSignal =
  | "HASH_PINNED"
  | "HASH_CONFLICT"
  | "HASH_UNAVAILABLE"
  | "INDEXER_CORROBORATED"
  | "INDEXER_CONFLICT"
  | "INDEXER_UNSUPPORTED"
  | "INDEXER_NOT_REQUESTED"
  | "BEHAVIOR_MATCHED"
  | "BEHAVIOR_NO_ACTIVITY"
  | "BEHAVIOR_UNAVAILABLE"
  | "ABI_OPAQUE"
  | "ABI_OPAQUE_ACTIVE"
  | "PHANTOM_ENTRYPOINTS"
  | "HOOK_CONTROLLED"
  | "HOOK_UNVERIFIED"
  | "PRIVILEGE_UNVERIFIED"
  | "PRIVILEGE_ESCALATION_POSSIBLE"
  | "MULTI_RPC_CONFIRMED"
  | "MULTI_RPC_CONFLICT"
  | "SUPPLY_CONFLICT"
  | "OWNER_CONFLICT"
  | "CAPS_CONFLICT"
  | "MINT_REACHABLE"
  | "BURN_REACHABLE"
  | "ADMIN_REACHABLE";

/**
 * Risk level classification
 */
export type RiskLevel =
  | "SAFE_STATIC"
  | "SAFE_DYNAMIC"
  | "OPAQUE_BUT_ACTIVE"
  | "ELEVATED_RISK"
  | "DANGEROUS";

/**
 * Risk synthesis result - agent-grade verdict
 */
export interface RiskSynthesis {
  signals: RiskSignal[];
  risk_level: RiskLevel;
  rationale: string[];
}


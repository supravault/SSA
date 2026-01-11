import { randomUUID } from "crypto";
import type { ModuleId, ScanLevel, ScanResult, Verdict, ArtifactMode } from "./types.js";
import {
  fetchModuleViewData,
  REQUIRED_VIEWS,
  V24_QUEUE_VIEWS,
  LEGACY_QUEUE_VIEWS,
  USER_REQUIRED_VIEWS,
} from "../rpc/supra.js";
import { buildArtifactViewHybrid } from "./artifactViewBuilder.js";
import { buildArtifactHybrid } from "./artifact.js";
import { executeRules } from "./ruleset.js";
import {
  calculateRiskScore,
  calculateSeverityCounts,
  determineVerdict,
  calculateBadgeEligibility,
} from "./scoring.js";
import { createViewErrorFindings } from "../rules/move/rule_view_errors.js";
import { getIsoTimestamp } from "../utils/time.js";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { loadArtifact } from "./artifactLoader.js";
import { fetchAccountModuleV3 } from "../rpc/supraAccountsV3.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import { fetchAllTransactionsFromSupraScan } from "../rpc/supraScanGraphql.js";
import type { SupraScanTransactionSummary } from "../rpc/supraScanGraphql.js";
import type { Finding } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Get engine version from package.json
 */
function getEngineVersion(): string {
  try {
    const packagePath = join(__dirname, "../../package.json");
    const pkg = JSON.parse(readFileSync(packagePath, "utf-8"));
    return pkg.version || "0.1.0";
  } catch {
    return "0.1.0";
  }
}

export interface ScanOptions {
  scan_level?: ScanLevel;
  rpc_url?: string;
  proxy_base?: string; // Railway proxy base URL
  allowed_views?: string[]; // Allowlisted view functions to call (overrides auto-profile)
  target_user?: string; // User address for user-specific views
  previous_artifact_hash?: string;
  artifact_path?: string; // Path to local artifact file
  artifact_dir?: string; // Directory containing artifacts
}

type ModuleProfile = "staking" | "generic";

function normalizeName(s: string): string {
  return String(s || "").toLowerCase().trim();
}

/**
 * Heuristic module profiling:
 * - If it *looks* like staking, treat as staking.
 * - Otherwise treat as generic.
 */
function guessModuleProfile(moduleName: string): { profile: ModuleProfile; reason: string } {
  const n = normalizeName(moduleName);

  const stakingHints = [
    "staking",
    "stake",
    "staker",
    "reward_per_token",
    "total_staked",
    "pool_stats",
    "withdraw_request",
    "claim_request",
  ];

  if (n.includes("staking")) return { profile: "staking", reason: `module_name contains "staking"` };

  if (n.startsWith("stake") || n.endsWith("stake") || n.includes("_stake") || n.includes("stake_")) {
    return { profile: "staking", reason: `module_name matches stake pattern` };
  }

  if (stakingHints.some((h) => n.includes(h))) {
    return { profile: "staking", reason: `module_name contains staking hint` };
  }

  return { profile: "generic", reason: `no staking naming hints; treating as generic` };
}

/**
 * If caller provided allowed_views explicitly, use it.
 * Otherwise:
 * - staking => undefined (use fetchModuleViewData defaults)
 * - generic => [] (but ONLY works if fetchModuleViewData treats [] as override!)
 */
function computeAllowedViews(
  profile: ModuleProfile,
  userAllowedViews?: string[]
): string[] | undefined {
  if (Array.isArray(userAllowedViews)) return userAllowedViews;
  if (profile === "staking") return undefined;
  return [];
}

/**
 * Run a security scan on a Supra Move module
 * Uses view-based inspection and hybrid ABI/bytecode when possible
 */
export async function runScan(moduleId: ModuleId, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = Date.now();
  const requestId = randomUUID();
  const timestamp = getIsoTimestamp();
  const scanLevel = options.scan_level || "quick";
  const rpcUrl = options.rpc_url || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
  const proxyBase = options.proxy_base || process.env.PROD_API;

  const targetUser = options.target_user || process.env.TARGET_USER?.toLowerCase().trim();

  // Profile module early
  const profileGuess = guessModuleProfile(moduleId.module_name);
  const moduleProfile: ModuleProfile = profileGuess.profile;

  // Decide which views to call
  const allowedViews = computeAllowedViews(moduleProfile, options.allowed_views);

  // Load local artifacts if provided
  const artifactPath = options.artifact_path || process.env.ARTIFACT_PATH;
  const artifactDir = options.artifact_dir || process.env.ARTIFACT_DIR;
  let loadedArtifact = loadArtifact(artifactPath, artifactDir, moduleId.module_name);

  // HYBRID: Fetch on-chain bytecode/ABI (v3-first with fallback)
  if (!loadedArtifact?.bytecodeBuffer || !loadedArtifact?.abi) {
    const rpcOptions: RpcClientOptions = {
      rpcUrl,
      timeout: 10000,
      retries: 2,
      retryDelay: 500,
    };

    try {
      const rpcResult = await fetchAccountModuleV3(
        moduleId.address,
        moduleId.module_name,
        rpcOptions
      );

      if (!loadedArtifact) {
        loadedArtifact = {
          artifactOrigin: {
            kind: "supra_rpc_v3",
            path: `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`,
          },
        };
      }

      // Bytecode
      if (!loadedArtifact.bytecodeBuffer && rpcResult.module?.bytecode) {
        let bytecodeRaw = rpcResult.module.bytecode;
        if (bytecodeRaw.startsWith("0x")) bytecodeRaw = bytecodeRaw.slice(2);

        try {
          loadedArtifact.bytecodeBuffer = Buffer.from(bytecodeRaw, "hex");
          loadedArtifact.bytecodeHex = bytecodeRaw;
        } catch {
          try {
            loadedArtifact.bytecodeBuffer = Buffer.from(bytecodeRaw, "base64");
            loadedArtifact.bytecodeHex = loadedArtifact.bytecodeBuffer.toString("hex");
          } catch {
            // ignore
          }
        }

        if (loadedArtifact.bytecodeBuffer) {
          loadedArtifact.artifactOrigin.kind = "supra_rpc_v3";
          loadedArtifact.artifactOrigin.path = `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`;
          loadedArtifact.onChainBytecodeFetched = true;
        }
      }

      // ABI
      if (!loadedArtifact.abi && rpcResult.module?.abi) {
        loadedArtifact.abi = rpcResult.module.abi;
        if (!loadedArtifact.bytecodeBuffer) {
          loadedArtifact.artifactOrigin.kind = "supra_rpc_v3";
          loadedArtifact.artifactOrigin.path = `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`;
        }
      }
    } catch (error) {
      const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.DEBUG_VIEW === "1";
      if (debug) {
        console.debug(
          `[Hybrid] RPC module fetch failed: ${error instanceof Error ? error.message : String(error)}`
        );
        console.debug(`[Hybrid] Falling back to view-only mode`);
      }
    }
  }

  // Fetch module data via view functions
  const viewData = await fetchModuleViewData({
    rpcUrl,
    moduleId,
    proxyBase,
    allowedViews,
    userAddress: targetUser,
  });

  // Profile-specific required views
  const requiredViewsForProfile = moduleProfile === "staking" ? REQUIRED_VIEWS : [];
  const requiredViewErrors = viewData.viewErrors.filter(
    (e) =>
      requiredViewsForProfile.includes(e.viewName as any) &&
      (!e.type || e.type === "error")
  );
  const hasRequiredViewFailures = requiredViewErrors.length > 0;

  // Build artifact view for rules
  const artifactView = buildArtifactViewHybrid(
    moduleId,
    viewData.viewResults,
    loadedArtifact || undefined
  );

  const hasAbi = artifactView.abi !== null && artifactView.abi !== undefined;
  const hasBytecodeOrSource =
    artifactView.bytecode !== null ||
    artifactView.strings.length > 0 ||
    loadedArtifact?.sourceText !== undefined;
  const viewOnly = !hasAbi && !hasBytecodeOrSource;

  const hasViewResults = Object.keys(viewData.viewResults).length > 0;
  const hasLocalArtifact =
    !!loadedArtifact &&
    (loadedArtifact.artifactOrigin.kind === "supra_ide_export" ||
      loadedArtifact.artifactOrigin.kind === "manual");
  const hasOnChainModule =
    loadedArtifact?.onChainBytecodeFetched ||
    (loadedArtifact?.bytecodeBuffer &&
      (loadedArtifact.artifactOrigin.kind === "supra_rpc_v1" ||
        loadedArtifact.artifactOrigin.kind === "supra_rpc_v3"));

  let artifactMode: ArtifactMode;
  if (hasViewResults && hasLocalArtifact) artifactMode = "hybrid_local";
  else if (hasViewResults && hasOnChainModule) artifactMode = "view_plus_onchain_module";
  else if (hasLocalArtifact || hasOnChainModule) artifactMode = "artifact_only";
  else artifactMode = "view_only";

  const ruleCapabilities = { viewOnly, hasAbi, hasBytecodeOrSource, artifactMode };

  // Execute rules
  const ruleContext = { artifact: artifactView, scanLevel, capabilities: ruleCapabilities };
  const ruleFindings = executeRules(ruleContext);

  // View errors -> findings
  const viewErrorFindings = createViewErrorFindings(viewData.viewErrors);

  // Optional SupraScan tx preview (agent-mode)
  let txPreview: SupraScanTransactionSummary[] | undefined = undefined;
  const txFindings: Finding[] = [];

  const agentMode = process.env.SSA_AGENT_MODE === "1" || process.env.AGENT_MODE === "1";
  if (agentMode) {
    try {
      const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet") as "mainnet" | "testnet";
      const txData = await fetchAllTransactionsFromSupraScan({
        blockchainEnvironment: suprascanEnv,
        address: moduleId.address,
        page: 1,
        rowsPerPage: 10,
      });

      if (txData?.transactions?.length) {
        txPreview = txData.transactions;

        const zeroValueTxs = txData.transactions.filter(
          (tx) => tx.transferAmount === "0" && tx.gasSUPRA && Number(tx.gasSUPRA) > 0
        );

        if (zeroValueTxs.length >= 5) {
          txFindings.push({
            id: "TX-SPAM-001",
            title: "Zero-Value Transaction Spam / Contract Calls",
            severity: "medium",
            confidence: 0.6,
            description: `Found ${zeroValueTxs.length} zero-value transactions with gas costs in recent history.`,
            recommendation: "Review transaction patterns; consider rate limiting / gas optimization.",
            evidence: { kind: "heuristic", matched: [`zero_value_txs=${zeroValueTxs.length}`], locations: [] },
            references: [],
          });
        }
      }
    } catch {
      // ignore
    }
  }

  // Capabilities (staking-aware)
  const capabilities = {
    moduleProfile,
    moduleProfileReason: profileGuess.reason,

    poolStats: moduleProfile === "staking" ? "pool_stats" in viewData.viewResults : false,
    totalStaked: moduleProfile === "staking" ? "total_staked" in viewData.viewResults : false,
    queue:
      moduleProfile === "staking"
        ? (viewData.queueMode === "v24" || viewData.queueMode === "legacy") &&
          (V24_QUEUE_VIEWS.some((v) => v in viewData.viewResults) ||
            LEGACY_QUEUE_VIEWS.some((v) => v in viewData.viewResults))
        : false,

    userViews:
      targetUser !== undefined && USER_REQUIRED_VIEWS.every((v) => v in viewData.viewResults),
  };

  // Only add queue-missing finding if staking
  if (moduleProfile === "staking") {
    if (!capabilities.queue && viewData.queueMode === "none") {
      viewErrorFindings.push({
        id: "SVSSA-MOVE-VIEW-QUEUE-MISSING",
        title: "Missing Queue Capability",
        severity: "high",
        confidence: 1.0,
        description:
          "Neither v24 nor legacy queue views are available. Queue inspection capabilities are missing.",
        recommendation: "Verify module deployment and ensure queue view functions exist.",
        evidence: { kind: "heuristic", matched: ["queue_missing"], locations: [] },
        references: [],
      });
    }
  }

  // Combine findings
  const allFindings = [...ruleFindings, ...viewErrorFindings, ...txFindings];

  // Downgrade CRITICAL in view-only mode
  const findings = allFindings.map((f) => {
    if (f.severity === "critical" && ruleCapabilities.viewOnly) {
      return {
        ...f,
        severity: "high" as const,
        confidence: Math.min(0.6, f.confidence),
        description: `${f.description} (Downgraded: view-only scan cannot verify access control without ABI/bytecode)`,
      };
    }
    return f;
  });

  // Scoring
  const severityCounts = calculateSeverityCounts(findings);
  let riskScore = calculateRiskScore(findings);

  // View penalties (profile-aware)
  let viewPenalty = 0;
  if (moduleProfile === "staking") {
    if (hasRequiredViewFailures) viewPenalty += 10;
    else if (viewData.viewErrors.length > 0) viewPenalty += Math.min(5, viewData.viewErrors.length);

    if (!capabilities.queue) viewPenalty += 5;
  } else {
    const hardErrors = viewData.viewErrors.filter((e) => !e.type || e.type === "error");
    if (hardErrors.length > 0) viewPenalty += Math.min(5, hardErrors.length);
  }

  viewPenalty = Math.min(10, viewPenalty);
  riskScore = Math.min(100, riskScore + viewPenalty);

  // Verdict
  let verdict: Verdict;
  let verdictReason: string | undefined;

  if (moduleProfile === "staking") {
    if (!capabilities.poolStats || !capabilities.totalStaked) {
      verdict = "fail";
      verdictReason = "Missing required staking view capabilities (poolStats or totalStaked)";
    } else if (!capabilities.queue) {
      verdict = "inconclusive";
      verdictReason = "Missing staking queue capability; cannot fully verify module state";
    } else if (hasRequiredViewFailures) {
      verdict = "inconclusive";
      verdictReason = "Required staking views failed; scan incomplete";
    } else {
      verdict = determineVerdict(findings, riskScore);
    }
  } else {
    if (ruleCapabilities.viewOnly && Object.keys(viewData.viewResults).length === 0) {
      verdict = "inconclusive";
      verdictReason =
        "Generic module: no ABI/bytecode and no views collected. Provide artifact/ABI/bytecode for stronger verification.";
    } else {
      verdict = determineVerdict(findings, riskScore);
      if (verdict === "fail") {
        verdictReason = "Generic module: evidence-backed high-severity findings detected";
      }
    }
  }

  // Build artifact object
  const artifact = buildArtifactHybrid(
    moduleId,
    viewData.viewResults,
    viewData.fetch_method,
    loadedArtifact || undefined
  );

  // Badge eligibility
  const badgeEligibility = calculateBadgeEligibility(
    scanLevel,
    artifact.artifact_hash,
    severityCounts,
    timestamp,
    hasBytecodeOrSource
  );

  const duration = Date.now() - startTime;

  const result: ScanResult = {
    request_id: requestId,
    target: {
      chain: "supra",
      module_address: moduleId.address,
      module_name: moduleId.module_name,
      module_id: `${moduleId.address}::${moduleId.module_name}`,
    },
    scan_level: scanLevel,
    timestamp_iso: timestamp,
    engine: {
      name: "ssa-scanner",
      version: getEngineVersion(),
      ruleset_version: "move-ruleset-0.1.0",
    },
    artifact,
    summary: {
      risk_score: riskScore,
      verdict,
      severity_counts: severityCounts,
      badge_eligibility: badgeEligibility,
      capabilities,
    },
    findings,
    meta: {
      scan_options: options,
      rpc_url: rpcUrl,
      duration_ms: duration,
      previous_artifact_hash: options.previous_artifact_hash,

      // debug
      view_results: viewData.viewResults,
      view_errors: viewData.viewErrors,
      skipped_user_views: viewData.skippedUserViews,
      target_user: targetUser || undefined,
      queue_mode: viewData.queueMode,
      rule_capabilities: ruleCapabilities,
      verdict_reason: verdictReason,
      tx_preview: txPreview,

      // module profiling
      module_profile: moduleProfile,
      module_profile_reason: profileGuess.reason,
      allowed_views_effective: allowedViews,
    },
  };

  return result;
}



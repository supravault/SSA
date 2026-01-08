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
import { buildArtifactFromViews, buildArtifactHybrid } from "./artifact.js";
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
import { loadArtifact, loadArtifactsFromEnv } from "./artifactLoader.js";
import type { LoadedArtifact } from "./artifactLoader.js";
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
  allowed_views?: string[]; // Allowlisted view functions to call
  target_user?: string; // User address for user-specific views
  previous_artifact_hash?: string;
  artifact_path?: string; // Path to local artifact file
  artifact_dir?: string; // Directory containing artifacts
}

/**
 * Run a security scan on a Supra Move module
 * Uses view-based inspection instead of bytecode fetching
 */
export async function runScan(
  moduleId: ModuleId,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const startTime = Date.now();
  const requestId = randomUUID();
  const timestamp = getIsoTimestamp();
  const scanLevel = options.scan_level || "quick";
  const rpcUrl = options.rpc_url || process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
  const proxyBase = options.proxy_base || process.env.PROD_API;

  // Get target user from options or environment
  const targetUser = options.target_user || process.env.TARGET_USER?.toLowerCase().trim();

  // Load local artifacts if provided
  const artifactPath = options.artifact_path || process.env.ARTIFACT_PATH;
  const artifactDir = options.artifact_dir || process.env.ARTIFACT_DIR;
  let loadedArtifact = loadArtifact(artifactPath, artifactDir, moduleId.module_name);

  // PART A: HYBRID MODE - Fetch on-chain bytecode/ABI (v3-first with v2 fallback)
  // This makes "View + On-chain Bytecode/ABI" the default scan mode for third-party Move modules
  // View-only mode remains the default-safe path if bytecode/ABI fetch fails
  if (!loadedArtifact?.bytecodeBuffer || !loadedArtifact?.abi) {
    const rpcOptions: RpcClientOptions = {
      rpcUrl,
      timeout: 10000,
      retries: 2,
      retryDelay: 500,
    };

    try {
      // Try v3-first with v2 fallback (canonical approach)
      const rpcResult = await fetchAccountModuleV3(
        moduleId.address,
        moduleId.module_name,
        rpcOptions
      );
      
      // Initialize artifact if needed
      if (!loadedArtifact) {
        loadedArtifact = {
          artifactOrigin: {
            kind: "supra_rpc_v3",
            path: `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`,
          },
        };
      }
      
      // Extract bytecode
      if (!loadedArtifact.bytecodeBuffer && rpcResult.module?.bytecode) {
        let bytecodeHex = rpcResult.module.bytecode;
        if (bytecodeHex.startsWith("0x")) {
          bytecodeHex = bytecodeHex.slice(2);
        }
        // Try to decode as hex, fallback to base64
        try {
          loadedArtifact.bytecodeBuffer = Buffer.from(bytecodeHex, "hex");
          loadedArtifact.bytecodeHex = bytecodeHex;
        } catch {
          // Try base64
          try {
            loadedArtifact.bytecodeBuffer = Buffer.from(bytecodeHex, "base64");
            loadedArtifact.bytecodeHex = loadedArtifact.bytecodeBuffer.toString("hex");
          } catch {
            console.debug(`Failed to decode bytecode from RPC v3/v2 (neither hex nor base64)`);
          }
        }
        if (loadedArtifact.bytecodeBuffer) {
          loadedArtifact.artifactOrigin.kind = "supra_rpc_v3";
          loadedArtifact.artifactOrigin.path = `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`;
          loadedArtifact.onChainBytecodeFetched = true;
        }
      }
      
      // Extract ABI
      if (!loadedArtifact.abi && rpcResult.module?.abi) {
        loadedArtifact.abi = rpcResult.module.abi;
        if (!loadedArtifact.bytecodeBuffer) {
          // Only update origin if we don't already have bytecode
          loadedArtifact.artifactOrigin.kind = "supra_rpc_v3";
          loadedArtifact.artifactOrigin.path = `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`;
        }
      }
    } catch (error) {
      // Silently fail - hybrid mode gracefully degrades to view-only
      const debug = process.env.SSA_DEBUG_VIEW === "1" || process.env.DEBUG_VIEW === "1";
      if (debug) {
        console.debug(`[Hybrid] RPC v3/v2 module fetch failed: ${error instanceof Error ? error.message : String(error)}`);
        console.debug(`[Hybrid] Falling back to view-only mode (safe default)`);
      }
    }
  }

  // Fetch module data via view functions (may skip if artifact_only mode, but for now always fetch)
  const viewData = await fetchModuleViewData({
    rpcUrl,
    moduleId,
    proxyBase,
    allowedViews: options.allowed_views,
    userAddress: targetUser,
  });
  
  // Check if any required views failed (only true errors, not skipped/unsupported)
  const requiredViewErrors = viewData.viewErrors.filter((e) =>
    REQUIRED_VIEWS.includes(e.viewName) && (!e.type || e.type === "error")
  );
  const hasRequiredViewFailures = requiredViewErrors.length > 0;

  // Build artifact view for rules (merge local artifacts with view results)
  const artifactView = buildArtifactViewHybrid(
    moduleId,
    viewData.viewResults,
    loadedArtifact || undefined
  );

  // Compute capabilities based on what's actually available
  const hasAbi = artifactView.abi !== null && artifactView.abi !== undefined;
  const hasBytecodeOrSource = artifactView.bytecode !== null || artifactView.strings.length > 0 || (loadedArtifact?.sourceText !== undefined);
  const viewOnly = !hasAbi && !hasBytecodeOrSource;

  // Determine artifact mode
  const hasViewResults = Object.keys(viewData.viewResults).length > 0;
  const hasLocalArtifact = !!loadedArtifact && (loadedArtifact.artifactOrigin.kind === "supra_ide_export" || loadedArtifact.artifactOrigin.kind === "manual");
  const hasOnChainModule = loadedArtifact?.onChainBytecodeFetched || (loadedArtifact?.bytecodeBuffer && (loadedArtifact.artifactOrigin.kind === "supra_rpc_v1" || loadedArtifact.artifactOrigin.kind === "supra_rpc_v3"));
  let artifactMode: ArtifactMode;
  if (hasViewResults && hasLocalArtifact) {
    artifactMode = "hybrid_local";
  } else if (hasViewResults && hasOnChainModule) {
    artifactMode = "view_plus_onchain_module";
  } else if (hasLocalArtifact || hasOnChainModule) {
    artifactMode = "artifact_only";
  } else {
    artifactMode = "view_only";
  }

  const ruleCapabilities = {
    viewOnly,
    hasAbi,
    hasBytecodeOrSource,
    artifactMode,
  };

  // Execute rules with capabilities
  const ruleContext = {
    artifact: artifactView,
    scanLevel,
    capabilities: ruleCapabilities,
  };
  const ruleFindings = executeRules(ruleContext);

  // Add findings for view errors
  const viewErrorFindings = createViewErrorFindings(viewData.viewErrors);
  
  // Optional: Fetch transaction preview from SupraScan (agent-mode)
  // Fetch last page of transactions for the module address
  let txPreview: SupraScanTransactionSummary[] | undefined = undefined;
  let txFindings: Finding[] = [];
  
  // Check if agent-mode is enabled (optional collection step)
  const agentMode = process.env.SSA_AGENT_MODE === "1" || process.env.AGENT_MODE === "1";
  if (agentMode) {
    try {
      const suprascanEnv = (process.env.SUPRASCAN_ENV || "mainnet") as "mainnet" | "testnet";
      // Fetch last page of transactions for the module address
      const txData = await fetchAllTransactionsFromSupraScan({
        blockchainEnvironment: suprascanEnv,
        address: moduleId.address,
        page: 1, // Start with page 1, could fetch last page if needed
        rowsPerPage: 10,
      });
      
      if (txData && txData.transactions.length > 0) {
        txPreview = txData.transactions;
        
        // Heuristic: Zero-value tx spam detection
        const zeroValueTxs = txData.transactions.filter(
          (tx: SupraScanTransactionSummary) => tx.transferAmount === "0" && tx.gasSUPRA && Number(tx.gasSUPRA) > 0
        );
        
        if (zeroValueTxs.length >= 5) {
          txFindings.push({
            id: "TX-SPAM-001",
            title: "Zero-Value Transaction Spam / Contract Calls",
            severity: "medium",
            confidence: 0.6,
            description: `Found ${zeroValueTxs.length} zero-value transactions with gas costs in recent transaction history. This may indicate spam or excessive contract calls.`,
            recommendation: "Review transaction patterns and consider implementing rate limiting or gas cost optimization.",
            evidence: {
              kind: "heuristic",
              matched: [`zero_value_txs=${zeroValueTxs.length}`, "gas_costs_present"],
              locations: [],
            },
            references: [],
          });
        }
        
        // Heuristic: Special contract receiver detection
        const hasSpecialContractReceiver = txData.transactions.some((tx: SupraScanTransactionSummary) =>
          tx.receivers?.some((r: { isSpecialAddress?: boolean; isContractAddress?: boolean }) => r.isSpecialAddress && r.isContractAddress)
        );
        
        if (hasSpecialContractReceiver) {
          txFindings.push({
            id: "TX-SPECIAL-001",
            title: "Special Contract Receiver Observed",
            severity: "info",
            confidence: 0.7,
            description: "Recent transactions include receivers marked as both special addresses and contract addresses. This may indicate interactions with system contracts or privileged addresses.",
            recommendation: "Review transaction recipients to ensure they are expected addresses.",
            evidence: {
              kind: "heuristic",
              matched: ["special_address", "contract_address", "receiver"],
              locations: [],
            },
            references: [],
          });
        }
      }
    } catch (error) {
      // Silently fail - transaction fetch is optional
      const debug = process.env.SSA_DEBUG_VIEW === "1";
      if (debug) {
        console.debug(`[Scanner] Failed to fetch transaction preview: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  }
  
  // Calculate capabilities
  const capabilities = {
    poolStats: "pool_stats" in viewData.viewResults,
    totalStaked: "total_staked" in viewData.viewResults,
    queue: (viewData.queueMode === "v24" || viewData.queueMode === "legacy") &&
           (V24_QUEUE_VIEWS.some((v) => v in viewData.viewResults) ||
            LEGACY_QUEUE_VIEWS.some((v) => v in viewData.viewResults)),
    userViews: targetUser !== undefined &&
               USER_REQUIRED_VIEWS.every((v) => v in viewData.viewResults),
  };

  // Add finding for missing queue capability
  if (!capabilities.queue && viewData.queueMode === "none") {
    viewErrorFindings.push({
      id: "SVSSA-MOVE-VIEW-QUEUE-MISSING",
      title: "Missing Queue Capability",
      severity: "high",
      confidence: 1.0,
      description: "Neither v24 nor legacy queue views are available. Queue inspection capabilities are missing.",
      recommendation: "Verify module deployment and ensure queue view functions are available.",
      evidence: {
        kind: "heuristic",
        matched: ["queue", "capability"],
        locations: [],
      },
      references: [],
    });
  }

  // Combine all findings (rule findings, view error findings, transaction findings)
  const allFindings = [...ruleFindings, ...viewErrorFindings, ...txFindings];
  
  // Downgrade CRITICAL findings in view-only mode (they should not exist, but safety check)
  const downgradedFindings = allFindings.map((finding) => {
    if (finding.severity === "critical" && ruleCapabilities.viewOnly) {
      return {
        ...finding,
        severity: "high" as const,
        confidence: Math.min(0.6, finding.confidence),
        description: `${finding.description} (Downgraded from CRITICAL: view-only scan cannot verify access control without ABI/bytecode)`,
      };
    }
    return finding;
  });

  const findings = [...downgradedFindings, ...viewErrorFindings];

  // Calculate scores and verdict
  const severityCounts = calculateSeverityCounts(findings);
  let riskScore = calculateRiskScore(findings);
  
  // Label risk score in view-only mode
  if (ruleCapabilities.viewOnly && riskScore > 0) {
    // Risk score is heuristic-based in view-only mode
    // Note: This is informational, not a code change
  }
  
  // Apply penalties for missing views (capped at 10 points total for optional/missing views)
  let viewPenalty = 0;
  if (hasRequiredViewFailures) {
    viewPenalty += 10; // Reduced from 25 to 10 (capped total)
  } else if (viewData.viewErrors.length > 0) {
    viewPenalty += Math.min(5, viewData.viewErrors.length * 1); // Small penalty per error, max 5
  }
  
  // Apply penalty for missing queue capability (capped)
  if (!capabilities.queue) {
    viewPenalty += 5; // Reduced from 20 to 5 (part of view penalty cap)
  }
  
  // Cap total view penalties at 10 points
  viewPenalty = Math.min(10, viewPenalty);
  riskScore = Math.min(100, riskScore + viewPenalty);

  // Determine verdict based on capabilities and findings
  let verdict: Verdict;
  let verdictReason: string | undefined;
  
  if (!capabilities.poolStats || !capabilities.totalStaked) {
    verdict = "fail"; // Missing required views
    verdictReason = "Missing required view capabilities (poolStats or totalStaked)";
  } else if (!capabilities.queue) {
    verdict = "inconclusive"; // Missing queue capability
    verdictReason = "Missing queue capability; cannot fully verify module state";
  } else if (hasRequiredViewFailures) {
    verdict = "inconclusive"; // Other required views missing
    verdictReason = "Required view functions failed; scan incomplete";
  } else {
    // In view-only mode, cannot FAIL based on heuristic findings alone
    if (ruleCapabilities.viewOnly) {
      // Check if we have evidence-backed findings (ABI/bytecode)
      const evidenceBackedFindings = findings.filter(
        (f) =>
          (f.severity === "high" || f.severity === "critical") &&
          f.confidence >= 0.7 &&
          f.evidence.kind !== "heuristic"
      );
      
      if (evidenceBackedFindings.length === 0) {
        // Only heuristic findings in view-only mode -> INCONCLUSIVE
        verdict = "inconclusive";
        verdictReason = "View-only scan; cannot verify access control without ABI/bytecode. Heuristic findings are not authoritative.";
      } else {
        // Has evidence-backed findings even in view-only (shouldn't happen, but handle it)
        verdict = determineVerdict(findings, riskScore);
        if (verdict === "fail") {
          verdictReason = "Evidence-backed findings detected (unexpected in view-only mode)";
        }
      }
    } else {
      // Not view-only: use standard verdict logic
      const evidenceBackedFindings = findings.filter(
        (f) =>
          (f.severity === "high" || f.severity === "critical") &&
          f.confidence >= 0.7 &&
          f.evidence.kind !== "heuristic"
      );
      
      const allHeuristicOrView = findings.every(
        (f) =>
          f.evidence.kind === "heuristic" ||
          f.confidence < 0.5 ||
          f.id.startsWith("SVSSA-MOVE-VIEW-")
      );
      
      if (allHeuristicOrView && findings.length > 0) {
        verdict = "inconclusive";
        verdictReason = "Only heuristic findings; evidence-backed verification required";
      } else {
        verdict = determineVerdict(findings, riskScore);
        if (verdict === "inconclusive" && !verdictReason) {
          verdictReason = "Insufficient evidence for definitive verdict";
        }
      }
    }
  }

  // Build artifact object (merge local artifacts with view data)
  const artifact = buildArtifactHybrid(
    moduleId,
    viewData.viewResults,
    viewData.fetch_method,
    loadedArtifact || undefined
  );

  // Calculate badge eligibility (requires bytecode/source for Security Verified)
  const badgeEligibility = calculateBadgeEligibility(
    scanLevel,
    artifact.artifact_hash,
    severityCounts,
    timestamp,
    hasBytecodeOrSource // Pass bytecode/source capability
  );

  const duration = Date.now() - startTime;

  // Build scan result
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
      view_results: viewData.viewResults, // Store view results for inspection
      view_errors: viewData.viewErrors, // Store view errors
      skipped_user_views: viewData.skippedUserViews, // Views skipped due to missing user
      target_user: targetUser || undefined, // User address used (if any)
      queue_mode: viewData.queueMode, // Detected queue capability mode
      rule_capabilities: ruleCapabilities, // Capabilities available to rules
      verdict_reason: verdictReason, // Explanation for verdict
      tx_preview: txPreview, // Transaction preview (agent-mode only)
    },
  };

  return result;
}


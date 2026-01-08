// src/scripts/ssa-agent.ts
// One-shot Level 3 Agent Mode: Full verification with simplified output and exit codes

import { verifySurface } from "../agent/verify.js";
import { writeJsonAtomic, ensureDir } from "../agent/storage.js";
import { dirname } from "path";
import type { VerificationReport } from "../agent/verify.js";
import type { RiskSynthesis } from "../agent/types.js";

/**
 * Agent-grade output format (simplified top-level with all evidence preserved)
 */
interface AgentOutput {
  identity: "confirmed" | "conflict" | "unavailable";
  behavior: "matched" | "unavailable" | "mismatch" | "no_activity";
  sources: string[];
  risk_level: string;
  signals: string[];
  rationale: string[];
  evidence: {
    verification: VerificationReport;
  };
}

/**
 * Derive identity status from verification report
 */
function deriveIdentityStatus(report: VerificationReport): "confirmed" | "conflict" | "unavailable" {
  if (report.status === "INVALID_ARGS") {
    return "unavailable";
  }
  
  // Check for conflicts in key claims
  const hasConflicts = report.discrepancies.length > 0 || report.status === "CONFLICT";
  
  if (hasConflicts) {
    return "conflict";
  }
  
  // Check if we have confirmed claims
  const hasConfirmed = report.claims.some(c => c.status === "CONFIRMED");
  
  if (hasConfirmed || report.overallEvidenceTier !== "view_only") {
    return "confirmed";
  }
  
  return "unavailable";
}

/**
 * Derive behavior status from behavior evidence
 */
function deriveBehaviorStatus(
  report: VerificationReport
): "matched" | "unavailable" | "mismatch" | "no_activity" {
  if (!report.behavior) {
    return "unavailable";
  }
  
  if (report.behavior.status === "no_activity") {
    return "no_activity";
  }
  
  if (report.behavior.status === "unavailable" || report.behavior.status === "error") {
    return "unavailable";
  }
  
  if (report.behavior.status === "sampled") {
    // Check for phantom entries (mismatch)
    if (report.behavior.phantom_entries.length > 0) {
      return "mismatch";
    }
    
    // If we have invoked entries and no phantoms, it's matched
    if (report.behavior.invoked_entries.length > 0) {
      return "matched";
    }
    
    // No entries invoked but sampled successfully
    return "no_activity";
  }
  
  return "unavailable";
}

/**
 * Collect sources array from report
 */
function collectSources(report: VerificationReport): string[] {
  const sources: string[] = [];
  
  // RPC sources
  if (report.sources_succeeded.includes("rpc_v3")) {
    sources.push("rpc");
  }
  if (report.sources_succeeded.includes("rpc_v3_2")) {
    sources.push("rpc2");
  }
  
  // SupraScan indexer (if supported for FA)
  if (report.target.kind === "fa" && report.indexer_parity?.status === "supported") {
    sources.push("suprascan");
  }
  
  // Transaction behavior (if sampled)
  if (report.behavior?.status === "sampled" || report.behavior?.status === "no_activity") {
    sources.push("tx");
  }
  
  return sources;
}

/**
 * Get exit code based on risk level
 */
function getExitCode(riskLevel: string): number {
  if (riskLevel === "SAFE_STATIC" || riskLevel === "SAFE_DYNAMIC") {
    return 0;
  }
  if (riskLevel === "OPAQUE_BUT_ACTIVE" || riskLevel === "ELEVATED_RISK") {
    return 2;
  }
  if (riskLevel === "DANGEROUS") {
    return 3;
  }
  // Default to elevated risk for unknown levels
  return 2;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  // Check for "verify" subcommand (for future extensibility)
  const subcommand = args[0];
  if (subcommand !== "verify" && subcommand !== undefined) {
    console.error(`Error: Unknown subcommand "${subcommand}". Use "verify".`);
    process.exit(1);
  }
  
  // Skip subcommand if present
  const argOffset = subcommand === "verify" ? 1 : 0;
  const remainingArgs = args.slice(argOffset);
  
  // Check for help flag early (before validation)
  if (remainingArgs.includes("--help") || remainingArgs.includes("-h")) {
    console.log(`Usage: node dist/src/scripts/ssa-agent.js verify [options]

One-Shot Level 3 Agent Mode: Full verification with simplified output and exit codes

Required:
  --fa <address>           FA token address to verify
  --coin <coinType>        Coin type to verify (e.g., "0xADDR::MODULE::COIN")
  --out <path>             Output JSON file path (required for agent mode)

Options:
  --rpc <url>              RPC URL (default: SUPRA_RPC_URL env or https://rpc-mainnet.supra.com)
  --rpc2 <url>             Secondary RPC URL for multi-RPC corroboration
  --mode <fast|strict|agent> Verification mode (default: agent)
  --with-suprascan         Enable SupraScan indexer parity checks (FA only, enabled by default in agent mode)
  --timeoutMs <ms>         Request timeout in milliseconds (default: 8000)
  --retries <n>            Number of retries for failed requests (default: 1)
  --tx-limit <n>           Maximum transactions to sample for behavior evidence (default: 20)
  --no-tx                  Skip transaction behavior sampling
  --help, -h               Show this help message

Exit Codes:
  0  SAFE_STATIC or SAFE_DYNAMIC
  2  OPAQUE_BUT_ACTIVE or ELEVATED_RISK
  3  DANGEROUS
  1  Runtime/tool errors

Examples:
  node dist/src/scripts/ssa-agent.js verify --fa 0x123... --out report.json
  node dist/src/scripts/ssa-agent.js verify --coin "0xADDR::MODULE::COIN" --out report.json --with-suprascan
`);
    process.exit(0);
  }
  
  let faAddress: string | null = null;
  let coinType: string | null = null;
  let rpcUrl: string | null = null;
  let rpc2Url: string | null = null;
  let outputPath: string | null = null;
  let mode: "fast" | "strict" | "agent" = "agent";
  let withSupraScan = false;
  let timeoutMs = 8000;
  let retries = 1;
  let txLimit = 20;
  let skipTx = false;
  
  // Parse arguments
  for (let i = 0; i < remainingArgs.length; i++) {
    if (remainingArgs[i] === "--fa" && i + 1 < remainingArgs.length) {
      faAddress = remainingArgs[i + 1];
      i++;
    } else if (remainingArgs[i] === "--coin" && i + 1 < remainingArgs.length) {
      coinType = remainingArgs[i + 1];
      i++;
    } else if (remainingArgs[i] === "--rpc" && i + 1 < remainingArgs.length) {
      rpcUrl = remainingArgs[i + 1];
      i++;
    } else if (remainingArgs[i] === "--rpc2" && i + 1 < remainingArgs.length) {
      rpc2Url = remainingArgs[i + 1];
      i++;
    } else if (remainingArgs[i] === "--out" && i + 1 < remainingArgs.length) {
      outputPath = remainingArgs[i + 1];
      i++;
    } else if (remainingArgs[i] === "--mode" && i + 1 < remainingArgs.length) {
      const modeArg = remainingArgs[i + 1];
      if (modeArg === "fast" || modeArg === "strict" || modeArg === "agent") {
        mode = modeArg as "fast" | "strict" | "agent";
      }
      i++;
    } else if (remainingArgs[i] === "--with-suprascan") {
      withSupraScan = true;
    } else if (remainingArgs[i] === "--timeoutMs" && i + 1 < remainingArgs.length) {
      const timeout = parseInt(remainingArgs[i + 1], 10);
      if (!isNaN(timeout) && timeout > 0) {
        timeoutMs = timeout;
      }
      i++;
    } else if (remainingArgs[i] === "--retries" && i + 1 < remainingArgs.length) {
      const retriesArg = parseInt(remainingArgs[i + 1], 10);
      if (!isNaN(retriesArg) && retriesArg >= 0) {
        retries = retriesArg;
      }
      i++;
    } else if (remainingArgs[i] === "--tx-limit" && i + 1 < remainingArgs.length) {
      const limit = parseInt(remainingArgs[i + 1], 10);
      if (!isNaN(limit) && limit > 0) {
        txLimit = limit;
      }
      i++;
    } else if (remainingArgs[i] === "--no-tx") {
      skipTx = true;
    }
  }
  
  // Validate target
  if (!faAddress && !coinType) {
    console.error("Error: Either --fa <address> or --coin <coinType> is required");
    process.exit(1);
  }
  
  if (faAddress && coinType) {
    console.error("Error: Cannot specify both --fa and --coin");
    process.exit(1);
  }
  
  // Validate output path (required for agent mode)
  if (!outputPath) {
    console.error("Error: --out <path> is required for agent mode");
    process.exit(1);
  }
  
  // Get RPC URL
  if (!rpcUrl) {
    rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
  }
  
  // In agent mode, enable suprascan and tx by default unless explicitly disabled
  if (mode === "agent") {
    if (!remainingArgs.includes("--with-suprascan") && !remainingArgs.includes("--no-tx")) {
      withSupraScan = true;
      // tx is already enabled by default (skipTx = false)
    }
  }
  
  const target = faAddress
    ? { kind: "fa" as const, id: faAddress }
    : { kind: "coin" as const, id: coinType! };
  
  try {
    // Run verification
    const report = await verifySurface(target, {
      rpcUrl,
      rpc2Url: rpc2Url || undefined,
      mode: mode === "agent" ? "strict" : mode, // Use strict mode for agent
      withSupraScan,
      timeoutMs,
      retries,
      txLimit,
      skipTx,
    });
    
    // Check for INVALID_ARGS status and exit with error
    if (report.status === "INVALID_ARGS") {
      console.error("Error: Invalid RPC URL(s) detected");
      const errorOutput: AgentOutput = {
        identity: "unavailable",
        behavior: "unavailable",
        sources: [],
        risk_level: "ELEVATED_RISK",
        signals: [],
        rationale: ["Invalid RPC URL(s) provided"],
        evidence: {
          verification: report,
        },
      };
      console.log(JSON.stringify(errorOutput, null, 2));
      ensureDir(dirname(outputPath));
      writeJsonAtomic(outputPath, errorOutput);
      process.exit(1);
    }
    
    // Derive simplified status fields
    const identity = deriveIdentityStatus(report);
    const behavior = deriveBehaviorStatus(report);
    const sources = collectSources(report);
    
    // Extract risk synthesis (should always be present after verification)
    const risk = report.risk || {
      signals: [],
      risk_level: "ELEVATED_RISK",
      rationale: ["Risk synthesis unavailable"],
    };
    
    // Build agent output
    const agentOutput: AgentOutput = {
      identity,
      behavior,
      sources,
      risk_level: risk.risk_level,
      signals: risk.signals,
      rationale: risk.rationale,
      evidence: {
        verification: report,
      },
    };
    
    // Write output to file
    ensureDir(dirname(outputPath));
    writeJsonAtomic(outputPath, agentOutput);
    
    // Also print to stdout (can be suppressed if needed)
    console.log(JSON.stringify(agentOutput, null, 2));
    
    // Exit with appropriate code based on risk level
    const exitCode = getExitCode(risk.risk_level);
    process.exit(exitCode);
  } catch (error) {
    console.error("Error during agent verification:", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


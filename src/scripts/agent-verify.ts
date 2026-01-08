// src/scripts/agent-verify.ts
// CLI script for Level 3 agent-mode verification

import { verifySurface } from "../agent/verify.js";
import { writeJsonAtomic, ensureDir } from "../agent/storage.js";
import { dirname } from "path";
import { readFileSync } from "fs";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  let faAddress: string | null = null;
  let coinType: string | null = null;
  let rpcUrl: string | null = null;
  let rpc2Url: string | null = null;
  let outputPath: string | null = null;
  let mode: "fast" | "strict" | "agent" = "fast";
  let withSupraScan = false;
  let timeoutMs = 8000;
  let retries = 1;
  let txLimit = 20;
  let skipTx = false;
  let preferV2 = false;
  let suprascanDump = true; // Default true when --with-suprascan is used
  const probeAddresses: string[] = [];
  let probeAddressFile: string | null = null;
  let quiet = false;
  let reportMode: "full" | "compact" = "full";
  let variantLabel: string | null = null;
  
  // Check for help flag early (before validation)
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: node dist/src/scripts/agent-verify.js [options]

Level 3 Agent-Mode Verification

Required:
  --fa <address>           FA token address to verify
  --coin <coinType>        Coin type to verify (e.g., "0xADDR::MODULE::COIN")

Options:
  --rpc <url>              RPC URL (default: SUPRA_RPC_URL env or https://rpc-mainnet.supra.com)
  --rpc2 <url>             Secondary RPC URL for multi-RPC corroboration
  --out <path>             Output file path (optional, also prints to stdout)
  --mode <fast|strict|agent> Verification mode (default: fast)
                             fast: Quick verification without behavior sampling
                             strict: Strict verification mode
                             agent: Full agent mode with behavior sampling and tx analysis
  --with-suprascan         Enable SupraScan indexer parity checks (FA/Coin)
  --timeoutMs <ms>         Request timeout in milliseconds (default: 8000)
  --retries <n>            Number of retries for failed requests (default: 1)
  --tx-limit <n>           Maximum transactions to sample for behavior evidence (default: 20)
  --no-tx                  Skip transaction behavior sampling
  --probe-address <addr>   Additional address to probe for transactions (repeatable)
  --probe-address-file <path>  File with addresses to probe (one per line)
  --prefer-v2              Prefer v2 endpoint for account transaction sampling
  --quiet, --out-only      Suppress JSON output to stdout (still writes to --out file)
  --report <full|compact>  Report format: full (default) or compact one-line summary
  --label <string>         Variant label for compact report (optional)
  --help, -h               Show this help message

Examples:
  node dist/src/scripts/agent-verify.js --fa 0x123... --with-suprascan
  node dist/src/scripts/agent-verify.js --coin "0xADDR::MODULE::COIN" --rpc https://... --rpc2 https://...
`);
    process.exit(0);
  }
  
  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--fa" && i + 1 < args.length) {
      faAddress = args[i + 1];
      i++;
    } else if (args[i] === "--coin" && i + 1 < args.length) {
      coinType = args[i + 1];
      i++;
    } else if (args[i] === "--rpc" && i + 1 < args.length) {
      rpcUrl = args[i + 1];
      i++;
    } else if (args[i] === "--rpc2" && i + 1 < args.length) {
      rpc2Url = args[i + 1];
      i++;
    } else if (args[i] === "--out" && i + 1 < args.length) {
      outputPath = args[i + 1];
      i++;
    } else if (args[i] === "--mode" && i + 1 < args.length) {
      const modeArg = args[i + 1].toLowerCase();
      if (modeArg === "fast" || modeArg === "strict" || modeArg === "agent") {
        mode = modeArg;
      } else {
        console.error(`Error: Invalid mode "${args[i + 1]}". Must be: fast, strict, or agent`);
        process.exit(1);
      }
      i++;
    } else if (args[i] === "--with-suprascan") {
      withSupraScan = true;
      suprascanDump = true; // Default to true when --with-suprascan is used
    } else if (args[i] === "--suprascan-dump" && i + 1 < args.length) {
      const dumpArg = args[i + 1].toLowerCase();
      suprascanDump = dumpArg === "true" || dumpArg === "1" || dumpArg === "yes";
      i++;
    } else if (args[i] === "--timeoutMs" && i + 1 < args.length) {
      const timeout = parseInt(args[i + 1], 10);
      if (!isNaN(timeout) && timeout > 0) {
        timeoutMs = timeout;
      }
      i++;
    } else if (args[i] === "--retries" && i + 1 < args.length) {
      const retriesArg = parseInt(args[i + 1], 10);
      if (!isNaN(retriesArg) && retriesArg >= 0) {
        retries = retriesArg;
      }
      i++;
    } else if (args[i] === "--tx-limit" && i + 1 < args.length) {
      const limit = parseInt(args[i + 1], 10);
      if (!isNaN(limit) && limit > 0) {
        txLimit = limit;
      }
      i++;
    } else if (args[i] === "--no-tx") {
      skipTx = true;
    } else if (args[i] === "--probe-address" && i + 1 < args.length) {
      probeAddresses.push(args[i + 1]);
      i++;
    } else if (args[i] === "--probe-address-file" && i + 1 < args.length) {
      probeAddressFile = args[i + 1];
      i++;
    } else if (args[i] === "--prefer-v2") {
      preferV2 = true;
      // Also accept --prefer-v2 true (but default is true if flag is present)
      if (i + 1 < args.length && args[i + 1] === "true") {
        i++;
      }
    } else if (args[i] === "--quiet" || args[i] === "--out-only") {
      quiet = true;
    } else if (args[i] === "--report" && i + 1 < args.length) {
      const reportArg = args[i + 1].toLowerCase();
      if (reportArg === "full" || reportArg === "compact") {
        reportMode = reportArg;
      } else {
        console.error(`Error: Invalid report mode "${args[i + 1]}". Must be: full or compact`);
        process.exit(1);
      }
      i++;
    } else if (args[i] === "--label" && i + 1 < args.length) {
      variantLabel = args[i + 1];
      i++;
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
  
  // Get RPC URL
  if (!rpcUrl) {
    rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
  }
  
  // Read probe addresses from file if provided
  if (probeAddressFile) {
    try {
      const fileContent = readFileSync(probeAddressFile, "utf-8");
      const lines = fileContent.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          // Skip empty lines and comments
          probeAddresses.push(trimmed);
        }
      }
    } catch (error) {
      console.error(`Error reading probe address file ${probeAddressFile}:`, error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  }
  
  // Normalize and deduplicate probe addresses
  const normalizedProbeAddresses = new Set<string>();
  for (const addr of probeAddresses) {
    const normalized = addr.trim().toLowerCase();
    if (normalized.startsWith("0x")) {
      normalizedProbeAddresses.add(normalized);
    }
  }
  
  const target = faAddress
    ? { kind: "fa" as const, id: faAddress }
    : { kind: "coin" as const, id: coinType! };
  
  // Build behaviorProbeAddresses for FA targets
  const behaviorProbeAddresses: string[] | undefined = target.kind === "fa" 
    ? Array.from(normalizedProbeAddresses) 
    : undefined;
  
  // In agent mode, behavior sampling should run by default (unless explicitly skipped with --no-tx)
  // The skipTx flag is already set correctly from CLI args
  
  try {
    // Run verification
    const report = await verifySurface(target, {
      rpcUrl,
      rpc2Url: rpc2Url || undefined,
      mode: mode === "agent" ? "strict" : mode, // Map agent mode to strict for verifySurface
      withSupraScan,
      timeoutMs,
      retries,
      txLimit,
      skipTx,
      behaviorProbeAddresses,
      preferV2,
      suprascanDump,
    });
    
    // Override mode in output to preserve "agent" if specified
    (report as { mode: string }).mode = mode;
    
    // Check for INVALID_ARGS status and exit with error
    if (report.status === "INVALID_ARGS") {
      console.error("Error: Invalid RPC URL(s) detected");
      console.log(JSON.stringify(report, null, 2));
      process.exit(1);
    }
    
    // Sort claims and discrepancies for deterministic output
    report.claims.sort((a, b) => {
      const typeOrder: Record<string, number> = {
        OWNER: 1,
        SUPPLY: 2,
        HOOKS: 3,
        CAPS: 4,
        INDEXER_PARITY: 4.5,
        HOOK_MODULE_HASHES: 4.6,
        MODULE_HASHES: 4.7,
        MODULES: 5,
        ABI_PRESENCE: 6,
      };
      return (typeOrder[a.claimType] || 999) - (typeOrder[b.claimType] || 999);
    });
    
    report.discrepancies.sort((a, b) => {
      const typeOrder: Record<string, number> = {
        OWNER: 1,
        SUPPLY: 2,
        HOOKS: 3,
        CAPS: 4,
        MODULES: 5,
        ABI_PRESENCE: 6,
      };
      return (typeOrder[a.claimType] || 999) - (typeOrder[b.claimType] || 999);
    });
    
    // Sort confirmations within each claim
    for (const claim of report.claims) {
      claim.confirmations.sort((a, b) => {
        const sourceOrder: Record<string, number> = {
          rpc_v3: 1,
          rpc_v1: 2,
          rpc_v3_2: 3,
          suprascan: 4,
        };
        return (sourceOrder[a.source] || 999) - (sourceOrder[b.source] || 999);
      });
    }
    
    // Write to file if specified (always write regardless of quiet mode)
    if (outputPath) {
      ensureDir(dirname(outputPath));
      writeJsonAtomic(outputPath, report);
    }
    
    // Print output based on mode and flags
    if (reportMode === "compact") {
      // Compact one-line summary
      const label = variantLabel || target.id.substring(0, 16);
      const kind = target.kind;
      const tier = report.overallEvidenceTier;
      const risk = report.risk?.risk_level || "unknown";
      
      // Get suprascan status (FA or Coin)
      // For coin, check if suprascan was attempted via provider_results
      let suprascanStatus = "n/a";
      if (target.kind === "fa" && report.suprascan_fa) {
        suprascanStatus = report.suprascan_fa.status || "unknown";
      } else if (target.kind === "coin") {
        // For coin, check provider_results for suprascan status
        const suprascanResult = report.provider_results.find(p => p.source === "suprascan");
        if (suprascanResult) {
          suprascanStatus = suprascanResult.ok ? "supported" : "error";
        } else if (withSupraScan) {
          suprascanStatus = "not_requested";
        }
      }
      
      // Get supply parity from indexer_parity if available
      let supplyParity = "n/a";
      if (report.indexer_parity?.details?.supplyParity) {
        supplyParity = report.indexer_parity.details.supplyParity;
      }
      
      // Get behavior source
      let behaviorSource = "none";
      if (report.behavior) {
        behaviorSource = report.behavior.source || "none";
      }
      
      console.log(`${label} | ${kind} | tier=${tier} risk=${risk} suprascan=${suprascanStatus} supplyParity=${supplyParity} behavior=${behaviorSource}`);
    } else if (!quiet) {
      // Full JSON output (default)
      console.log(JSON.stringify(report, null, 2));
    } else {
      // Quiet mode: only print minimal status
      console.error(`Verification complete. Output written to ${outputPath || "stdout"}`);
    }
  } catch (error) {
    console.error("Error during verification:", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


// src/scripts/snapshot-coin.ts
// CLI script to generate COIN snapshot JSON baseline

import { scanCoinToken } from "../core/coinScanner.js";
import { buildCoinSnapshot } from "../agent/snapshot.js";
import { writeJsonAtomic, ensureDir } from "../agent/storage.js";
import { dirname } from "path";

async function main(): Promise<void> {
  const coinType = process.env.TARGET_COIN;
  if (!coinType) {
    console.error("Error: TARGET_COIN environment variable is required");
    process.exit(1);
  }

  const rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";

  // Parse --out argument (simple parsing, no commander needed for this script)
  let outputPath = "state/coin_snapshot.json";
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--out" && i + 1 < args.length) {
      outputPath = args[i + 1];
      break;
    }
  }

  try {
    // Scan coin token to get ScanResult
    const scanResult = await scanCoinToken(coinType, { rpc_url: rpcUrl });

    // Build snapshot
    const snapshot = await buildCoinSnapshot({
      scanResult,
      rpcUrl,
    });

    // Ensure output directory exists
    ensureDir(dirname(outputPath));

    // Write snapshot to disk
    writeJsonAtomic(outputPath, snapshot);

    // Print summary
    console.log(`Wrote COIN snapshot: ${outputPath}`);
  } catch (error) {
    console.error("Error generating COIN snapshot:", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


// src/scripts/snapshot-fa.ts
// CLI script to generate FA snapshot JSON baseline

import { scanFAToken } from "../core/faScanner.js";
import { buildFASnapshot } from "../agent/snapshot.js";
import { writeJsonAtomic, ensureDir } from "../agent/storage.js";
import { dirname } from "path";

async function main(): Promise<void> {
  const faAddress = process.env.TARGET_FA;
  if (!faAddress) {
    console.error("Error: TARGET_FA environment variable is required");
    process.exit(1);
  }

  const rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";

  // Parse --out argument (simple parsing, no commander needed for this script)
  let outputPath = "state/fa_snapshot.json";
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--out" && i + 1 < args.length) {
      outputPath = args[i + 1];
      break;
    }
  }

  try {
    // Scan FA token to get ScanResult
    const scanResult = await scanFAToken(faAddress, { rpc_url: rpcUrl });

    // Build snapshot
    const snapshot = await buildFASnapshot({
      scanResult,
      rpcUrl,
    });

    // Ensure output directory exists
    ensureDir(dirname(outputPath));

    // Write snapshot to disk
    writeJsonAtomic(outputPath, snapshot);

    // Print summary
    console.log(`Wrote FA snapshot: ${outputPath}`);
  } catch (error) {
    console.error("Error generating FA snapshot:", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


// src/scripts/agent-suprascan-coin.ts
// CLI script for SupraScan Evidence Mode - Coin tokens

import { getCoinDetails, addressDetail, parseResources } from "../adapters/suprascan.js";
import { writeFileSync } from "fs";
import { dirname } from "path";
import { mkdirSync } from "fs";

interface SupraScanEvidenceReport {
  timestamp_iso: string;
  coinType: string;
  creatorAddress?: string;
  blockchainEnvironment: "mainnet" | "testnet";
  suprascan: {
    summary?: {
      name?: string;
      symbol?: string;
      verified?: boolean;
      assetAddress?: string;
      decimals?: number;
      price?: string | number;
      totalSupply?: string | number;
      creatorAddress?: string;
      holders?: number;
    };
    resources?: Array<{
      type: string;
      data?: any;
    }>;
    creatorResources?: Array<{
      type: string;
      data?: any;
    }>;
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  let coinType: string | null = null;
  let creatorAddress: string | null = null;
  let outputPath: string | null = null;
  let blockchainEnvironment: "mainnet" | "testnet" = "mainnet";

  // Check for help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: node dist/src/scripts/agent-suprascan-coin.js [options]

SupraScan Evidence Mode - Coin Tokens

Required:
  --coin <coinType>        Coin type (e.g., "0x6253...::NANA::NANA")

Options:
  --creator <address>      Creator/publisher address (optional, for fetching creator resources)
  --out <path>             Output file path (required)
  --env <mainnet|testnet>  Blockchain environment (default: mainnet)
  --help, -h               Show this help message

Examples:
  node dist/src/scripts/agent-suprascan-coin.js --coin "0x6253...::NANA::NANA" --creator 0x123... --out coin-evidence.json
`);
    process.exit(0);
  }

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--coin" && i + 1 < args.length) {
      coinType = args[i + 1];
      i++;
    } else if (args[i] === "--creator" && i + 1 < args.length) {
      creatorAddress = args[i + 1];
      i++;
    } else if (args[i] === "--out" && i + 1 < args.length) {
      outputPath = args[i + 1];
      i++;
    } else if (args[i] === "--env" && i + 1 < args.length) {
      const env = args[i + 1].toLowerCase();
      if (env === "mainnet" || env === "testnet") {
        blockchainEnvironment = env;
      } else {
        console.error(`Invalid environment: ${env}. Must be "mainnet" or "testnet"`);
        process.exit(1);
      }
      i++;
    }
  }

  // Validate required arguments
  if (!coinType) {
    console.error("Error: --coin <coinType> is required");
    process.exit(1);
  }

  if (!outputPath) {
    console.error("Error: --out <path> is required");
    process.exit(1);
  }

  // Generate timestamp
  const timestamp = new Date().toISOString();

  // Fetch coin details
  console.log(`Fetching coin details for ${coinType}...`);
  const coinDetails = await getCoinDetails(coinType, blockchainEnvironment);

  if (!coinDetails) {
    console.error("Failed to fetch coin details from SupraScan");
    process.exit(1);
  }

  // Use creatorAddress from coinDetails if not provided
  const finalCreatorAddress = creatorAddress || coinDetails.creatorAddress || undefined;

  // Fetch creator address resources if available
  let creatorResources: Array<{ type: string; data?: any }> | undefined = undefined;
  if (finalCreatorAddress) {
    console.log(`Fetching address resources for creator ${finalCreatorAddress}...`);
    const addressDetailResult = await addressDetail(finalCreatorAddress, blockchainEnvironment);
    if (addressDetailResult && !addressDetailResult.isError && addressDetailResult.addressDetailSupra?.resources) {
      creatorResources = parseResources(addressDetailResult.addressDetailSupra.resources);
    }
  }

  // Build report
  const report: SupraScanEvidenceReport = {
    timestamp_iso: timestamp,
    coinType,
    creatorAddress: finalCreatorAddress,
    blockchainEnvironment,
    suprascan: {
      summary: coinDetails,
      creatorResources,
    },
  };

  // Write output file
  try {
    // Ensure output directory exists
    const outputDir = dirname(outputPath);
    if (outputDir !== ".") {
      mkdirSync(outputDir, { recursive: true });
    }

    writeFileSync(outputPath, JSON.stringify(report, null, 2), "utf-8");
    console.log(`Evidence report written to ${outputPath}`);
  } catch (error) {
    console.error(`Failed to write output file: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

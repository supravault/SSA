// src/scripts/agent-suprascan-fa.ts
// CLI script for SupraScan Evidence Mode - Fungible Assets

import { getFaDetails, addressDetail, parseResources } from "../adapters/suprascan.js";
import { writeFileSync } from "fs";
import { dirname } from "path";
import { mkdirSync } from "fs";

interface SupraScanEvidenceReport {
  timestamp_iso: string;
  faAddress: string;
  creatorAddress?: string;
  blockchainEnvironment: "mainnet" | "testnet";
  suprascan: {
    summary?: {
      faName?: string;
      faSymbol?: string;
      verified?: boolean;
      faAddress?: string;
      iconUrl?: string;
      decimals?: number;
      price?: string | number;
      totalSupply?: string | number;
      creatorAddress?: string;
      holders?: number;
      isDualNature?: boolean;
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

  let faAddress: string | null = null;
  let outputPath: string | null = null;
  let blockchainEnvironment: "mainnet" | "testnet" = "mainnet";

  // Check for help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: node dist/src/scripts/agent-suprascan-fa.js [options]

SupraScan Evidence Mode - Fungible Assets

Required:
  --fa <faAddress>         FA token address (e.g., "0x123...")

Options:
  --out <path>             Output file path (required)
  --env <mainnet|testnet>  Blockchain environment (default: mainnet)
  --help, -h               Show this help message

Examples:
  node dist/src/scripts/agent-suprascan-fa.js --fa 0x123... --out fa-evidence.json
`);
    process.exit(0);
  }

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--fa" && i + 1 < args.length) {
      faAddress = args[i + 1];
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
  if (!faAddress) {
    console.error("Error: --fa <faAddress> is required");
    process.exit(1);
  }

  if (!outputPath) {
    console.error("Error: --out <path> is required");
    process.exit(1);
  }

  // Generate timestamp
  const timestamp = new Date().toISOString();

  // Fetch FA details
  console.log(`Fetching FA details for ${faAddress}...`);
  const faDetails = await getFaDetails(faAddress, blockchainEnvironment);

  if (!faDetails) {
    console.error("Failed to fetch FA details from SupraScan");
    process.exit(1);
  }

  // Fetch FA address resources
  console.log(`Fetching address resources for FA ${faAddress}...`);
  const faAddressDetail = await addressDetail(faAddress, blockchainEnvironment);
  let faResources: Array<{ type: string; data?: any }> | undefined = undefined;
  if (faAddressDetail && !faAddressDetail.isError && faAddressDetail.addressDetailSupra?.resources) {
    faResources = parseResources(faAddressDetail.addressDetailSupra.resources);
  }

  // Fetch creator address resources if different from FA address
  const creatorAddress = faDetails.creatorAddress;
  let creatorResources: Array<{ type: string; data?: any }> | undefined = undefined;
  if (creatorAddress && creatorAddress.toLowerCase() !== faAddress.toLowerCase()) {
    console.log(`Fetching address resources for creator ${creatorAddress}...`);
    const creatorAddressDetail = await addressDetail(creatorAddress, blockchainEnvironment);
    if (creatorAddressDetail && !creatorAddressDetail.isError && creatorAddressDetail.addressDetailSupra?.resources) {
      creatorResources = parseResources(creatorAddressDetail.addressDetailSupra.resources);
    }
  }

  // Build report
  const report: SupraScanEvidenceReport = {
    timestamp_iso: timestamp,
    faAddress,
    creatorAddress,
    blockchainEnvironment,
    suprascan: {
      summary: faDetails,
      resources: faResources,
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

// src/scripts/suprascan-ingest.ts
// CLI script for SupraScan evidence ingestion + Level-1 surface extraction

import { parseResources, extractFlags, computeRisk, type SupraScanCoinDetails, type SupraScanFaDetails } from "../adapters/suprascan.js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";

interface SupraScanBundle {
  kind: "fa" | "coin";
  ts_utc: string;
  fa?: SupraScanFaDetails;
  coin?: SupraScanCoinDetails;
  faResourcesJson?: string;
  coinResourcesJson?: string;
}

interface EnrichedSupraScanEvidence {
  kind: "fa" | "coin";
  ts_utc: string;
  details: SupraScanCoinDetails | SupraScanFaDetails | null;
  flags: ReturnType<typeof extractFlags>;
  risk: ReturnType<typeof computeRisk>;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  let inputPath: string | null = null;
  let outputPath: string | null = null;

  // Check for help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: node dist/src/scripts/suprascan-ingest.js [options]

SupraScan Evidence Ingestion + Level-1 Surface Extraction

Required:
  --in <path>              Input bundle JSON file path
  --out <path>             Output enriched JSON file path

Options:
  --help, -h               Show this help message

Examples:
  node dist/src/scripts/suprascan-ingest.js --in tmp/suprascan_fa_DXLYN.json --out state/suprascan_fa_DXLYN.enriched.json
`);
    process.exit(0);
  }

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--in" && i + 1 < args.length) {
      inputPath = args[i + 1];
      i++;
    } else if (args[i] === "--out" && i + 1 < args.length) {
      outputPath = args[i + 1];
      i++;
    }
  }

  // Validate required arguments
  if (!inputPath) {
    console.error("Error: --in <path> is required");
    process.exit(1);
  }

  if (!outputPath) {
    console.error("Error: --out <path> is required");
    process.exit(1);
  }

  // Read input bundle
  let bundle: SupraScanBundle;
  try {
    const inputContent = readFileSync(inputPath, "utf-8");
    bundle = JSON.parse(inputContent);
  } catch (error) {
    console.error(`Failed to read input file: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }

  // Validate bundle structure
  if (!bundle.kind || (bundle.kind !== "fa" && bundle.kind !== "coin")) {
    console.error("Error: Bundle must have 'kind' field set to 'fa' or 'coin'");
    process.exit(1);
  }

  if (!bundle.ts_utc) {
    console.error("Error: Bundle must have 'ts_utc' field");
    process.exit(1);
  }

  // Extract details based on kind
  const details = bundle.kind === "fa" ? bundle.fa : bundle.coin;
  const resourcesJson = bundle.kind === "fa" ? bundle.faResourcesJson : bundle.coinResourcesJson;

  // Parse resources
  const resources = parseResources(resourcesJson);

  // Extract flags
  const flags = extractFlags(resources, bundle.kind);

  // Compute risk
  const risk = computeRisk(flags, details || null, bundle.kind);

  // Build enriched evidence
  const enriched: EnrichedSupraScanEvidence = {
    kind: bundle.kind,
    ts_utc: bundle.ts_utc,
    details: details || null,
    flags,
    risk,
  };

  // Write output file
  try {
    // Ensure output directory exists
    const outputDir = dirname(outputPath);
    if (outputDir !== ".") {
      mkdirSync(outputDir, { recursive: true });
    }

    writeFileSync(outputPath, JSON.stringify(enriched, null, 2), "utf-8");
    console.log(`Enriched evidence written to ${outputPath}`);
    console.log(`  Kind: ${enriched.kind}`);
    console.log(`  Risk Score: ${enriched.risk.score}/100`);
    console.log(`  Risk Labels: ${enriched.risk.labels.join(", ")}`);
    console.log(`  Flags: ${Object.keys(enriched.flags).filter((k) => enriched.flags[k as keyof typeof enriched.flags] === true).join(", ")}`);
  } catch (error) {
    console.error(`Failed to write output file: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

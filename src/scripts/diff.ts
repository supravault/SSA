// src/scripts/diff.ts
// CLI script to compute and print diff between two snapshots

import { readJsonFile } from "../agent/storage.js";
import { diffSnapshots } from "../agent/diff.js";
import { applySeverityRules } from "../agent/rules.js";
import type { CoinSnapshot, FASnapshot } from "../agent/types.js";
import { existsSync } from "fs";

async function main(): Promise<void> {
  // Parse arguments
  const args = process.argv.slice(2);
  let prevPath: string | null = null;
  let currPath: string | null = null;
  let pretty = true; // default to pretty

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--prev" && i + 1 < args.length) {
      prevPath = args[i + 1];
      i++; // skip next arg
    } else if (args[i] === "--curr" && i + 1 < args.length) {
      currPath = args[i + 1];
      i++; // skip next arg
    } else if (args[i] === "--pretty") {
      pretty = true;
    } else if (args[i] === "--no-pretty" || args[i] === "--compact") {
      pretty = false;
    }
  }

  // Validate required arguments
  if (!prevPath) {
    console.error("Error: --prev <path> is required");
    process.exit(1);
  }
  if (!currPath) {
    console.error("Error: --curr <path> is required");
    process.exit(1);
  }

  // Check if files exist
  if (!existsSync(prevPath)) {
    console.error(`Error: Previous snapshot file not found: ${prevPath}`);
    process.exit(1);
  }
  if (!existsSync(currPath)) {
    console.error(`Error: Current snapshot file not found: ${currPath}`);
    process.exit(1);
  }

  try {
    // Read previous snapshot
    const prevSnapshot = readJsonFile<CoinSnapshot | FASnapshot>(prevPath);
    if (prevSnapshot === null) {
      console.error(`Error: Failed to parse previous snapshot: ${prevPath}`);
      process.exit(1);
    }

    // Read current snapshot
    const currSnapshot = readJsonFile<CoinSnapshot | FASnapshot>(currPath);
    if (currSnapshot === null) {
      console.error(`Error: Failed to parse current snapshot: ${currPath}`);
      process.exit(1);
    }

    // Compute diff
    const diffResult = diffSnapshots(prevSnapshot, currSnapshot);

    // Apply severity rules
    const resultWithSeverity = applySeverityRules(diffResult, prevSnapshot, currSnapshot);

    // Print JSON to stdout
    if (pretty) {
      console.log(JSON.stringify(resultWithSeverity, null, 2));
    } else {
      console.log(JSON.stringify(resultWithSeverity));
    }
  } catch (error) {
    console.error("Error computing diff:", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


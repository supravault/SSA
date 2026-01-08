#!/usr/bin/env node

/**
 * Standalone Node CLI script for testing FA resource analysis
 * Fetches FA resources using SupraScan GraphQL AddressDetail query
 * and runs analyzeFaResources() on the returned resources
 */

import { suprascanGraphql } from "../adapters/suprascanGraphql.js";
import { analyzeFaResources } from "../analyzers/fa/analyzeFaResources.js";

const ADDRESS_DETAIL_QUERY = `
query AddressDetail(
  $address: String,
  $page: Int,
  $offset: Int,
  $userWalletAddress: String,
  $blockchainEnvironment: BlockchainEnvironment,
  $isAddressName: Boolean
) {
  addressDetail(
    address: $address,
    page: $page,
    offset: $offset,
    userWalletAddress: $userWalletAddress,
    blockchainEnvironment: $blockchainEnvironment,
    isAddressName: $isAddressName
  ) {
    isError
    errorType
    addressDetailSupra {
      resources
    }
  }
}
`;

async function main(): Promise<void> {
  try {
    // Read FA address from environment
    const TARGET_FA = process.env.TARGET_FA;
    if (!TARGET_FA) {
      throw new Error("TARGET_FA environment variable is required");
    }

    // Call SupraScan GraphQL API
    const data = await suprascanGraphql<{
      addressDetail: {
        isError: boolean;
        errorType: string | null;
        addressDetailSupra: { resources: string | null } | null;
      };
    }>(
      ADDRESS_DETAIL_QUERY,
      {
        address: TARGET_FA,
        blockchainEnvironment: "mainnet",
        isAddressName: false,
      },
      {
        env: "mainnet",
      }
    );

    // Check for errors
    if (data.addressDetail?.isError) {
      const errorType = data.addressDetail.errorType || "Unknown error";
      console.error(`Error: SupraScan returned an error: ${errorType}`);
      process.exit(1);
    }

    // Check if resources are missing
    const resourcesStr = data.addressDetail?.addressDetailSupra?.resources;
    if (!resourcesStr || typeof resourcesStr !== "string" || resourcesStr.trim().length === 0) {
      console.error("Error: Resources are missing or empty in the response");
      process.exit(1);
    }

    // Analyze FA resources
    const analysis = analyzeFaResources(resourcesStr);

    // Print parsedCount
    console.log(`parsedCount: ${analysis.parsedCount}`);

    // Print caps
    console.log("caps:", JSON.stringify(analysis.caps, null, 2));

    // Print findings (severity + id + title)
    console.log("findings:");
    if (analysis.findings.length === 0) {
      console.log("  (none)");
    } else {
      // Map severity to lowercase for output format
      const severityMap: Record<string, string> = {
        INFO: "info",
        LOW: "low",
        MEDIUM: "medium",
        HIGH: "high",
      };

      analysis.findings.forEach((finding) => {
        const severity = severityMap[finding.severity] || finding.severity.toLowerCase();
        console.log(`  [${severity}] ${finding.id}: ${finding.title}`);
      });
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${errorMessage}`);
    if (error instanceof Error && error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run main function
main().catch((error) => {
  const errorMessage = error instanceof Error ? error.message : String(error);
  console.error(`Unhandled error: ${errorMessage}`);
  process.exit(1);
});


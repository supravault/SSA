// src/scripts/test-agent-verify-local.ts
// Deterministic local test for agent verification (no network)

import { corroborateClaims, type MiniSurface } from "../agent/verify.js";

async function main(): Promise<void> {
  // Test fixture 1: v3 and v1 match (CONFIRMED)
  const miniV3_match: MiniSurface = {
    owner: "0x1234567890abcdef",
    supplyCurrentBase: "1000000",
    decimals: 6,
    capabilities: {
      hasMintRef: true,
      hasWithdrawHook: true,
    },
  };
  
  const miniV1_match: MiniSurface = {
    owner: "0x1234567890abcdef",
    supplyCurrentBase: "1000000",
    decimals: 6,
    capabilities: {
      hasMintRef: true,
      hasWithdrawHook: true,
    },
  };
  
  const result_match = corroborateClaims(miniV3_match, miniV1_match, null, null, "fa");
  console.log("=== Test 1: Matching sources (CONFIRMED) ===");
  console.log(JSON.stringify(result_match, null, 2));
  
  // Assertions
  const ownerClaim = result_match.claims.find(c => c.claimType === "OWNER");
  if (ownerClaim?.status !== "CONFIRMED" || ownerClaim?.confidence !== "HIGH") {
    throw new Error("Test 1 failed: Owner should be CONFIRMED HIGH");
  }
  
  const supplyClaim = result_match.claims.find(c => c.claimType === "SUPPLY");
  if (supplyClaim?.status !== "CONFIRMED" || supplyClaim?.confidence !== "HIGH") {
    throw new Error("Test 1 failed: Supply should be CONFIRMED HIGH");
  }
  
  if (result_match.status !== "OK") {
    throw new Error("Test 1 failed: Status should be OK");
  }
  
  console.log("✅ Test 1 passed\n");
  
  // Test fixture 2: v3 and v1 mismatch (CONFLICT)
  const miniV3_mismatch: MiniSurface = {
    owner: "0x1234567890abcdef",
    supplyCurrentBase: "1000000",
  };
  
  const miniV1_mismatch: MiniSurface = {
    owner: "0xfedcba0987654321",
    supplyCurrentBase: "2000000",
  };
  
  const result_mismatch = corroborateClaims(miniV3_mismatch, miniV1_mismatch, null, null, "fa");
  console.log("=== Test 2: Mismatching sources (CONFLICT) ===");
  console.log(JSON.stringify(result_mismatch, null, 2));
  
  // Assertions
  const ownerClaim2 = result_mismatch.claims.find(c => c.claimType === "OWNER");
  if (ownerClaim2?.status !== "CONFLICT" || ownerClaim2?.confidence !== "HIGH") {
    throw new Error("Test 2 failed: Owner should be CONFLICT HIGH");
  }
  
  if (result_mismatch.discrepancies.length === 0) {
    throw new Error("Test 2 failed: Should have discrepancies");
  }
  
  if (result_mismatch.status !== "CONFLICT") {
    throw new Error("Test 2 failed: Status should be CONFLICT");
  }
  
  console.log("✅ Test 2 passed\n");
  
  // Test fixture 3: Only v3 available (PARTIAL)
  const miniV3_partial: MiniSurface = {
    owner: "0x1234567890abcdef",
    supplyCurrentBase: "1000000",
  };
  
  const result_partial = corroborateClaims(miniV3_partial, null, null, null, "fa");
  console.log("=== Test 3: Only v3 available (PARTIAL) ===");
  console.log(JSON.stringify(result_partial, null, 2));
  
  // Assertions
  const ownerClaim3 = result_partial.claims.find(c => c.claimType === "OWNER");
  if (ownerClaim3?.status !== "PARTIAL" || ownerClaim3?.confidence !== "MEDIUM") {
    throw new Error("Test 3 failed: Owner should be PARTIAL MEDIUM");
  }
  
  console.log("✅ Test 3 passed\n");
  
  // Test fixture 4: Missing data (UNAVAILABLE)
  const result_unavailable = corroborateClaims(null, null, null, null, "fa");
  console.log("=== Test 4: No sources (UNAVAILABLE) ===");
  console.log(JSON.stringify(result_unavailable, null, 2));
  
  // Assertions
  const ownerClaim4 = result_unavailable.claims.find(c => c.claimType === "OWNER");
  if (ownerClaim4?.status !== "UNAVAILABLE" || ownerClaim4?.confidence !== "LOW") {
    throw new Error("Test 4 failed: Owner should be UNAVAILABLE LOW");
  }
  
  console.log("✅ Test 4 passed\n");
  
  console.log("All local tests passed! ✅");
}

main().catch((error) => {
  console.error("Test failed:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


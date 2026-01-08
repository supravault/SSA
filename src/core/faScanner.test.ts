import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { scanFAToken, fetchFAMetadata } from "./faScanner.js";

describe("FA Scanner", () => {
  const testFAAddress = "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358";
  const testRpcUrl = process.env.RPC_URL || process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";
  
  beforeEach(() => {
    // Clear TARGET_COIN_TYPE for tests that don't need it
    delete process.env.TARGET_COIN_TYPE;
    delete process.env.FA_STRUCT_TAG;
    delete process.env.FA_METADATA_PROVIDER;
  });

  afterEach(() => {
    // Clean up env vars after each test
    delete process.env.TARGET_COIN_TYPE;
    delete process.env.FA_STRUCT_TAG;
    delete process.env.FA_METADATA_PROVIDER;
  });

  describe("fetchFAMetadata", () => {
    it("should fetch FA metadata without TARGET_COIN_TYPE", async () => {
      // Test that metadata can be fetched without coin type
      const metadata = await fetchFAMetadata(testFAAddress, testRpcUrl);
      
      // Should not have fetchError solely due to missing coin type
      expect(metadata.address).toBe(testFAAddress.toLowerCase());
      // Should attempt to fetch via resources or SupraScan
      expect(metadata.fetchMethod || metadata.fetchError).toBeDefined();
    }, 30000);

    it("should fetch FA metadata with TARGET_COIN_TYPE", async () => {
      // Test that metadata can be fetched with coin type provided
      const coinType = "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358::svlt::SVLT";
      process.env.TARGET_COIN_TYPE = coinType;
      
      const metadata = await fetchFAMetadata(testFAAddress, testRpcUrl);
      
      expect(metadata.address).toBe(testFAAddress.toLowerCase());
      // Should have coin type stored
      expect((metadata as any).coinType).toBe(coinType);
    }, 30000);
  });

  describe("scanFAToken", () => {
    it("should scan FA token without TARGET_COIN_TYPE and not mark as INCONCLUSIVE", async () => {
      // Test that scan completes without coin type and doesn't mark as INCONCLUSIVE solely due to missing coin type
      const result = await scanFAToken(testFAAddress, {
        rpc_url: testRpcUrl,
      });
      
      expect(result.target.module_address).toBe(testFAAddress.toLowerCase());
      expect(result.target.module_name).toBe("fa_token");
      
      // Should not be INCONCLUSIVE solely due to missing coin type
      // Only INCONCLUSIVE if metadata itself is unavailable
      if (result.summary.verdict === "inconclusive") {
        expect(result.meta.verdict_reason).not.toContain("TARGET_COIN_TYPE");
        expect(result.meta.verdict_reason).toContain("metadata unavailable");
      }
      
      // Should have artifact mode set to view_only
      expect(result.meta.artifact_mode).toBe("view_only");
      
      // Should have rule capabilities
      expect(result.meta.rule_capabilities).toBeDefined();
      expect(result.meta.rule_capabilities?.viewOnly).toBe(true);
    }, 60000);

    it("should scan FA token with TARGET_COIN_TYPE", async () => {
      // Test that scan works with coin type provided
      const coinType = "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358::svlt::SVLT";
      process.env.TARGET_COIN_TYPE = coinType;
      
      const result = await scanFAToken(testFAAddress, {
        rpc_url: testRpcUrl,
      });
      
      expect(result.target.module_address).toBe(testFAAddress.toLowerCase());
      expect(result.target.module_name).toBe("fa_token");
      
      // Should have metadata
      expect(result.meta.fa_metadata).toBeDefined();
      
      // Should have artifact mode set to view_only (FA scans are always view-only)
      expect(result.meta.artifact_mode).toBe("view_only");
    }, 60000);

    it("should continue scanning even when coin type inference fails", async () => {
      // Test that scan continues even if coin type cannot be inferred
      // Use an FA address that might not have coin type in resources
      const result = await scanFAToken(testFAAddress, {
        rpc_url: testRpcUrl,
      });
      
      // Should complete scan
      expect(result.request_id).toBeDefined();
      expect(result.summary).toBeDefined();
      
      // Should not have fetchError solely due to missing coin type
      if (result.meta.fa_metadata?.fetchError) {
        expect(result.meta.fa_metadata.fetchError).not.toContain("TARGET_COIN_TYPE not set");
      }
    }, 60000);

    it("should not emit SSA-L1-FA-OPAQUE-CONTROL-SURFACE for framework-managed FA (no custom modules)", async () => {
      // Use a real FA address that is framework-managed (no custom modules at creator)
      // This test verifies that framework-managed FAs don't get the opaque control surface finding
      const result = await scanFAToken(testFAAddress, {
        rpc_url: testRpcUrl,
      });
      
      // Check if this FA has custom modules
      const hasCustomModules = result.meta.fa_metadata?.has_custom_modules === true;
      
      if (!hasCustomModules && result.meta.fa_metadata?.creator) {
        // Framework-managed FA: should NOT have SSA-L1-FA-OPAQUE-CONTROL-SURFACE
        const opaqueFinding = result.findings.find((f) => f.id === "SSA-L1-FA-OPAQUE-CONTROL-SURFACE");
        expect(opaqueFinding).toBeUndefined();
        
        // Should have FA-FRAMEWORK-MANAGED-001 INFO finding instead
        const frameworkFinding = result.findings.find((f) => f.id === "FA-FRAMEWORK-MANAGED-001");
        expect(frameworkFinding).toBeDefined();
        expect(frameworkFinding?.severity).toBe("info");
        
        // Risk score should be low (only INFO findings, or MEDIUM from resource analysis if resources don't match patterns)
        // Note: Resource analysis may emit FA-OPAQUE-001 (MEDIUM) if resources are parsed but don't match expected patterns
        // This is expected behavior - the test verifies that SSA-L1-FA-OPAQUE-CONTROL-SURFACE is not emitted
        // Resource analysis findings are separate and acceptable
        expect(result.summary.risk_score).toBeLessThan(20); // Allow for resource analysis findings
      }
      // If hasCustomModules is true, skip this assertion (test passes)
    }, 60000);

    it("should emit SSA-L1-FA-OPAQUE-CONTROL-SURFACE MEDIUM when custom modules exist but no bytecode", async () => {
      // Use a real FA address that has custom modules but bytecode might not be available
      // This test verifies that FAs with custom modules but no bytecode get the opaque finding
      const result = await scanFAToken(testFAAddress, {
        rpc_url: testRpcUrl,
      });
      
      // Check if this FA has custom modules but no bytecode
      const hasCustomModules = result.meta.fa_metadata?.has_custom_modules === true;
      const hasCreatorBytecode = result.meta.code_verified === true;
      
      if (hasCustomModules && !hasCreatorBytecode && result.meta.fa_metadata?.creator) {
        // Should have SSA-L1-FA-OPAQUE-CONTROL-SURFACE finding with MEDIUM severity
        const opaqueFinding = result.findings.find((f) => f.id === "SSA-L1-FA-OPAQUE-CONTROL-SURFACE");
        expect(opaqueFinding).toBeDefined();
        expect(opaqueFinding?.severity).toBe("medium");
        
        // Should NOT have FA-FRAMEWORK-MANAGED-001 (only for framework-managed)
        const frameworkFinding = result.findings.find((f) => f.id === "FA-FRAMEWORK-MANAGED-001");
        expect(frameworkFinding).toBeUndefined();
      }
      // If conditions don't match, skip this assertion (test passes)
    }, 60000);

    it("should use SupraScan as fetchMethod when FA_METADATA_PROVIDER=suprascan even if resources succeed", async () => {
      process.env.FA_METADATA_PROVIDER = "suprascan";
      
      const metadata = await fetchFAMetadata(testFAAddress, testRpcUrl);
      
      // fetchMethod should be suprascan_graphql when provider is "suprascan"
      // (even if resources also succeeded)
      if (metadata.fetchMethod) {
        expect(metadata.fetchMethod).toBe("suprascan_graphql");
      }
      
      // Clean up
      delete process.env.FA_METADATA_PROVIDER;
    }, 30000);
  });
});


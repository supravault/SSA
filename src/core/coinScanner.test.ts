/**
 * Unit tests for coin scanner module coverage
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { scanCoinToken } from "./coinScanner.js";
import { fetchAccountModulesV3 } from "../rpc/supraAccountsV3.js";
import { fetchCoinDetailsFromSupraScan } from "../rpc/supraScanGraphql.js";

// Mock RPC functions
vi.mock("../rpc/supraAccountsV3.js", () => ({
  fetchAccountModulesV3: vi.fn(),
  fetchAccountModuleV3: vi.fn(),
}));

vi.mock("../rpc/supraScanGraphql.js", () => ({
  fetchCoinDetailsFromSupraScan: vi.fn(),
}));

vi.mock("../rpc/viewRpc.js", () => ({
  viewFunctionRawRpc: vi.fn(),
}));

describe("Coin Scanner - Module Coverage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    // Default mock: SupraScan returns metadata
    vi.mocked(fetchCoinDetailsFromSupraScan).mockResolvedValue({
      name: "TestCoin",
      symbol: "TEST",
      decimals: 8,
      totalSupply: "1000000",
      creatorAddress: "0x123",
    });
  });

  it("should report all publisher modules when multiple modules exist", async () => {
    const coinType = "0x123::TEST::TEST";
    
    // Mock: Publisher has 3 modules
    vi.mocked(fetchAccountModulesV3).mockResolvedValue({
      modules: [
        {
          name: "TEST",
          bytecode: "0x1234",
          abi: {
            exposed_functions: [],
          },
        },
        {
          name: "ADMIN",
          bytecode: "0x5678",
          abi: {
            exposed_functions: [],
          },
        },
        {
          name: "TREASURY",
          bytecode: "0x9abc",
          abi: {
            exposed_functions: [],
          },
        },
      ],
    });

    const result = await scanCoinToken(coinType, {
      rpc_url: "https://rpc-mainnet.supra.com",
    });

    // Assertions
    expect(result.meta.coin_publisher_modules_count).toBe(3);
    expect(result.meta.coin_publisher_modules).toEqual(["TEST", "ADMIN", "TREASURY"]);
    expect(result.meta.coin_scanned_modules_count).toBe(3);
    
    // All modules scanned, should be code-verified
    expect(result.meta.code_verified).toBe(true);
    expect(result.summary.verdict).toBe("pass");
    expect(result.meta.verdict_tier).toBe("verified");
  });

  it("should report INCONCLUSIVE when only partial modules scanned", async () => {
    const coinType = "0x123::TEST::TEST";
    
    // Mock: Publisher has 3 modules, but only 2 have bytecode
    vi.mocked(fetchAccountModulesV3).mockResolvedValue({
      modules: [
        {
          name: "TEST",
          bytecode: "0x1234",
          abi: {
            exposed_functions: [],
          },
        },
        {
          name: "ADMIN",
          bytecode: "0x5678",
          abi: {
            exposed_functions: [],
          },
        },
        {
          name: "TREASURY",
          // No bytecode/ABI
        },
      ],
    });

    const result = await scanCoinToken(coinType, {
      rpc_url: "https://rpc-mainnet.supra.com",
    });

    // Assertions
    expect(result.meta.coin_publisher_modules_count).toBe(3);
    expect(result.meta.coin_scanned_modules_count).toBe(2);
    
    // Partial coverage - should be INCONCLUSIVE
    expect(result.meta.code_verified).toBe(false);
    expect(result.summary.verdict).toBe("inconclusive");
    expect(result.meta.verdict_tier).toBe("metadata");
    expect(result.meta.verdict_reason).toContain("Partial module coverage");
    expect(result.meta.verdict_reason).toContain("scanned_modules=2 / total_modules=3");
  });

  it("should scan all modules for dangerous patterns", async () => {
    const coinType = "0x123::TEST::TEST";
    
    // Mock: Publisher has 2 modules, one with dangerous function
    vi.mocked(fetchAccountModulesV3).mockResolvedValue({
      modules: [
        {
          name: "TEST",
          bytecode: "0x1234",
          abi: {
            exposed_functions: [
              {
                name: "mint",
                params: [],
              },
            ],
          },
        },
        {
          name: "ADMIN",
          bytecode: "0x5678",
          abi: {
            exposed_functions: [
              {
                name: "set_admin",
                params: [],
              },
            ],
          },
        },
      ],
    });

    const result = await scanCoinToken(coinType, {
      rpc_url: "https://rpc-mainnet.supra.com",
    });

    // Should find dangerous patterns in both modules
    const dangerousFindings = result.findings.filter((f) => f.id.startsWith("COIN-SEC"));
    expect(dangerousFindings.length).toBeGreaterThan(0);
    
    // Check that findings reference both modules
    const moduleNamesInFindings = dangerousFindings.flatMap((f) =>
      f.evidence.locations.map((loc: any) => loc.fn)
    );
    expect(moduleNamesInFindings.some((fn) => fn.includes("TEST"))).toBe(true);
    expect(moduleNamesInFindings.some((fn) => fn.includes("ADMIN"))).toBe(true);
  });

  describe("Level 1: Surface Area Verification", () => {
    it("should enumerate all modules without filtering", async () => {
      const coinType = "0x123::TEST::TEST";
      
      // Mock: Publisher has 5 modules (not just the target module)
      vi.mocked(fetchAccountModulesV3).mockResolvedValue({
        modules: [
          { name: "TEST", bytecode: "0x1234", abi: { exposed_functions: [] } },
          { name: "ADMIN", bytecode: "0x5678", abi: { exposed_functions: [] } },
          { name: "TREASURY", bytecode: "0x9abc", abi: { exposed_functions: [] } },
          { name: "UTILS", bytecode: "0xdef0", abi: { exposed_functions: [] } },
          { name: "MISC", bytecode: "0x1111", abi: { exposed_functions: [] } },
        ],
      });

      const result = await scanCoinToken(coinType, {
        rpc_url: "https://rpc-mainnet.supra.com",
      });

      // Assert Level 1 surface report
      expect(result.meta.surface_report).toBeDefined();
      expect(result.meta.surface_report!.kind).toBe("coin");
      expect(result.meta.surface_report!.modules_total).toBe(5);
      expect(result.meta.surface_report!.modules_list).toEqual([
        "TEST",
        "ADMIN",
        "TREASURY",
        "UTILS",
        "MISC",
      ]);
    });

    it("should enumerate entry functions correctly", async () => {
      const coinType = "0x123::TEST::TEST";
      
      vi.mocked(fetchAccountModulesV3).mockResolvedValue({
        modules: [
          {
            name: "TEST",
            bytecode: "0x1234",
            abi: {
              exposed_functions: [
                { name: "transfer", is_entry: true },
                { name: "mint", is_entry: true },
                { name: "burn", is_entry: false },
              ],
            },
          },
          {
            name: "ADMIN",
            bytecode: "0x5678",
            abi: {
              exposed_functions: [
                { name: "set_admin", is_entry: true },
              ],
            },
          },
        ],
      });

      const result = await scanCoinToken(coinType, {
        rpc_url: "https://rpc-mainnet.supra.com",
      });

      expect(result.meta.surface_report).toBeDefined();
      expect(result.meta.surface_report!.entry_functions_total).toBe(3);
      expect(result.meta.surface_report!.entry_functions_by_module).toEqual({
        TEST: ["transfer", "mint"],
        ADMIN: ["set_admin"],
      });
    });

    it("should detect opaque ABI for tradable tokens", async () => {
      const coinType = "0x123::TEST::TEST";
      
      // Mock: Tradable token (has price) but no entry functions
      vi.mocked(fetchCoinDetailsFromSupraScan).mockResolvedValue({
        name: "TestCoin",
        symbol: "TEST",
        decimals: 8,
        totalSupply: "1000000",
        price: "1.50", // Tradable signal
      });
      
      vi.mocked(fetchAccountModulesV3).mockResolvedValue({
        modules: [
          {
            name: "TEST",
            bytecode: "0x1234",
            abi: {
              exposed_functions: [], // Empty - opaque ABI
            },
          },
        ],
      });

      const result = await scanCoinToken(coinType, {
        rpc_url: "https://rpc-mainnet.supra.com",
      });

      expect(result.meta.surface_report).toBeDefined();
      expect(result.meta.surface_report!.opaque_abi?.flagged).toBe(true);
      expect(result.meta.surface_report!.opaque_abi?.signal_tradable).toBe("suprascan_price");
      
      // Should have finding for opaque ABI
      const opaqueFinding = result.findings.find((f) => f.id === "SSA-L1-OPAQUE-ABI");
      expect(opaqueFinding).toBeDefined();
      expect(opaqueFinding?.severity).toBe("medium");
    });

    it("should detect capability patterns", async () => {
      const coinType = "0x123::TEST::TEST";
      
      vi.mocked(fetchAccountModulesV3).mockResolvedValue({
        modules: [
          {
            name: "TEST",
            bytecode: "0x1234",
            abi: {
              structs: [
                { name: "MintCapability", fields: [] },
                { name: "AdminCap", fields: [] },
              ],
              exposed_functions: [
                {
                  name: "mint",
                  params: ["0x123::TEST::MintCapability"],
                  return: [],
                },
              ],
            },
          },
        ],
      });

      const result = await scanCoinToken(coinType, {
        rpc_url: "https://rpc-mainnet.supra.com",
      });

      expect(result.meta.surface_report).toBeDefined();
      expect(result.meta.surface_report!.capability_hits_total).toBeGreaterThan(0);
      expect(result.meta.surface_report!.capability_hits_by_module).toBeDefined();
      expect(result.meta.surface_report!.capability_hits_by_module!["TEST"]).toBeDefined();
      expect(result.meta.surface_report!.capability_hits_by_module!["TEST"].length).toBeGreaterThan(0);
    });

    it("should track modules with empty exposed_functions", async () => {
      const coinType = "0x123::TEST::TEST";
      
      vi.mocked(fetchAccountModulesV3).mockResolvedValue({
        modules: [
          {
            name: "TEST",
            bytecode: "0x1234",
            abi: {
              exposed_functions: [], // Empty array
            },
          },
          {
            name: "ADMIN",
            bytecode: "0x5678",
            abi: {
              exposed_functions: [{ name: "set_admin", is_entry: true }],
            },
          },
        ],
      });

      const result = await scanCoinToken(coinType, {
        rpc_url: "https://rpc-mainnet.supra.com",
      });

      expect(result.meta.surface_report).toBeDefined();
      expect(result.meta.surface_report!.exposed_functions_empty_modules).toContain("TEST");
      expect(result.meta.surface_report!.exposed_functions_empty_modules).not.toContain("ADMIN");
    });
  });
});


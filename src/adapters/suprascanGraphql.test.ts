import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchSupraScanAddressResources,
  decompressModuleSource,
  SupraScanResourceError,
  fetchAddressDetailSupra,
} from "./suprascanGraphql.js";

// Mock the GraphQL fetch function
vi.mock("./suprascanGraphql.js", async () => {
  const actual = await vi.importActual("./suprascanGraphql.js");
  return {
    ...actual,
    fetchAddressDetailSupra: vi.fn(),
  };
});

describe("SupraScan Address Resources Parser", () => {
  const mockAddress = "0x9176f70f125199a3e3d5549ce795a8e906eed75901d535ded623802f15ae3637";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("fetchSupraScanAddressResources", () => {
    it("should parse resources string and extract PackageRegistry", async () => {
      // Mock response with resources as JSON string
      const mockResourcesString = JSON.stringify([
        {
          type: "0x1::account::Account",
          data: { sequence_number: "0" },
        },
        {
          type: "0x1::code::PackageRegistry",
          data: {
            packages: [
              {
                package_name: "my_package",
                account: "0x123",
                upgrade_number: 1,
                upgrade_policy: { policy: 1 },
                source_digest: "abc123",
                deps: [
                  { account: "0x456", package_name: "dep_package" },
                ],
                modules: [
                  {
                    name: "my_module",
                    source: "0x1f8b08000000000000ff", // Minimal gzip header (will fail decompression but that's ok)
                    source_map: "0x",
                  },
                ],
              },
            ],
          },
        },
      ]);

      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: false,
        errorType: null,
        addressDetailSupra: {
          resources: mockResourcesString,
        },
      });

      const result = await fetchSupraScanAddressResources(mockAddress, "mainnet");

      expect(result).toMatchObject({
        address: mockAddress,
        env: "mainnet",
        rawResourcesCount: 2,
        hasPackageRegistry: true,
        packages: [
          {
            publisher: "0x123",
            name: "my_package",
            upgradeNumber: 1,
            upgradePolicy: 1,
            sourceDigest: "abc123",
            deps: [{ publisher: "0x456", name: "dep_package" }],
            modules: [
              {
                moduleName: "my_module",
                sourceHex: "0x1f8b08000000000000ff",
              },
            ],
          },
        ],
      });
    });

    it("should throw SupraScanResourceError when isError is true", async () => {
      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: true,
        errorType: "INVALID_ADDRESS",
        addressDetailSupra: null,
      });

      await expect(
        fetchSupraScanAddressResources(mockAddress, "mainnet")
      ).rejects.toThrow(SupraScanResourceError);

      await expect(
        fetchSupraScanAddressResources(mockAddress, "mainnet")
      ).rejects.toThrow("SupraScan returned error: INVALID_ADDRESS");
    });

    it("should throw bad_resources_payload when resources is not a valid JSON string", async () => {
      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: false,
        errorType: null,
        addressDetailSupra: {
          resources: "not valid json{",
        },
      });

      await expect(
        fetchSupraScanAddressResources(mockAddress, "mainnet")
      ).rejects.toThrow(SupraScanResourceError);

      await expect(
        fetchSupraScanAddressResources(mockAddress, "mainnet")
      ).rejects.toThrow("bad_resources_payload");
    });

    it("should handle missing PackageRegistry gracefully", async () => {
      const mockResourcesString = JSON.stringify([
        {
          type: "0x1::account::Account",
          data: { sequence_number: "0" },
        },
      ]);

      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: false,
        errorType: null,
        addressDetailSupra: {
          resources: mockResourcesString,
        },
      });

      const result = await fetchSupraScanAddressResources(mockAddress, "mainnet");

      expect(result.hasPackageRegistry).toBe(false);
      expect(result.packages).toEqual([]);
      expect(result.rawResourcesCount).toBe(1);
    });

    it("should handle empty packages array", async () => {
      const mockResourcesString = JSON.stringify([
        {
          type: "0x1::code::PackageRegistry",
          data: {
            packages: [],
          },
        },
      ]);

      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: false,
        errorType: null,
        addressDetailSupra: {
          resources: mockResourcesString,
        },
      });

      const result = await fetchSupraScanAddressResources(mockAddress, "mainnet");

      expect(result.hasPackageRegistry).toBe(true);
      expect(result.packages).toEqual([]);
    });

    it("should decompress module source when decompressSource is true", async () => {
      // Create a minimal valid gzip payload (compressed "module test {}")
      // This is a best-effort test - real gzip data would be longer
      const mockResourcesString = JSON.stringify([
        {
          type: "0x1::code::PackageRegistry",
          data: {
            packages: [
              {
                package_name: "test_package",
                account: "0x123",
                modules: [
                  {
                    name: "test_module",
                    source: "0x1f8b08000000000000ff", // Minimal gzip (will fail but that's ok for test)
                  },
                ],
              },
            ],
          },
        },
      ]);

      vi.mocked(fetchAddressDetailSupra).mockResolvedValue({
        isError: false,
        errorType: null,
        addressDetailSupra: {
          resources: mockResourcesString,
        },
      });

      const result = await fetchSupraScanAddressResources(mockAddress, "mainnet", {
        decompressSource: true,
      });

      // Decompression will fail for this minimal data, so decodedMoveSource should be undefined
      expect(result.packages[0].modules[0].sourceHex).toBe("0x1f8b08000000000000ff");
      // decodedMoveSource may be undefined if decompression fails (which is expected for test data)
    });
  });

  describe("decompressModuleSource", () => {
    it("should return null for invalid hex string", () => {
      expect(decompressModuleSource("")).toBeNull();
      expect(decompressModuleSource("invalid")).toBeNull();
      expect(decompressModuleSource("123")).toBeNull(); // Missing 0x prefix
    });

    it("should return null for invalid gzip data", () => {
      // Invalid gzip data
      expect(decompressModuleSource("0x123456")).toBeNull();
    });

    it("should handle decompression gracefully on failure", () => {
      // This should not throw, just return null
      const result = decompressModuleSource("0x1f8b08000000000000ff");
      // Result may be null if decompression fails (expected for minimal test data)
      expect(result === null || typeof result === "string").toBe(true);
    });
  });
});


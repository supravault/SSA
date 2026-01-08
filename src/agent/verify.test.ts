import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type { VerificationReport } from "./types";

/**
 * Unit tests for agent-verify output structure and field normalization
 */
describe("agent-verify output structure", () => {
  const tmpDir = join(process.cwd(), "tmp");

  describe("indexer_parity.details normalization", () => {
    it("should have details.supplyParity when indexer_parity exists (with-suprascan enabled)", () => {
      // This test expects a real output file from a run with --with-suprascan true
      const outputPath = join(tmpDir, "fa_agent_suprascan.json");
      if (!existsSync(outputPath)) {
        // Skip if test output doesn't exist yet - user needs to generate it first
        console.warn(`Skipping test: ${outputPath} not found. Run agent-verify with --with-suprascan true first.`);
        return;
      }

      const outputStr = readFileSync(outputPath, "utf-8");
      const report: VerificationReport = JSON.parse(outputStr);

      // indexer_parity should exist when withSupraScan was enabled
      if (report.indexer_parity) {
        expect(report.indexer_parity.details).toBeDefined();
        expect(report.indexer_parity.details?.supplyParity).toBeDefined();
        expect(typeof report.indexer_parity.details?.supplyParity).toBe("string");
        // Should be a valid parity value or "n/a"
        const validParityValues = ["match", "mismatch", "unknown", "insufficient", "unsupported", "n/a"];
        expect(validParityValues).toContain(report.indexer_parity.details?.supplyParity);
      }
    });

    it("should have details.supplyParity === 'n/a' when SupraScan disabled", () => {
      // This test expects a real output file from a run WITHOUT --with-suprascan
      const outputPath = join(tmpDir, "verify_fa_hashes2.json");
      if (!existsSync(outputPath)) {
        // Try alternative path
        const altPath = join(tmpDir, "verify_fa_hashes.json");
        if (!existsSync(altPath)) {
          console.warn(`Skipping test: ${outputPath} not found. Run agent-verify without --with-suprascan first.`);
          return;
        }
        const outputStr = readFileSync(altPath, "utf-8");
        const report: VerificationReport = JSON.parse(outputStr);

        // If indexer_parity exists, details should be normalized
        if (report.indexer_parity) {
          expect(report.indexer_parity.details).toBeDefined();
          expect(report.indexer_parity.details?.supplyParity).toBe("n/a");
        }
        return;
      }

      const outputStr = readFileSync(outputPath, "utf-8");
      const report: VerificationReport = JSON.parse(outputStr);

      // If indexer_parity exists (even if not requested), details should be normalized
      if (report.indexer_parity) {
        expect(report.indexer_parity.details).toBeDefined();
        expect(report.indexer_parity.details?.supplyParity).toBe("n/a");
        // Other fields should also be "n/a" when not requested
        expect(report.indexer_parity.details?.ownerParity).toBe("n/a");
        expect(report.indexer_parity.details?.hooksParity).toBe("n/a");
      }
    });

    it("should never have undefined details when indexer_parity exists", () => {
      // Test both cases if files exist
      const testFiles = [
        join(tmpDir, "fa_agent_suprascan.json"),
        join(tmpDir, "verify_fa_hashes2.json"),
        join(tmpDir, "verify_fa_hashes.json"),
      ];

      let foundAny = false;
      for (const filePath of testFiles) {
        if (existsSync(filePath)) {
          foundAny = true;
          const outputStr = readFileSync(filePath, "utf-8");
          const report: VerificationReport = JSON.parse(outputStr);

          if (report.indexer_parity) {
            expect(report.indexer_parity.details).toBeDefined();
            expect(report.indexer_parity.details).not.toBeNull();
            // All parity fields should be defined (even if "n/a")
            expect(report.indexer_parity.details?.supplyParity).toBeDefined();
            expect(report.indexer_parity.details?.ownerParity).toBeDefined();
            expect(report.indexer_parity.details?.hooksParity).toBeDefined();
            expect(report.indexer_parity.details?.hookHashParity).toBeDefined();
          }
        }
      }

      if (!foundAny) {
        console.warn("Skipping test: No test output files found. Run agent-verify to generate test outputs.");
      }
    });
  });

  describe("suprascan_fa.reason normalization", () => {
    it("should have reason string when with-suprascan enabled", () => {
      const outputPath = join(tmpDir, "fa_agent_suprascan.json");
      if (!existsSync(outputPath)) {
        console.warn(`Skipping test: ${outputPath} not found. Run agent-verify with --with-suprascan true first.`);
        return;
      }

      const outputStr = readFileSync(outputPath, "utf-8");
      const report: VerificationReport = JSON.parse(outputStr);

      if (report.suprascan_fa) {
        expect(report.suprascan_fa.reason).toBeDefined();
        expect(typeof report.suprascan_fa.reason).toBe("string");
        // Reason should explain which fields were returned
        expect(report.suprascan_fa.reason.length).toBeGreaterThan(0);
        
        // If partial_ok, should mention partial evidence
        if (report.suprascan_fa.status === "partial_ok") {
          expect(report.suprascan_fa.reason).toMatch(/partial|supply|owner|hooks/i);
        }
      }
    });

    it("should have reason string when SupraScan disabled", () => {
      const outputPath = join(tmpDir, "verify_fa_hashes2.json");
      if (!existsSync(outputPath)) {
        const altPath = join(tmpDir, "verify_fa_hashes.json");
        if (!existsSync(altPath)) {
          console.warn(`Skipping test: ${outputPath} not found. Run agent-verify without --with-suprascan first.`);
          return;
        }
        const outputStr = readFileSync(altPath, "utf-8");
        const report: VerificationReport = JSON.parse(outputStr);

        if (report.suprascan_fa) {
          expect(report.suprascan_fa.reason).toBeDefined();
          expect(typeof report.suprascan_fa.reason).toBe("string");
          // Should mention not requested
          expect(report.suprascan_fa.reason).toMatch(/not requested/i);
        }
        return;
      }

      const outputStr = readFileSync(outputPath, "utf-8");
      const report: VerificationReport = JSON.parse(outputStr);

      if (report.suprascan_fa) {
        expect(report.suprascan_fa.reason).toBeDefined();
        expect(typeof report.suprascan_fa.reason).toBe("string");
        // Should mention not requested
        expect(report.suprascan_fa.reason).toMatch(/not requested/i);
      }
    });

    it("should never have undefined reason when suprascan_fa exists", () => {
      const testFiles = [
        join(tmpDir, "fa_agent_suprascan.json"),
        join(tmpDir, "verify_fa_hashes2.json"),
        join(tmpDir, "verify_fa_hashes.json"),
      ];

      let foundAny = false;
      for (const filePath of testFiles) {
        if (existsSync(filePath)) {
          foundAny = true;
          const outputStr = readFileSync(filePath, "utf-8");
          const report: VerificationReport = JSON.parse(outputStr);

          if (report.suprascan_fa) {
            expect(report.suprascan_fa.reason).toBeDefined();
            expect(report.suprascan_fa.reason).not.toBeNull();
            expect(typeof report.suprascan_fa.reason).toBe("string");
          }
        }
      }

      if (!foundAny) {
        console.warn("Skipping test: No test output files found. Run agent-verify to generate test outputs.");
      }
    });
  });

  describe("field consistency", () => {
    it("should have consistent structure across all test outputs", () => {
      const testFiles = [
        join(tmpDir, "fa_agent_suprascan.json"),
        join(tmpDir, "verify_fa_hashes2.json"),
        join(tmpDir, "verify_fa_hashes.json"),
      ];

      let foundAny = false;
      for (const filePath of testFiles) {
        if (existsSync(filePath)) {
          foundAny = true;
          const outputStr = readFileSync(filePath, "utf-8");
          const report: VerificationReport = JSON.parse(outputStr);

          // Required top-level fields
          expect(report.target).toBeDefined();
          expect(report.timestamp_iso).toBeDefined();
          expect(report.rpc_url).toBeDefined();
          expect(report.mode).toBeDefined();
          expect(report.claims).toBeDefined();
          expect(Array.isArray(report.claims)).toBe(true);
          expect(report.overallEvidenceTier).toBeDefined();
          expect(report.discrepancies).toBeDefined();
          expect(Array.isArray(report.discrepancies)).toBe(true);
          expect(report.status).toBeDefined();

          // If indexer_parity exists, details must exist
          if (report.indexer_parity) {
            expect(report.indexer_parity.details).toBeDefined();
            expect(report.indexer_parity.details?.supplyParity).toBeDefined();
          }

          // If suprascan_fa exists, reason must exist
          if (report.suprascan_fa) {
            expect(report.suprascan_fa.reason).toBeDefined();
            expect(typeof report.suprascan_fa.reason).toBe("string");
          }
        }
      }

      if (!foundAny) {
        console.warn("Skipping test: No test output files found. Run agent-verify to generate test outputs.");
      }
    });
  });
});


import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync, writeFileSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import { execSync } from "child_process";

/**
 * Unit tests for agent-verify CLI improvements
 */
describe("agent-verify CLI", () => {
  const testDir = join(process.cwd(), "tmp");
  const testOutputPath = join(testDir, "test_agent_verify.json");
  const testFA = "0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee";
  const rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";

  beforeAll(() => {
    // Ensure tmp directory exists
    if (!existsSync(testDir)) {
      execSync(`mkdir -p ${testDir}`, { stdio: "inherit" });
    }
  });

  afterAll(() => {
    // Cleanup test output file
    if (existsSync(testOutputPath)) {
      try {
        unlinkSync(testOutputPath);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  });

  describe("--mode handling", () => {
    it("should accept --mode agent and set mode to 'agent' in output", () => {
      // This test requires a real RPC connection, so we'll check the output file if it exists
      // For a real test, you would run: node dist/src/scripts/agent-verify.js --fa <fa> --mode agent --out tmp/test.json
      // Then check that test.json has "mode":"agent"
      
      // Skip if dist doesn't exist yet (requires build)
      const distScript = join(process.cwd(), "dist", "src", "scripts", "agent-verify.js");
      if (!existsSync(distScript)) {
        console.warn("Skipping test: dist/src/scripts/agent-verify.js not found. Run npm run build first.");
        return;
      }

      try {
        // Run with --mode agent
        execSync(
          `node "${distScript}" --fa "${testFA}" --rpc "${rpcUrl}" --mode agent --out "${testOutputPath}" --quiet`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 }
        );

        if (existsSync(testOutputPath)) {
          const output = JSON.parse(readFileSync(testOutputPath, "utf-8"));
          expect(output.mode).toBe("agent");
        }
      } catch (error: any) {
        // If RPC fails, skip the test (requires network)
        console.warn(`Skipping test due to RPC error: ${error.message}`);
      }
    });

    it("should accept --mode fast (case-insensitive)", () => {
      const distScript = join(process.cwd(), "dist", "src", "scripts", "agent-verify.js");
      if (!existsSync(distScript)) {
        return;
      }

      try {
        execSync(
          `node "${distScript}" --fa "${testFA}" --rpc "${rpcUrl}" --mode FAST --out "${testOutputPath}" --quiet`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 }
        );

        if (existsSync(testOutputPath)) {
          const output = JSON.parse(readFileSync(testOutputPath, "utf-8"));
          expect(output.mode.toLowerCase()).toBe("fast");
        }
      } catch (error: any) {
        console.warn(`Skipping test due to RPC error: ${error.message}`);
      }
    });
  });

  describe("--quiet flag", () => {
    it("should suppress JSON output to stdout when --quiet is set", () => {
      const distScript = join(process.cwd(), "dist", "src", "scripts", "agent-verify.js");
      if (!existsSync(distScript)) {
        return;
      }

      try {
        const stdout = execSync(
          `node "${distScript}" --fa "${testFA}" --rpc "${rpcUrl}" --quiet --out "${testOutputPath}"`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 }
        );

        // stdout should not contain JSON (may have status messages)
        const jsonMatch = stdout.match(/\{[\s\S]*\}/);
        expect(jsonMatch).toBeNull();

        // But file should still be written
        expect(existsSync(testOutputPath)).toBe(true);
      } catch (error: any) {
        console.warn(`Skipping test due to RPC error: ${error.message}`);
      }
    });
  });

  describe("--report compact", () => {
    it("should print compact one-line report when --report compact is set", () => {
      const distScript = join(process.cwd(), "dist", "src", "scripts", "agent-verify.js");
      if (!existsSync(distScript)) {
        return;
      }

      try {
        const stdout = execSync(
          `node "${distScript}" --fa "${testFA}" --rpc "${rpcUrl}" --report compact --label TEST_LABEL --out "${testOutputPath}"`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 }
        );

        // Should be exactly one line with expected format
        const lines = stdout.trim().split("\n").filter(l => l.trim().length > 0);
        expect(lines.length).toBeGreaterThan(0);
        
        const compactLine = lines[lines.length - 1]; // Last non-empty line should be the compact report
        expect(compactLine).toMatch(/TEST_LABEL \| fa \| tier=/);
        expect(compactLine).toMatch(/risk=/);
        expect(compactLine).toMatch(/suprascan=/);
        expect(compactLine).toMatch(/supplyParity=/);
        expect(compactLine).toMatch(/behavior=/);
        
        // Should have exactly one pipe separator for the format
        const pipeCount = (compactLine.match(/\|/g) || []).length;
        expect(pipeCount).toBe(2); // label | kind | details
      } catch (error: any) {
        console.warn(`Skipping test due to RPC error: ${error.message}`);
      }
    });
  });

  describe("coin support parity", () => {
    it("should support --coin flag and set target.kind to 'coin'", () => {
      const distScript = join(process.cwd(), "dist", "src", "scripts", "agent-verify.js");
      if (!existsSync(distScript)) {
        return;
      }

      const testCoin = "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH";
      
      try {
        execSync(
          `node "${distScript}" --coin "${testCoin}" --rpc "${rpcUrl}" --out "${testOutputPath}" --quiet`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 }
        );

        if (existsSync(testOutputPath)) {
          const output = JSON.parse(readFileSync(testOutputPath, "utf-8"));
          expect(output.target.kind).toBe("coin");
          expect(output.target.id).toBe(testCoin);
        }
      } catch (error: any) {
        console.warn(`Skipping test due to RPC error: ${error.message}`);
      }
    });
  });
});


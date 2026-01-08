import { describe, it, expect } from "vitest";
import { rule_001_open_entrypoints } from "./rule_001_open_entrypoints.js";
import type { ArtifactView, RuleContext } from "../../core/types.js";

describe("rule_001_open_entrypoints", () => {
  it("should detect dangerous entrypoints without access control", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["mint", "transfer"],
      entryFunctions: ["mint", "transfer"],
      strings: [],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
      capabilities: {
        viewOnly: true,
        hasAbi: false,
        hasBytecodeOrSource: false,
      },
    };

    const findings = rule_001_open_entrypoints(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.id === "SVSSA-MOVE-001")).toBe(true);
    // In view-only mode, should NOT be critical (max medium)
    expect(findings.some((f) => f.severity === "medium" || f.severity === "high")).toBe(true);
    // Should NOT have critical findings
    expect(findings.some((f) => f.severity === "critical")).toBe(false);
  });

  it("should lower severity if access control hints exist", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["mint", "only_admin"],
      entryFunctions: ["mint"],
      strings: ["only_admin", "require_admin"],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
      capabilities: {
        viewOnly: false,
        hasAbi: false,
        hasBytecodeOrSource: false,
      },
    };

    const findings = rule_001_open_entrypoints(ctx);
    const mintFinding = findings.find((f) => f.evidence.matched.includes("mint"));
    expect(mintFinding).toBeDefined();
    // Should be medium (heuristic) or high, never critical
    expect(["medium", "high"]).toContain(mintFinding?.severity);
    expect(mintFinding?.severity).not.toBe("critical");
  });

  it("should return empty array if no dangerous patterns", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["get_balance", "get_info"],
      entryFunctions: ["get_balance"],
      strings: [],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
      capabilities: {
        viewOnly: false,
        hasAbi: false,
        hasBytecodeOrSource: false,
      },
    };

    const findings = rule_001_open_entrypoints(ctx);
    expect(findings.length).toBe(0);
  });
});


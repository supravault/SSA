import { describe, it, expect } from "vitest";
import { rule_005_asset_outflow } from "./rule_005_asset_outflow.js";
import type { ArtifactView, RuleContext } from "../../core/types.js";

describe("rule_005_asset_outflow", () => {
  it("should detect asset outflow functions", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["withdraw", "transfer", "burn"],
      entryFunctions: ["withdraw", "transfer"],
      strings: [],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_005_asset_outflow(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.id === "SVSSA-MOVE-005")).toBe(true);
  });

  it("should detect multiple outflow patterns", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["withdraw", "mint", "burn", "drain"],
      entryFunctions: ["withdraw", "mint", "burn", "drain"],
      strings: [],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_005_asset_outflow(ctx);
    expect(findings.length).toBeGreaterThanOrEqual(4); // At least one finding per function
  });

  it("should lower severity if access control hints exist", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: ["withdraw", "only_admin"],
      entryFunctions: ["withdraw"],
      strings: ["only_admin", "assert_owner"],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_005_asset_outflow(ctx);
    const withdrawFinding = findings.find((f) => f.evidence.matched.includes("withdraw"));
    expect(withdrawFinding).toBeDefined();
    // Should be high instead of critical if access control exists
    expect(withdrawFinding?.severity).toBe("high");
  });
});


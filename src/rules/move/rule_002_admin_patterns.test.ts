import { describe, it, expect } from "vitest";
import { rule_002_admin_patterns } from "./rule_002_admin_patterns.js";
import type { ArtifactView, RuleContext } from "../../core/types.js";

describe("rule_002_admin_patterns", () => {
  it("should detect hardcoded addresses with admin keywords", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: [],
      entryFunctions: [],
      strings: [
        "0x1234567890123456789012345678901234567890",
        "admin",
        "owner",
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      ],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_002_admin_patterns(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.id === "SVSSA-MOVE-002")).toBe(true);
  });

  it("should not flag if only addresses without admin keywords", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: [],
      entryFunctions: [],
      strings: ["0x1234567890123456789012345678901234567890"],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_002_admin_patterns(ctx);
    expect(findings.length).toBe(0);
  });

  it("should not flag if only admin keywords without addresses", () => {
    const artifact: ArtifactView = {
      moduleId: { address: "0x123", module_name: "test" },
      bytecode: null,
      abi: null,
      functionNames: [],
      entryFunctions: [],
      strings: ["admin", "owner"],
      metadata: null,
    };

    const ctx: RuleContext = {
      artifact,
      scanLevel: "quick",
    };

    const findings = rule_002_admin_patterns(ctx);
    expect(findings.length).toBe(0);
  });
});


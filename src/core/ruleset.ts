import type { Finding, RuleContext, RuleCapabilities } from "./types.js";
import { rule_001_open_entrypoints } from "../rules/move/rule_001_open_entrypoints.js";
import { rule_002_admin_patterns } from "../rules/move/rule_002_admin_patterns.js";
import { rule_003_hardcoded_privileged } from "../rules/move/rule_003_hardcoded_privileged.js";
import { rule_004_upgrade_init_reentry } from "../rules/move/rule_004_upgrade_init_reentry.js";
import { rule_005_asset_outflow } from "../rules/move/rule_005_asset_outflow.js";
import { rule_006_unbounded_loops } from "../rules/move/rule_006_unbounded_loops.js";
import { rule_007_missing_events } from "../rules/move/rule_007_missing_events.js";
import { rule_008_centralization } from "../rules/move/rule_008_centralization.js";
import { rule_009_external_dependency } from "../rules/move/rule_009_external_dependency.js";
import { rule_010_emergency_pause } from "../rules/move/rule_010_emergency_pause.js";
import { rule_011 } from "../rules/move/rule_011.js";
import { rule_012 } from "../rules/move/rule_012.js";
import { rule_013 } from "../rules/move/rule_013.js";
import { rule_014 } from "../rules/move/rule_014.js";
import { rule_015 } from "../rules/move/rule_015.js";
import { rule_016 } from "../rules/move/rule_016.js";
import { rule_017 } from "../rules/move/rule_017.js";
import { rule_018 } from "../rules/move/rule_018.js";
import { rule_019 } from "../rules/move/rule_019.js";
import { rule_020 } from "../rules/move/rule_020.js";
import { rule_021 } from "../rules/move/rule_021.js";
import { rule_022 } from "../rules/move/rule_022.js";
import { rule_023 } from "../rules/move/rule_023.js";
import { rule_024 } from "../rules/move/rule_024.js";
import { rule_025 } from "../rules/move/rule_025.js";

export type RuleFunction = (ctx: RuleContext) => Finding[];

export interface Rule {
  id: string;
  name: string;
  fn: RuleFunction;
}

/**
 * Ruleset registry
 * Version: move-ruleset-0.1.0
 */
export const RULESET_VERSION = "move-ruleset-0.1.0";

export const RULES: Rule[] = [
  { id: "SVSSA-MOVE-001", name: "Open/Dangerous Entrypoints", fn: rule_001_open_entrypoints },
  { id: "SVSSA-MOVE-002", name: "Privileged Role Hardcoding", fn: rule_002_admin_patterns },
  { id: "SVSSA-MOVE-003", name: "Re-initialization Risk", fn: rule_003_hardcoded_privileged },
  { id: "SVSSA-MOVE-004", name: "Upgrade Hooks Risk", fn: rule_004_upgrade_init_reentry },
  { id: "SVSSA-MOVE-005", name: "Asset Outflow Primitives", fn: rule_005_asset_outflow },
  { id: "SVSSA-MOVE-006", name: "Unbounded Loops", fn: rule_006_unbounded_loops },
  { id: "SVSSA-MOVE-007", name: "Missing Event Emissions", fn: rule_007_missing_events },
  { id: "SVSSA-MOVE-008", name: "Centralization Risk", fn: rule_008_centralization },
  { id: "SVSSA-MOVE-009", name: "External Dependency/Oracle Usage", fn: rule_009_external_dependency },
  { id: "SVSSA-MOVE-010", name: "Emergency Pause Abuse", fn: rule_010_emergency_pause },
  { id: "SVSSA-MOVE-011", name: "Integer Overflow/Underflow", fn: rule_011 },
  { id: "SVSSA-MOVE-012", name: "Reentrancy Risks", fn: rule_012 },
  { id: "SVSSA-MOVE-013", name: "Front-running Vulnerabilities", fn: rule_013 },
  { id: "SVSSA-MOVE-014", name: "Access Control Bypass", fn: rule_014 },
  { id: "SVSSA-MOVE-015", name: "Timestamp Dependence", fn: rule_015 },
  { id: "SVSSA-MOVE-016", name: "Random Number Generation Risks", fn: rule_016 },
  { id: "SVSSA-MOVE-017", name: "Denial of Service Risks", fn: rule_017 },
  { id: "SVSSA-MOVE-018", name: "Gas Optimization Issues", fn: rule_018 },
  { id: "SVSSA-MOVE-019", name: "Unchecked External Calls", fn: rule_019 },
  { id: "SVSSA-MOVE-020", name: "Missing Input Validation", fn: rule_020 },
  { id: "SVSSA-MOVE-021", name: "Signature Replay Attacks", fn: rule_021 },
  { id: "SVSSA-MOVE-022", name: "Price Manipulation Risks", fn: rule_022 },
  { id: "SVSSA-MOVE-023", name: "Flash Loan Attack Vectors", fn: rule_023 },
  { id: "SVSSA-MOVE-024", name: "Missing Slippage Protection", fn: rule_024 },
  { id: "SVSSA-MOVE-025", name: "Uninitialized Storage Risks", fn: rule_025 },
];

/**
 * Get rules for a given scan level
 * For now, "quick" returns all rules (can be optimized later)
 */
export function getRulesForLevel(scanLevel: string): Rule[] {
  // For MVP, all scan levels use all rules
  // Future: filter rules based on scan level
  return RULES;
}

/**
 * Default capabilities object for safe rule execution
 * Used when ctx.capabilities is missing or undefined
 */
const DEFAULT_CAPABILITIES: RuleCapabilities = {
  viewOnly: false,
  hasAbi: false,
  hasBytecodeOrSource: false,
  artifactMode: "view_only",
};

/**
 * Normalize RuleContext to ensure capabilities always exists
 * This prevents crashes when rules access ctx.capabilities directly
 */
export function normalizeRuleContext(ctx: RuleContext): RuleContext & { capabilities: RuleCapabilities } {
  return {
    ...ctx,
    capabilities: {
      ...DEFAULT_CAPABILITIES,
      ...(ctx.capabilities ?? {}),
    },
  };
}

/**
 * Execute all rules for a given context
 * Ensures ctx.capabilities always exists to prevent crashes
 */
export function executeRules(ctx: RuleContext): Finding[] {
  // Normalize capabilities: merge with defaults to ensure all fields exist
  const normalizedCtx = normalizeRuleContext(ctx);

  const rules = getRulesForLevel(normalizedCtx.scanLevel);
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.fn(normalizedCtx);
      findings.push(...ruleFindings);
    } catch (error) {
      console.error(`Error executing rule ${rule.id}:`, error);
      // Continue with other rules even if one fails
    }
  }

  return findings;
}


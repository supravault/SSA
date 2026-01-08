import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-004: Upgrade hooks risk
 * Detects upgrade-related functions that may lack proper access control
 * Evidence-based: Maximum severity is HIGH (never CRITICAL) based on ABI evidence
 * View-only scans are capped at MEDIUM severity with low confidence
 */
export function rule_004_upgrade_init_reentry(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  const upgradePatterns = ["upgrade", "set_code", "publish", "migrate", "update_code"];

  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    const matchedPatterns = upgradePatterns.filter((pattern) =>
      fnLower.includes(pattern)
    );

    if (matchedPatterns.length === 0) {
      continue;
    }

    // Check for access control hints (heuristic only)
    const accessControlKeywords = ["only_admin", "only_owner", "require_admin", "governance"];
    const hasAccessControl = 
      artifact.strings.some((s) =>
        accessControlKeywords.some((keyword) => s.toLowerCase().includes(keyword))
      ) ||
      artifact.functionNames.some((fn) =>
        accessControlKeywords.some((keyword) => fn.toLowerCase().includes(keyword))
      );

    // Check ABI for signer parameter (if available)
    let hasSignerParam = false;
    let hasAbiEvidence = false;
    if (artifact.abi && capabilities.hasAbi) {
      const fnDef = findFunctionInAbi(artifact.abi, entryFn);
      if (fnDef) {
        hasAbiEvidence = true;
        hasSignerParam = hasSignerParameter(fnDef);
      }
    }

    // Evidence-based severity gating
    // Maximum severity: HIGH (never CRITICAL without verified access control absence)
    let severity: "high" | "medium" | "low" | "info";
    let confidence: number;
    let evidenceKind: "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic";

    if (capabilities.viewOnly) {
      // View-only mode: cannot verify access control, cap at medium with low confidence
      severity = "medium";
      confidence = 0.4;
      evidenceKind = "heuristic";
    } else if (capabilities.hasAbi && hasAbiEvidence) {
      // ABI available: can check signer params
      // Maximum confidence: 0.6 for ABI-based findings
      if (hasSignerParam || hasAccessControl) {
        severity = "high";
        confidence = 0.6;
        evidenceKind = "abi_pattern";
      } else {
        // No signer param and no access control markers: high severity but capped confidence
        severity = "high";
        confidence = 0.6; // Capped at 0.6 - cannot prove absence without verified access control check
        evidenceKind = "abi_pattern";
      }
    } else {
      // No ABI: heuristic only, cap at medium with low confidence
      severity = "medium";
      confidence = 0.4;
      evidenceKind = "heuristic";
    }

    findings.push({
      id: "SVSSA-MOVE-004",
      title: "Upgrade Function Without Clear Access Control",
      severity,
      confidence,
      description: `Entry function "${entryFn}" appears to handle code upgrades or migrations. Upgrade functions are critical security points and must be properly gated.${capabilities.viewOnly ? " Note: View-only scan; cannot verify access control without ABI/bytecode." : ""}`,
      recommendation: hasAccessControl || hasSignerParam
        ? "Verify that upgrade access control is enforced and consider adding timelock or multisig requirements."
        : "Implement strict access control (admin/owner/governance) for upgrade functions. Consider adding timelock delays for production deployments.",
      evidence: {
        kind: evidenceKind,
        matched: matchedPatterns,
        locations: [{ fn: entryFn, note: "Upgrade-related function detected" }],
      },
      references: [],
    });
  }

  return findings;
}

function findFunctionInAbi(abi: any, functionName: string): any {
  if (Array.isArray(abi.functions)) {
    return abi.functions.find((f: any) => f.name === functionName);
  }
  if (Array.isArray(abi.entry_functions)) {
    return abi.entry_functions.find((f: any) => f.name === functionName);
  }
  if (Array.isArray(abi)) {
    return abi.find((f: any) => f.name === functionName);
  }
  return null;
}

function hasSignerParameter(fnDef: any): boolean {
  if (!fnDef.params || !Array.isArray(fnDef.params)) {
    return false;
  }
  return fnDef.params.some((p: any) => 
    p.type === "&signer" || 
    p.type === "&mut signer" ||
    (typeof p === "string" && p.includes("signer"))
  );
}


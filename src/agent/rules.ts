/**
 * Level 3 Agent/Watcher Mode Severity Rules
 * Apply severity rules to diff results
 */

import type { DiffResult, ChangeItem, CoinSnapshot, FASnapshot } from "./types.js";

// Large supply delta threshold (base units)
const LARGE_SUPPLY_DELTA_THRESHOLD = 1_000_000_000;

/**
 * Parse supply value to number (handles string numbers)
 */
function parseSupplyValue(value: any): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = parseFloat(value);
    return isNaN(parsed) ? null : parsed;
  }
  return null;
}

/**
 * Calculate supply delta
 */
function calculateSupplyDelta(before: any, after: any): number | null {
  const beforeVal = parseSupplyValue(before);
  const afterVal = parseSupplyValue(after);
  if (beforeVal === null || afterVal === null) return null;
  return afterVal - beforeVal;
}

/**
 * Check if function names contain mint patterns
 */
function hasMintFunction(functionNames: string[]): boolean {
  const mintPattern = /mint|issue|create|increase_supply/i;
  return functionNames.some((fn) => mintPattern.test(fn));
}

/**
 * Apply severity rules to diff result
 */
export function applySeverityRules(
  diff: DiffResult,
  prev: CoinSnapshot | FASnapshot | null,
  curr: CoinSnapshot | FASnapshot
): DiffResult {
  if (!prev || !diff.changed) {
    return diff;
  }
  
  const updatedChanges: ChangeItem[] = diff.changes.map((change) => {
    let severity = change.severity;
    
    // SUPPLY_CHANGED rules
    if (change.type === "SUPPLY_CHANGED") {
      const delta = calculateSupplyDelta(change.before, change.after);
      if (delta !== null) {
        if (delta > 0) {
          // Supply increase
          const isFA = "objectOwner" in curr.identity;
          const isCoin = "hasMintCap" in curr.capabilities;
          
          if (isFA) {
            // FA token rules
            const hasMintRef = "hasMintRef" in curr.capabilities && (curr.capabilities as any).hasMintRef;
            
            // Check if exceeds max supply
            let exceedsMax = false;
            if ("supplyMaxBase" in curr.supply && curr.supply.supplyMaxBase) {
              const maxVal = parseSupplyValue(curr.supply.supplyMaxBase);
              const afterVal = parseSupplyValue(change.after);
              if (maxVal !== null && afterVal !== null && afterVal > maxVal) {
                exceedsMax = true;
              }
            }
            
            if (exceedsMax) {
              severity = "critical";
            } else if (hasMintRef) {
              severity = "high";
            } else {
              severity = "info";
            }
          } else if (isCoin) {
            // Legacy coin rules
            const hasMintCap = (curr.capabilities as any).hasMintCap;
            
            if (hasMintCap) {
              severity = "critical";
            } else {
              // No public mint expected, but supply increased
              severity = "high";
            }
          } else {
            // Unknown type, default to info
            severity = "info";
          }
        } else {
          // Supply decrease (burn) - info for both FA and Coin
          severity = "info";
        }
      }
    }
    
    // SUPPLY_MAX_CHANGED rules (FA only)
    if (change.type === "SUPPLY_MAX_CHANGED") {
      severity = "critical"; // FA max supply changes are always critical
    }
    
    // ABI_SURFACE_CHANGED rules - check for mint-like functions in added functions
    // Default: high
    // If hasMintLikeFunction == true (mint-like functions newly added) => critical
    // Applies to both coin and FA
    if (change.type === "ABI_SURFACE_CHANGED") {
      // Default severity is high
      severity = "high";
      
      // Check if mint-like functions were newly added (only added functions are checked in diff.ts)
      const hasMintLikeFunction = change.evidence?.hasMintLikeFunction === true;
      if (hasMintLikeFunction) {
        severity = "critical";
      }
    }
    
    // OWNER_CHANGED + HOOKS_CHANGED combination
    if (change.type === "OWNER_CHANGED") {
      const hasHooksChange = diff.changes.some((c) => c.type === "HOOKS_CHANGED");
      if (hasHooksChange) {
        severity = "critical";
      } else {
        severity = "high";
      }
    }
    
    // HOOKS_CHANGED rules
    if (change.type === "HOOKS_CHANGED") {
      severity = "high";
    }
    
    // HOOK_MODULE_CODE_CHANGED rules - stealth upgrade detection
    if (change.type === "HOOK_MODULE_CODE_CHANGED") {
      severity = "high";
    }
    
    // COIN_MODULE_CODE_CHANGED rules - stealth upgrade detection
    if (change.type === "COIN_MODULE_CODE_CHANGED") {
      severity = "high";
    }
    
    // MODULE_ADDED rules
    if (change.type === "MODULE_ADDED") {
      severity = "high";
    }
    
    // COVERAGE_CHANGED rules
    if (change.type === "COVERAGE_CHANGED") {
      if (change.before === "complete" && change.after === "partial") {
        severity = "high";
      } else {
        severity = "info";
      }
    }

    // PRIVILEGES_CHANGED rules
    if (change.type === "PRIVILEGES_CHANGED") {
      const evidence = change.evidence as any;
      const addedPrivileges = evidence?.addedPrivileges || {};
      const opaqueControlChanged = evidence?.opaqueControlChanged === true;
      const opaqueControlAfter = evidence?.opaqueControlAfter === true;

      // Check for critical privilege additions
      if (addedPrivileges.UPGRADE_PUBLISH && addedPrivileges.UPGRADE_PUBLISH.length > 0) {
        severity = "critical";
      } else if (addedPrivileges.MINT && addedPrivileges.MINT.length > 0) {
        severity = "high";
      } else if (opaqueControlChanged && opaqueControlAfter) {
        // Opaque control becoming true is high severity
        severity = "high";
      } else if (Object.keys(addedPrivileges).length > 0) {
        // Other privilege additions are high by default
        severity = "high";
      } else {
        // Privilege removals or other changes
        severity = "medium";
      }
    }

    // INVARIANTS_CHANGED rules
    if (change.type === "INVARIANTS_CHANGED") {
      const evidence = change.evidence as any;
      const newViolations = evidence?.newViolations || [];
      const statusEscalations = evidence?.statusEscalations || [];
      const overallAfter = evidence?.overallAfter || "unknown";

      // Critical if new violations appear
      if (newViolations.length > 0) {
        severity = "critical";
      } else if (overallAfter === "violation") {
        // Overall status is violation
        severity = "critical";
      } else {
        // Check for escalations to warning or violation
        const hasEscalation = statusEscalations.some(
          (e: any) => e.after === "violation" || e.after === "warning"
        );
        if (hasEscalation) {
          severity = "high";
        } else {
          severity = "medium";
        }
      }
    }
    
    // FINDINGS_CHANGED rules - use max severity of new findings
    if (change.type === "FINDINGS_CHANGED") {
      const evidence = change.evidence as any;
      // The diff engine already calculates maxNewSeverity, use it if available
      if (evidence?.maxNewSeverity) {
        severity = evidence.maxNewSeverity;
      } else if (evidence?.newFindings?.length > 0) {
        // Fallback: calculate max severity from new findings
        const severityOrder: Record<string, number> = {
          info: 1,
          medium: 2,
          high: 3,
          critical: 4,
        };
        let maxSeverity: "info" | "medium" | "high" | "critical" = "info";
        for (const finding of evidence.newFindings) {
          const findingSeverity = severityOrder[finding.severity] || 0;
          const currentMax = severityOrder[maxSeverity] || 0;
          if (findingSeverity > currentMax) {
            maxSeverity = finding.severity as "info" | "medium" | "high" | "critical";
          }
        }
        severity = maxSeverity;
      } else if (evidence?.severityEscalations?.length > 0) {
        severity = "high";
      } else {
        severity = "info";
      }
    }
    
    // Never downgrade severity
    const severityOrder: Record<string, number> = {
      info: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    if (severityOrder[change.severity] > severityOrder[severity]) {
      severity = change.severity;
    }
    
    return {
      ...change,
      severity,
    };
  });
  
  return {
    changed: diff.changed,
    changes: updatedChanges,
  };
}


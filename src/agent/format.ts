/**
 * Level 3 Agent/Watcher Mode Formatting
 * Human-readable output formatting
 */

import type { DiffResult, CoinSnapshot, FASnapshot } from "./types.js";

/**
 * Format diff result for human-readable output
 */
export function formatHuman(
  diff: DiffResult,
  currSnapshot: CoinSnapshot | FASnapshot
): string {
  const lines: string[] = [];
  
  // Identity summary
  if ("coinType" in currSnapshot.identity) {
    lines.push(`Coin: ${currSnapshot.identity.coinType}`);
    if (currSnapshot.identity.symbol) {
      lines.push(`Symbol: ${currSnapshot.identity.symbol}`);
    }
  } else {
    lines.push(`FA: ${currSnapshot.identity.faAddress}`);
    if (currSnapshot.identity.objectOwner) {
      lines.push(`Owner: ${currSnapshot.identity.objectOwner}`);
    }
  }
  
  lines.push(`Changed: ${diff.changed ? "YES" : "NO"}`);
  lines.push("");
  
  if (!diff.changed) {
    lines.push("No changes detected.");
    return lines.join("\n");
  }
  
  // List changes
  lines.push("Changes:");
  for (const change of diff.changes) {
    const severityLabel = change.severity.toUpperCase().padEnd(8);
    lines.push(`  [${severityLabel}] ${change.type}:`);
    
    // Format before/after
    if (change.before !== null && change.before !== undefined) {
      const beforeStr = typeof change.before === "object" ? JSON.stringify(change.before) : String(change.before);
      lines.push(`    Before: ${beforeStr}`);
    }
    if (change.after !== null && change.after !== undefined) {
      const afterStr = typeof change.after === "object" ? JSON.stringify(change.after) : String(change.after);
      lines.push(`    After:  ${afterStr}`);
    }
    
    // Format evidence
    if (change.evidence) {
      const evidence = change.evidence as any;
      
      if (change.type === "HOOKS_CHANGED") {
        if (evidence.added?.length > 0) {
          lines.push(`    Added hooks: ${evidence.added.map((h: any) => `${h.module_address}::${h.module_name}::${h.function_name}`).join(", ")}`);
        }
        if (evidence.removed?.length > 0) {
          lines.push(`    Removed hooks: ${evidence.removed.map((h: any) => `${h.module_address}::${h.module_name}::${h.function_name}`).join(", ")}`);
        }
      }
      
      if (change.type === "MODULE_ADDED" || change.type === "MODULE_REMOVED") {
        if (evidence.modules?.length > 0) {
          lines.push(`    Modules: ${evidence.modules.join(", ")}`);
        }
      }
      
      if (change.type === "ABI_SURFACE_CHANGED") {
        if (evidence.functionChanges) {
          const fc = evidence.functionChanges as Record<string, { added: string[]; removed: string[] }>;
          for (const [moduleId, changes] of Object.entries(fc)) {
            if (changes.added.length > 0) {
              lines.push(`    ${moduleId}: Added functions: ${changes.added.join(", ")}`);
            }
            if (changes.removed.length > 0) {
              lines.push(`    ${moduleId}: Removed functions: ${changes.removed.join(", ")}`);
            }
          }
        }
      }
      
      if (change.type === "FINDINGS_CHANGED") {
        if (evidence.new_findings?.length > 0) {
          lines.push(`    New findings: ${evidence.new_findings.map((f: any) => f.id).join(", ")}`);
        }
        if (evidence.removed_findings?.length > 0) {
          lines.push(`    Removed findings: ${evidence.removed_findings.map((f: any) => f.id).join(", ")}`);
        }
        if (evidence.severity_escalations?.length > 0) {
          lines.push(`    Severity escalations: ${evidence.severity_escalations.map((e: any) => `${e.id}: ${e.before} -> ${e.after}`).join(", ")}`);
        }
      }
      
      if (change.type === "SUPPLY_CHANGED" && evidence.formatted_before && evidence.formatted_after) {
        lines.push(`    Formatted: ${evidence.formatted_before} -> ${evidence.formatted_after}`);
      }
    }
    
    lines.push("");
  }
  
  return lines.join("\n");
}


/**
 * Level 3 Agent/Watcher Mode Diff Computation
 * Compare snapshots and detect changes
 */

import type { CoinSnapshot, FASnapshot, DiffResult, ChangeItem, ChangeType, FAControlSurface, CoinCapabilities, FACapabilities, Severity, AgentHints } from "./types.js";

const DEBUG_DIFF = process.env.SSA_DEBUG_DIFF === "1";

function debugLog(message: string, ...args: unknown[]): void {
  if (DEBUG_DIFF) {
    console.error(`[DIFF DEBUG] ${message}`, ...args);
  }
}

/**
 * Diff two snapshots (coin or FA)
 * @param ignoreSupply If true, skip SUPPLY_CHANGED and SUPPLY_MAX_CHANGED diffs
 */
export function diffSnapshots(
  prev: CoinSnapshot | FASnapshot | null,
  curr: CoinSnapshot | FASnapshot,
  options?: { ignoreSupply?: boolean }
): DiffResult {
  const ignoreSupply = options?.ignoreSupply || false;
  if (!prev) {
    // First snapshot - no changes
    debugLog("No previous snapshot, returning baseline");
    return {
      changed: false,
      changes: [],
    };
  }
  
  debugLog("Starting diff comparison");
  const changes: ChangeItem[] = [];
  
  // Check supply changes (works for both Coin and FA)
  // Skip if --ignore-supply flag is set (for deterministic testing)
  if (!ignoreSupply) {
    debugLog("Checking supply.supplyCurrentBase", {
      prev: prev.supply.supplyCurrentBase,
      curr: curr.supply.supplyCurrentBase,
      prevType: typeof prev.supply.supplyCurrentBase,
      currType: typeof curr.supply.supplyCurrentBase,
    });
    // Handle null/undefined comparison correctly
    const prevSupply = prev.supply.supplyCurrentBase ?? null;
    const currSupply = curr.supply.supplyCurrentBase ?? null;
    if (prevSupply !== currSupply) {
      debugLog("SUPPLY_CHANGED detected", {
        before: prevSupply,
        after: currSupply,
      });
      
      // Parse supply values to BigInt for calculation
      const LARGE_SUPPLY_DELTA_THRESHOLD = 1_000_000; // 1M base units
      const LARGE_SUPPLY_PCT_THRESHOLD = 0.01; // 1%
      
      let prevVal: bigint | null = null;
      let currVal: bigint | null = null;
      
      try {
        if (prevSupply !== null) {
          prevVal = BigInt(String(prevSupply));
        }
        if (currSupply !== null) {
          currVal = BigInt(String(currSupply));
        }
      } catch {
        // If BigInt parsing fails, treat as null
      }
      
      let changeType: "SUPPLY_CHANGED_LARGE" | "SUPPLY_CHANGED_SMALL" = "SUPPLY_CHANGED_SMALL";
      let severity: Severity = "info";
      let deltaAbs: bigint | null = null;
      let deltaPct: number | null = null;
      
      if (prevVal !== null && currVal !== null) {
        deltaAbs = currVal > prevVal ? currVal - prevVal : prevVal - currVal;
        const deltaAbsNum = Number(deltaAbs);
        const prevNum = Number(prevVal);
        const maxBase = Math.max(prevNum, 1);
        deltaPct = deltaAbsNum / maxBase;
        
        // Determine if large change
        if (deltaPct > LARGE_SUPPLY_PCT_THRESHOLD || deltaAbsNum > LARGE_SUPPLY_DELTA_THRESHOLD) {
          changeType = "SUPPLY_CHANGED_LARGE";
          severity = "high";
        }
      }
      
      changes.push({
        type: changeType,
        severity,
        before: prevSupply,
        after: currSupply,
        evidence: {
          formatted_before: prev.supply.supplyCurrentFormatted ?? null,
          formatted_after: curr.supply.supplyCurrentFormatted ?? null,
          decimals: curr.supply.decimals ?? null,
          delta_abs: deltaAbs !== null ? String(deltaAbs) : null,
          delta_pct: deltaPct !== null ? deltaPct : null,
        },
      });
    } else {
      debugLog("SUPPLY_CHANGED NOT detected - values are equal");
    }
    
    // Check max supply changes (FA only)
    debugLog("Checking supply.supplyMaxBase");
    if ("supplyMaxBase" in prev.supply && "supplyMaxBase" in curr.supply) {
      const prevMax = prev.supply.supplyMaxBase ?? null;
      const currMax = curr.supply.supplyMaxBase ?? null;
      debugLog("supplyMaxBase values", {
        prev: prevMax,
        curr: currMax,
        prevType: typeof prevMax,
        currType: typeof currMax,
      });
      if (prevMax !== currMax) {
        debugLog("SUPPLY_MAX_CHANGED detected", {
          before: prevMax,
          after: currMax,
        });
        changes.push({
          type: "SUPPLY_MAX_CHANGED",
          severity: "critical", // FA max supply changes are critical
          before: prevMax,
          after: currMax,
        });
      } else {
        debugLog("SUPPLY_MAX_CHANGED NOT detected - values are equal");
      }
    } else {
      debugLog("Skipping supplyMaxBase check - not FA snapshots");
    }
  } else {
    debugLog("Skipping supply checks (--ignore-supply flag set)");
  }
  
  // Check owner changes (FA only)
  debugLog("Checking identity.objectOwner");
  if ("objectOwner" in prev.identity && "objectOwner" in curr.identity) {
    const prevOwner = prev.identity.objectOwner;
    const currOwner = curr.identity.objectOwner;
    debugLog("objectOwner values", { 
      prev: prevOwner, 
      curr: currOwner,
      prevType: typeof prevOwner,
      currType: typeof currOwner,
      areEqual: prevOwner === currOwner,
    });
    if (prevOwner !== currOwner) {
      debugLog("OWNER_CHANGED detected", {
        before: prevOwner,
        after: currOwner,
      });
      changes.push({
        type: "OWNER_CHANGED",
        severity: "high", // Will be upgraded by rules if needed
        before: prevOwner,
        after: currOwner,
      });
    } else {
      debugLog("OWNER_CHANGED NOT detected - values are equal");
    }
  } else {
    debugLog("Skipping owner check - not FA snapshots or missing objectOwner field", {
      prevHasOwner: "objectOwner" in prev.identity,
      currHasOwner: "objectOwner" in curr.identity,
    });
  }
  
  // Check admin changes (Coin only)
  debugLog("Checking capabilities for admin changes");
  if ("hasFreezeCap" in prev.capabilities && "hasFreezeCap" in curr.capabilities) {
    // This is a coin snapshot - check admin if available
    const prevCaps = prev.capabilities as CoinCapabilities;
    const currCaps = curr.capabilities as CoinCapabilities;
    // Note: Admin is stored in capabilities but we need to check if it changed
    // For now, we'll check capabilities as a whole
  }
  
  // Check capabilities changes (compare all capability fields)
  debugLog("Checking capabilities");
  const prevCapsStr = JSON.stringify(prev.capabilities);
  const currCapsStr = JSON.stringify(curr.capabilities);
  if (prevCapsStr !== currCapsStr) {
    debugLog("CAPABILITIES_CHANGED detected");
    // Determine which capabilities changed
    const changedFields: string[] = [];
    let hasMintRefAppeared = false;
    let hasBurnRefAppeared = false;
    let hasMintCapAppeared = false;
    let hasFreezeCapAppeared = false;
    
    // Compare capabilities field by field
    if ("hasMintCap" in prev.capabilities && "hasMintCap" in curr.capabilities) {
      // Coin capabilities
      const prevCoin = prev.capabilities as CoinCapabilities;
      const currCoin = curr.capabilities as CoinCapabilities;
      if (prevCoin.hasMintCap !== currCoin.hasMintCap) {
        changedFields.push("hasMintCap");
        if (!prevCoin.hasMintCap && currCoin.hasMintCap) hasMintCapAppeared = true;
      }
      if (prevCoin.hasBurnCap !== currCoin.hasBurnCap) changedFields.push("hasBurnCap");
      if (prevCoin.hasFreezeCap !== currCoin.hasFreezeCap) {
        changedFields.push("hasFreezeCap");
        if (!prevCoin.hasFreezeCap && currCoin.hasFreezeCap) hasFreezeCapAppeared = true;
      }
      if (prevCoin.hasTransferRestrictions !== currCoin.hasTransferRestrictions) changedFields.push("hasTransferRestrictions");
    } else if ("hasMintRef" in prev.capabilities && "hasMintRef" in curr.capabilities) {
      // FA capabilities
      const prevFA = prev.capabilities as FACapabilities;
      const currFA = curr.capabilities as FACapabilities;
      if (prevFA.hasMintRef !== currFA.hasMintRef) {
        changedFields.push("hasMintRef");
        if (!prevFA.hasMintRef && currFA.hasMintRef) hasMintRefAppeared = true;
      }
      if (prevFA.hasBurnRef !== currFA.hasBurnRef) {
        changedFields.push("hasBurnRef");
        if (!prevFA.hasBurnRef && currFA.hasBurnRef) hasBurnRefAppeared = true;
      }
      if (prevFA.hasTransferRef !== currFA.hasTransferRef) changedFields.push("hasTransferRef");
      if (prevFA.hasDepositHook !== currFA.hasDepositHook) changedFields.push("hasDepositHook");
      if (prevFA.hasWithdrawHook !== currFA.hasWithdrawHook) changedFields.push("hasWithdrawHook");
      if (prevFA.hasDerivedBalanceHook !== currFA.hasDerivedBalanceHook) changedFields.push("hasDerivedBalanceHook");
    }
    
    // Determine severity: high if MintRef/BurnRef appears (FA) or MintCap/FreezeCap appears (Coin)
    const severity = (hasMintRefAppeared || hasBurnRefAppeared || hasMintCapAppeared || hasFreezeCapAppeared) 
      ? "high" 
      : "medium";
    
    changes.push({
      type: "CAPABILITIES_CHANGED",
      severity,
      before: prev.capabilities,
      after: curr.capabilities,
      evidence: {
        changed_fields: changedFields,
        mintRefAppeared: hasMintRefAppeared,
        burnRefAppeared: hasBurnRefAppeared,
        mintCapAppeared: hasMintCapAppeared,
        freezeCapAppeared: hasFreezeCapAppeared,
      },
    });
    
    // Check for PRIVILEGE_ESCALATION (capabilities that appeared: false -> true)
    const appearedCapabilities: string[] = [];
    if (hasMintRefAppeared) appearedCapabilities.push("hasMintRef");
    if (hasMintCapAppeared) appearedCapabilities.push("hasMintCap");
    
    // Check for withdraw hook appearance (FA only)
    let hasWithdrawHookAppeared = false;
    let hasFreezeCapAppearedForEscalation = false;
    let hasTransferRestrictionsAppeared = false;
    let hasTransferRefAppeared = false;
    
    if ("hasWithdrawHook" in prev.capabilities && "hasWithdrawHook" in curr.capabilities) {
      const prevFA = prev.capabilities as FACapabilities;
      const currFA = curr.capabilities as FACapabilities;
      if (!prevFA.hasWithdrawHook && currFA.hasWithdrawHook) {
        hasWithdrawHookAppeared = true;
        appearedCapabilities.push("hasWithdrawHook");
      }
      if (!prevFA.hasTransferRef && currFA.hasTransferRef) {
        hasTransferRefAppeared = true;
        appearedCapabilities.push("hasTransferRef");
      }
    }
    
    if ("hasFreezeCap" in prev.capabilities && "hasFreezeCap" in curr.capabilities) {
      const prevCoin = prev.capabilities as CoinCapabilities;
      const currCoin = curr.capabilities as CoinCapabilities;
      if (!prevCoin.hasFreezeCap && currCoin.hasFreezeCap) {
        hasFreezeCapAppearedForEscalation = true;
        appearedCapabilities.push("hasFreezeCap");
      }
      if (!prevCoin.hasTransferRestrictions && currCoin.hasTransferRestrictions) {
        hasTransferRestrictionsAppeared = true;
        appearedCapabilities.push("hasTransferRestrictions");
      }
    }
    
    // Prioritize escalation reasons: mint > withdraw > freeze > transfer restrictions/ref
    if (appearedCapabilities.length > 0) {
      // Sort by priority
      const priorityOrder = ["hasMintRef", "hasMintCap", "hasWithdrawHook", "hasFreezeCap", "hasTransferRestrictions", "hasTransferRef"];
      appearedCapabilities.sort((a, b) => {
        const aIdx = priorityOrder.indexOf(a);
        const bIdx = priorityOrder.indexOf(b);
        return (aIdx === -1 ? 999 : aIdx) - (bIdx === -1 ? 999 : bIdx);
      });
      
      changes.push({
        type: "PRIVILEGE_ESCALATION",
        severity: "high",
        before: false,
        after: true,
        evidence: {
          appeared: appearedCapabilities,
        },
      });
    }
  } else {
    debugLog("CAPABILITIES_CHANGED NOT detected - capabilities are equal");
  }
  
  // Check hooks changes (FA only)
  debugLog("Checking control_surface.hookModules");
  if ("hookModules" in prev.control_surface && "hookModules" in curr.control_surface) {
    const prevSurface = prev.control_surface as FAControlSurface;
    const currSurface = curr.control_surface as FAControlSurface;
    
    // Sort hooks for comparison (deep copy to avoid mutating)
    const prevHooksSorted = [...prevSurface.hookModules].sort((a, b) => {
      const aStr = `${a.module_address}::${a.module_name}::${a.function_name}`;
      const bStr = `${b.module_address}::${b.module_name}::${b.function_name}`;
      return aStr.localeCompare(bStr);
    });
    const currHooksSorted = [...currSurface.hookModules].sort((a, b) => {
      const aStr = `${a.module_address}::${a.module_name}::${a.function_name}`;
      const bStr = `${b.module_address}::${b.module_name}::${b.function_name}`;
      return aStr.localeCompare(bStr);
    });
    
    const prevHooks = JSON.stringify(prevHooksSorted);
    const currHooks = JSON.stringify(currHooksSorted);
    debugLog("hookModules comparison", {
      prevCount: prevSurface.hookModules.length,
      currCount: currSurface.hookModules.length,
      prevHooks: prevHooksSorted,
      currHooks: currHooksSorted,
    });
    if (prevHooks !== currHooks) {
      debugLog("HOOKS_CHANGED detected");
      const added = currHooksSorted.filter(
        (h) => !prevHooksSorted.some(
          (ph) => ph.module_address === h.module_address &&
                   ph.module_name === h.module_name &&
                   ph.function_name === h.function_name
        )
      );
      const removed = prevHooksSorted.filter(
        (h) => !currHooksSorted.some(
          (ch) => ch.module_address === h.module_address &&
                   ch.module_name === h.module_name &&
                   ch.function_name === h.function_name
        )
      );
      
      debugLog("HOOKS_CHANGED details", {
        addedCount: added.length,
        removedCount: removed.length,
        added,
        removed,
      });
      
      // Determine severity based on hook function names
      let severity: Severity = "medium";
      const allChangedHooks = [...added, ...removed];
      for (const hook of allChangedHooks) {
        const fnName = (hook.function_name || "").toLowerCase();
        if (fnName.includes("withdraw")) {
          severity = "high";
          break; // Highest priority
        } else if (fnName.includes("transfer") && severity !== "high") {
          severity = "high";
        } else if (fnName.includes("deposit") && severity === "medium") {
          // Keep medium for deposit-only changes
        }
      }
      
      changes.push({
        type: "HOOKS_CHANGED",
        severity,
        before: prevSurface.hookModules,
        after: currSurface.hookModules,
        evidence: {
          added,
          removed,
        },
      });
    } else {
      debugLog("HOOKS_CHANGED NOT detected - hook lists are equal");
    }
  } else {
    debugLog("Skipping hooks check - not FA snapshots or missing hookModules field");
  }
  
  // Check hook module code hash changes (FA only)
  if (prev.identity && "faAddress" in prev.identity && curr.identity && "faAddress" in curr.identity) {
    const prevSurface = prev.control_surface as FAControlSurface;
    const currSurface = curr.control_surface as FAControlSurface;
    const prevPins = prevSurface.hookModulePins || [];
    const currPins = currSurface.hookModulePins || [];
    
    if (prevPins.length > 0 || currPins.length > 0) {
      // Check for hash changes
      const changedModules: Array<{ moduleId: string; prevHash: string | null; currHash: string | null }> = [];
      const pinMap = new Map<string, typeof prevPins[0]>();
      
      // Build map of previous pins
      for (const pin of prevPins) {
        pinMap.set(pin.moduleId, pin);
      }
      
      // Check current pins for changes
      for (const currPin of currPins) {
        const prevPin = pinMap.get(currPin.moduleId);
        if (prevPin) {
          if (prevPin.codeHash !== currPin.codeHash) {
            changedModules.push({
              moduleId: currPin.moduleId,
              prevHash: prevPin.codeHash,
              currHash: currPin.codeHash,
            });
          }
        }
      }
      
      // Also check for removed modules (hash changed from something to null)
      for (const prevPin of prevPins) {
        if (!currPins.find(p => p.moduleId === prevPin.moduleId)) {
          if (prevPin.codeHash !== null) {
            changedModules.push({
              moduleId: prevPin.moduleId,
              prevHash: prevPin.codeHash,
              currHash: null,
            });
          }
        }
      }
      
      // Check aggregate hash
      const prevAggregate = prev.hashes.hookModulesSurfaceHash;
      const currAggregate = curr.hashes.hookModulesSurfaceHash;
      const aggregateChanged = prevAggregate !== undefined && currAggregate !== undefined && prevAggregate !== currAggregate;
      
      if (changedModules.length > 0 || aggregateChanged) {
        debugLog("HOOK_MODULE_CODE_CHANGED detected", {
          changedModulesCount: changedModules.length,
          aggregateChanged,
        });
        
        changes.push({
          type: "HOOK_MODULE_CODE_CHANGED",
          severity: "high",
          before: prevPins,
          after: currPins,
          evidence: {
            changed_modules: changedModules,
            prev_aggregate_hash: prevAggregate,
            curr_aggregate_hash: currAggregate,
          },
        });
      }
    }
  }
  
  // Check coin module code hash changes (COIN only)
  if (prev.identity && "coinType" in prev.identity && curr.identity && "coinType" in curr.identity) {
    const prevSurface = prev.control_surface as import("./types.js").CoinControlSurface;
    const currSurface = curr.control_surface as import("./types.js").CoinControlSurface;
    const prevPins = prevSurface.modulePins || [];
    const currPins = currSurface.modulePins || [];
    
    if (prevPins.length > 0 || currPins.length > 0) {
      // Check for hash changes
      const changedModules: Array<{ moduleId: string; prevHash: string | null; currHash: string | null; role?: string }> = [];
      const pinMap = new Map<string, typeof prevPins[0]>();
      
      // Build map of previous pins
      for (const pin of prevPins) {
        pinMap.set(pin.moduleId, pin);
      }
      
      // Check current pins for changes
      for (const currPin of currPins) {
        const prevPin = pinMap.get(currPin.moduleId);
        if (prevPin) {
          if (prevPin.codeHash !== currPin.codeHash) {
            changedModules.push({
              moduleId: currPin.moduleId,
              prevHash: prevPin.codeHash,
              currHash: currPin.codeHash,
              role: currPin.role,
            });
          }
        }
      }
      
      // Also check for removed modules
      for (const prevPin of prevPins) {
        if (!currPins.find(p => p.moduleId === prevPin.moduleId)) {
          if (prevPin.codeHash !== null) {
            changedModules.push({
              moduleId: prevPin.moduleId,
              prevHash: prevPin.codeHash,
              currHash: null,
              role: prevPin.role,
            });
          }
        }
      }
      
      // Check aggregate hash
      const prevAggregate = prev.hashes.modulePinsHash;
      const currAggregate = curr.hashes.modulePinsHash;
      const aggregateChanged = prevAggregate !== undefined && currAggregate !== undefined && prevAggregate !== currAggregate;
      
      if (changedModules.length > 0 || aggregateChanged) {
        debugLog("COIN_MODULE_CODE_CHANGED detected", {
          changedModulesCount: changedModules.length,
          aggregateChanged,
        });
        
        changes.push({
          type: "COIN_MODULE_CODE_CHANGED",
          severity: "high",
          before: prevPins,
          after: currPins,
          evidence: {
            changed_modules: changedModules,
            prev_aggregate_hash: prevAggregate,
            curr_aggregate_hash: currAggregate,
          },
        });
      }
    }
  }
  
  // Check module additions/removals (works for both Coin and FA)
  debugLog("Checking control_surface.relevantModules");
  const prevModules = new Set(prev.control_surface.relevantModules || []);
  const currModules = new Set(curr.control_surface.relevantModules || []);
  
  debugLog("relevantModules comparison", {
    prevCount: prevModules.size,
    currCount: currModules.size,
    prevModules: Array.from(prevModules),
    currModules: Array.from(currModules),
  });
  
  const addedModules = Array.from(currModules).filter((m) => !prevModules.has(m));
  const removedModules = Array.from(prevModules).filter((m) => !currModules.has(m));
  
  if (addedModules.length > 0) {
    debugLog("MODULE_ADDED detected", { 
      count: addedModules.length,
      modules: addedModules 
    });
    changes.push({
      type: "MODULE_ADDED",
      severity: "high",
      before: null,
      after: addedModules,
      evidence: {
        modules: addedModules,
        count: addedModules.length,
      },
    });
  } else {
    debugLog("MODULE_ADDED NOT detected - no new modules");
  }
  
  if (removedModules.length > 0) {
    debugLog("MODULE_REMOVED detected", { 
      count: removedModules.length,
      modules: removedModules 
    });
    changes.push({
      type: "MODULE_REMOVED",
      severity: "high",
      before: removedModules,
      after: null,
      evidence: {
        modules: removedModules,
        count: removedModules.length,
      },
    });
  } else {
    debugLog("MODULE_REMOVED NOT detected - no removed modules");
  }
  
  // Check ABI surface changes
  // Strategy: Always do array comparison (reliable), use hashes as fast path optimization
  // This catches cases where hashes are missing or incorrect (e.g., manual snapshot edits)
  debugLog("Checking ABI surface changes");
  
  // Fast path check: if hashes match and exist, we can skip (but still verify one module as sanity check)
  const hashesExist = prev.hashes.overallSurfaceHash && curr.hashes.overallSurfaceHash;
  const hashesMatch = prev.hashes.overallSurfaceHash === curr.hashes.overallSurfaceHash;
  
  const prevModuleIds = new Set(Object.keys(prev.control_surface.modules));
  const currModuleIds = new Set(Object.keys(curr.control_surface.modules));
  const allModuleIds = new Set([
    ...Array.from(prevModuleIds),
    ...Array.from(currModuleIds),
  ]);
  
  // Check for modules added/removed from modules map
  const addedModuleIds = Array.from(currModuleIds).filter((id) => !prevModuleIds.has(id));
  const removedModuleIds = Array.from(prevModuleIds).filter((id) => !currModuleIds.has(id));
  
  const moduleChanges: Array<{
    moduleId: string;
    addedEntryFns: string[];
    removedEntryFns: string[];
    addedExposedFns: string[];
    removedExposedFns: string[];
    beforeHash?: string;
    afterHash?: string;
  }> = [];
  
  // Always do array comparison for all modules (reliable even if hashes are wrong)
  // This ensures we catch manual edits to snapshot files
  for (const moduleId of allModuleIds) {
    const prevMod = prev.control_surface.modules[moduleId];
    const currMod = curr.control_surface.modules[moduleId];
    
    // Handle module added/removed
    if (!prevMod && currMod) {
      // New module added
      debugLog(`Module ${moduleId} added to modules map`);
      moduleChanges.push({
        moduleId,
        addedEntryFns: (currMod.entry_fn_names || []).slice().sort(),
        removedEntryFns: [],
        addedExposedFns: (currMod.exposed_fn_names || []).slice().sort(),
        removedExposedFns: [],
        beforeHash: undefined,
        afterHash: curr.hashes.moduleSurfaceHash[moduleId],
      });
      continue;
    } else if (prevMod && !currMod) {
      // Module removed
      debugLog(`Module ${moduleId} removed from modules map`);
      moduleChanges.push({
        moduleId,
        addedEntryFns: [],
        removedEntryFns: (prevMod.entry_fn_names || []).slice().sort(),
        addedExposedFns: [],
        removedExposedFns: (prevMod.exposed_fn_names || []).slice().sort(),
        beforeHash: prev.hashes.moduleSurfaceHash[moduleId],
        afterHash: undefined,
      });
      continue;
    } else if (!prevMod && !currMod) {
      // Neither exists (shouldn't happen, but handle gracefully)
      continue;
    }
    
    // Both exist - compare function lists
    // Get function lists (sorted for comparison, handle undefined/null)
    const prevEntryFns = (prevMod.entry_fn_names || []).slice().sort();
    const currEntryFns = (currMod.entry_fn_names || []).slice().sort();
    const prevExposedFns = (prevMod.exposed_fn_names || []).slice().sort();
    const currExposedFns = (currMod.exposed_fn_names || []).slice().sort();
    
    // Compare arrays
    const entryFnsEqual = JSON.stringify(prevEntryFns) === JSON.stringify(currEntryFns);
    const exposedFnsEqual = JSON.stringify(prevExposedFns) === JSON.stringify(currExposedFns);
    
    if (!entryFnsEqual || !exposedFnsEqual) {
      debugLog(`Module ${moduleId} surface changed`, {
        prevEntry: prevEntryFns,
        currEntry: currEntryFns,
        prevExposed: prevExposedFns,
        currExposed: currExposedFns,
      });
      
      // Calculate added/removed
      const prevEntrySet = new Set(prevEntryFns);
      const currEntrySet = new Set(currEntryFns);
      const prevExposedSet = new Set(prevExposedFns);
      const currExposedSet = new Set(currExposedFns);
      
      const addedEntryFns = currEntryFns.filter((f) => !prevEntrySet.has(f));
      const removedEntryFns = prevEntryFns.filter((f) => !currEntrySet.has(f));
      const addedExposedFns = currExposedFns.filter((f) => !prevExposedSet.has(f));
      const removedExposedFns = prevExposedFns.filter((f) => !currExposedSet.has(f));
      
      moduleChanges.push({
        moduleId,
        addedEntryFns,
        removedEntryFns,
        addedExposedFns,
        removedExposedFns,
        beforeHash: prev.hashes.moduleSurfaceHash[moduleId],
        afterHash: curr.hashes.moduleSurfaceHash[moduleId],
      });
    } else {
      // Arrays match, but check if hash differs (might indicate hash computation issue)
      const prevHash = prev.hashes.moduleSurfaceHash[moduleId];
      const currHash = curr.hashes.moduleSurfaceHash[moduleId];
      if (prevHash && currHash && prevHash !== currHash) {
        debugLog(`Module ${moduleId} arrays match but hashes differ - hash computation issue?`, {
          prevHash,
          currHash,
        });
      }
    }
  }
  
  // Also check if hash changed (even if arrays match, hash change indicates something)
  const hashChanged = prev.hashes.overallSurfaceHash !== curr.hashes.overallSurfaceHash;
  
  // Emit ABI_SURFACE_CHANGED if any module changed OR if hash changed (but arrays don't match, indicating hash issue)
  if (moduleChanges.length > 0 || (hashChanged && moduleChanges.length === 0)) {
    debugLog("ABI_SURFACE_CHANGED detected", {
      moduleChangesCount: moduleChanges.length,
      hashChanged,
      hashMismatch: !hashesMatch,
      hashesExist,
      addedModules: addedModuleIds.length,
      removedModules: removedModuleIds.length,
    });
    
    // Check for mint-like functions in added functions ONLY (not removed)
    // Pattern: /(mint|issue|faucet|set_admin|set_minter)/ (case-insensitive)
    const mintPattern = /(mint|issue|faucet|set_admin|set_minter)/i;
    let hasMintLikeFunction = false;
    for (const change of moduleChanges) {
      // Only check added functions (entry + exposed), not removed
      const allAdded = [...change.addedEntryFns, ...change.addedExposedFns];
      if (allAdded.some((fn) => mintPattern.test(fn))) {
        hasMintLikeFunction = true;
        const matchingFn = allAdded.find((fn) => mintPattern.test(fn));
        debugLog(`Mint-like function detected in added functions: ${matchingFn}`);
        break;
      }
    }
    
    // Initial severity: default to high (rules.ts will escalate to critical if hasMintLikeFunction)
    const severity = "high";
    if (hasMintLikeFunction) {
      debugLog("Mint-like function detected in ABI changes - will be escalated to critical by rules");
    }
    
    // Format evidence per module (as specified in requirements)
    const evidenceModules = moduleChanges.map((change) => ({
      moduleId: change.moduleId,
      addedEntryFns: change.addedEntryFns,
      removedEntryFns: change.removedEntryFns,
      addedExposedFns: change.addedExposedFns,
      removedExposedFns: change.removedExposedFns,
      beforeModuleHash: change.beforeHash,
      afterModuleHash: change.afterHash,
    }));
    
    changes.push({
      type: "ABI_SURFACE_CHANGED",
      severity,
      before: {
        overallSurfaceHash: prev.hashes.overallSurfaceHash,
        moduleSurfaceHash: prev.hashes.moduleSurfaceHash,
      },
      after: {
        overallSurfaceHash: curr.hashes.overallSurfaceHash,
        moduleSurfaceHash: curr.hashes.moduleSurfaceHash,
      },
      evidence: {
        moduleChanges: evidenceModules,
        modulesAdded: addedModuleIds,
        modulesRemoved: removedModuleIds,
        hasMintLikeFunction,
      },
    });
  } else {
    if (hashesExist && !hashesMatch) {
      debugLog("ABI_SURFACE_CHANGED NOT detected - arrays match but hashes differ (hash computation issue)");
    } else {
      debugLog("ABI_SURFACE_CHANGED NOT detected - all modules unchanged");
    }
  }
  
  // Check coverage changes (works for both Coin and FA)
  debugLog("Checking coverage.coverage", {
    prev: prev.coverage.coverage,
    curr: curr.coverage.coverage,
  });
  if (prev.coverage.coverage !== curr.coverage.coverage) {
    debugLog("COVERAGE_CHANGED detected", {
      before: prev.coverage.coverage,
      after: curr.coverage.coverage,
    });
    changes.push({
      type: "COVERAGE_CHANGED",
      severity: prev.coverage.coverage === "complete" && curr.coverage.coverage === "partial" ? "high" : "info",
      before: prev.coverage.coverage,
      after: curr.coverage.coverage,
      evidence: {
        reasons_before: prev.coverage.reasons || [],
        reasons_after: curr.coverage.reasons || [],
      },
    });
  } else {
    debugLog("COVERAGE_CHANGED NOT detected - coverage status unchanged");
  }
  
  // Check findings changes
  debugLog("Checking findings");
  // First, check by ID only for FINDING_ADDED/FINDING_REMOVED
  const prevFindingIdsOnly = new Set(prev.findings.map((f) => f.id));
  const currFindingIdsOnly = new Set(curr.findings.map((f) => f.id));
  
  const addedFindingIds = curr.findings.filter((f) => !prevFindingIdsOnly.has(f.id));
  const removedFindingIds = prev.findings.filter((f) => !currFindingIdsOnly.has(f.id));
  
  // Emit FINDING_ADDED for each newly added finding ID
  for (const finding of addedFindingIds) {
    changes.push({
      type: "FINDING_ADDED",
      severity: finding.severity,
      before: null,
      after: finding.id,
      evidence: {
        id: finding.id,
        title: finding.title || null,
        severity: finding.severity,
      },
    });
  }
  
  // Emit FINDING_REMOVED for each removed finding ID
  for (const finding of removedFindingIds) {
    changes.push({
      type: "FINDING_REMOVED",
      severity: "info",
      before: finding.id,
      after: null,
      evidence: {
        id: finding.id,
        title: finding.title || null,
      },
    });
  }
  
  // Also check by id+severity for FINDINGS_CHANGED (severity escalations)
  const prevFindingKeys = new Set(prev.findings.map((f) => `${f.id}:${f.severity}`));
  const currFindingKeys = new Set(curr.findings.map((f) => `${f.id}:${f.severity}`));
  
  const newFindings = curr.findings.filter((f) => {
    const key = `${f.id}:${f.severity}`;
    return !prevFindingKeys.has(key);
  });
  const removedFindings = prev.findings.filter((f) => {
    const key = `${f.id}:${f.severity}`;
    return !currFindingKeys.has(key);
  });
  
  debugLog("findings comparison", {
    prevCount: prev.findings.length,
    currCount: curr.findings.length,
    addedIds: addedFindingIds.map(f => f.id),
    removedIds: removedFindingIds.map(f => f.id),
    newFindings: newFindings.map(f => `${f.id}:${f.severity}`),
    removedFindings: removedFindings.map(f => `${f.id}:${f.severity}`),
  });
  
  // Check severity escalations
  const severityEscalations: Array<{ id: string; before: string; after: string }> = [];
  for (const currFinding of curr.findings) {
    const prevFinding = prev.findings.find((f) => f.id === currFinding.id);
    if (prevFinding) {
      const severityOrder: Record<string, number> = {
        info: 1,
        medium: 2,
        high: 3,
        critical: 4,
      };
      if (severityOrder[currFinding.severity] > severityOrder[prevFinding.severity]) {
        severityEscalations.push({
          id: currFinding.id,
          before: prevFinding.severity,
          after: currFinding.severity,
        });
      }
    }
  }
  
  if (newFindings.length > 0 || removedFindings.length > 0 || severityEscalations.length > 0) {
    debugLog("FINDINGS_CHANGED detected");
    
    // Calculate max severity of new findings
    const severityOrder: Record<string, number> = {
      info: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    let maxSeverity: "info" | "medium" | "high" | "critical" = "info";
    for (const finding of newFindings) {
      const findingSeverity = severityOrder[finding.severity] || 0;
      const currentMax = severityOrder[maxSeverity] || 0;
      if (findingSeverity > currentMax) {
        maxSeverity = finding.severity as "info" | "medium" | "high" | "critical";
      }
    }
    // If severity escalations exist, use high (or higher if new findings are critical)
    if (severityEscalations.length > 0 && severityOrder[maxSeverity] < severityOrder.high) {
      maxSeverity = "high";
    }
    
    changes.push({
      type: "FINDINGS_CHANGED",
      severity: maxSeverity,
      before: prev.findings,
      after: curr.findings,
      evidence: {
        newFindings: newFindings,
        removedFindings: removedFindings,
        severityEscalations: severityEscalations,
        maxNewSeverity: maxSeverity,
      },
    });
  } else {
    debugLog("FINDINGS_CHANGED NOT detected - findings are equal");
  }

  // Check privileges changes
  debugLog("Checking privileges");
  const prevPrivileges = prev.privileges;
  const currPrivileges = curr.privileges;

  if (prevPrivileges || currPrivileges) {
    const prevPrivilegesStr = prevPrivileges ? JSON.stringify(prevPrivileges) : null;
    const currPrivilegesStr = currPrivileges ? JSON.stringify(currPrivileges) : null;

    if (prevPrivilegesStr !== currPrivilegesStr) {
      debugLog("PRIVILEGES_CHANGED detected");

      // Detect newly added privileges by class
      const addedPrivileges: Record<string, string[]> = {};
      const removedPrivileges: Record<string, string[]> = {};
      let opaqueControlChanged = false;

      if (prevPrivileges && currPrivileges) {
        // Compare by class
        for (const privClass of Object.keys(currPrivileges.byClass || {})) {
          const prevFns = new Set(
            (prevPrivileges.byClass[privClass] || []).map((p: any) => `${p.moduleId}::${p.fnName}`)
          );
          const currFns = new Set(
            (currPrivileges.byClass[privClass] || []).map((p: any) => `${p.moduleId}::${p.fnName}`)
          );

          const added = Array.from(currFns).filter((fn) => !prevFns.has(fn));
          const removed = Array.from(prevFns).filter((fn) => !currFns.has(fn));

          if (added.length > 0) {
            addedPrivileges[privClass] = added;
          }
          if (removed.length > 0) {
            removedPrivileges[privClass] = removed;
          }
        }

        // Check opaque control change
        if (prevPrivileges.hasOpaqueControl !== currPrivileges.hasOpaqueControl) {
          opaqueControlChanged = true;
        }
      } else if (!prevPrivileges && currPrivileges) {
        // New privileges added
        for (const privClass of Object.keys(currPrivileges.byClass || {})) {
          const fns = (currPrivileges.byClass[privClass] || []).map((p: any) => `${p.moduleId}::${p.fnName}`);
          if (fns.length > 0) {
            addedPrivileges[privClass] = fns;
          }
        }
        opaqueControlChanged = currPrivileges.hasOpaqueControl || false;
      }

      changes.push({
        type: "PRIVILEGES_CHANGED",
        severity: "high",
        before: prevPrivileges,
        after: currPrivileges,
        evidence: {
          addedPrivileges,
          removedPrivileges,
          opaqueControlChanged,
          opaqueControlBefore: prevPrivileges?.hasOpaqueControl || false,
          opaqueControlAfter: currPrivileges?.hasOpaqueControl || false,
        },
      });
    } else {
      debugLog("PRIVILEGES_CHANGED NOT detected - values are equal");
    }
  } else {
    debugLog("Skipping privileges check - neither snapshot has privileges");
  }

  // Check invariants changes
  debugLog("Checking invariants");
  const prevInvariants = prev.invariants;
  const currInvariants = curr.invariants;

  if (prevInvariants || currInvariants) {
    const prevInvariantsStr = prevInvariants ? JSON.stringify(prevInvariants) : null;
    const currInvariantsStr = currInvariants ? JSON.stringify(currInvariants) : null;

    if (prevInvariantsStr !== currInvariantsStr) {
      debugLog("INVARIANTS_CHANGED detected");

      // Detect invariant status escalations
      const statusEscalations: Array<{ id: string; before: string; after: string }> = [];
      const newViolations: string[] = [];
      const resolvedViolations: string[] = [];

      if (prevInvariants && currInvariants) {
        const prevItemsMap = new Map(prevInvariants.items.map((item) => [item.id, item]));
        const currItemsMap = new Map(currInvariants.items.map((item) => [item.id, item]));

        // Check for status changes
        for (const [id, currItem] of currItemsMap) {
          const prevItem = prevItemsMap.get(id);
          if (prevItem) {
            if (prevItem.status !== currItem.status) {
              statusEscalations.push({
                id,
                before: prevItem.status,
                after: currItem.status,
              });

              // Track violations
              if (currItem.status === "violation") {
                newViolations.push(id);
              }
              if (prevItem.status === "violation" && currItem.status !== "violation") {
                resolvedViolations.push(id);
              }
            }
          } else {
            // New invariant
            if (currItem.status === "violation") {
              newViolations.push(id);
            }
          }
        }

        // Check for removed invariants
        for (const [id, prevItem] of prevItemsMap) {
          if (!currItemsMap.has(id) && prevItem.status === "violation") {
            resolvedViolations.push(id);
          }
        }
      } else if (!prevInvariants && currInvariants) {
        // New invariants
        for (const item of currInvariants.items) {
          if (item.status === "violation") {
            newViolations.push(item.id);
          }
        }
      }

      // Check overall status change
      const overallEscalated =
        prevInvariants && currInvariants
          ? prevInvariants.overall !== currInvariants.overall
          : true;

      changes.push({
        type: "INVARIANTS_CHANGED",
        severity: newViolations.length > 0 ? "critical" : overallEscalated ? "high" : "medium",
        before: prevInvariants,
        after: currInvariants,
        evidence: {
          statusEscalations,
          newViolations,
          resolvedViolations,
          overallBefore: prevInvariants?.overall || "unknown",
          overallAfter: currInvariants?.overall || "unknown",
        },
      });
    } else {
      debugLog("INVARIANTS_CHANGED NOT detected - values are equal");
    }
  } else {
    debugLog("Skipping invariants check - neither snapshot has invariants");
  }
  
  // Sort changes by priority (critical > high > medium > info, then by type priority)
  const typePriority: Record<ChangeType, number> = {
    "SUPPLY_MAX_CHANGED": 1,
    "PRIVILEGE_ESCALATION": 2,
    "OWNER_CHANGED": 3,
    "SUPPLY_CHANGED_LARGE": 4,
    "HOOKS_CHANGED": 5,
    "HOOK_MODULE_CODE_CHANGED": 5.5,
    "COIN_MODULE_CODE_CHANGED": 5.5,
    "CAPABILITIES_CHANGED": 6,
    "ABI_SURFACE_CHANGED": 7,
    "MODULE_ADDED": 8,
    "MODULE_REMOVED": 9,
    "FINDING_ADDED": 10,
    "FINDINGS_CHANGED": 11,
    "FINDING_REMOVED": 12,
    "PRIVILEGES_CHANGED": 13,
    "INVARIANTS_CHANGED": 14,
    "COVERAGE_CHANGED": 15,
    "SUPPLY_CHANGED": 16,
    "SUPPLY_CHANGED_SMALL": 17,
    "ADMIN_CHANGED": 18,
  };
  
  const severityPriority: Record<Severity, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    info: 4,
  };
  
  changes.sort((a, b) => {
    const severityDiff = severityPriority[a.severity] - severityPriority[b.severity];
    if (severityDiff !== 0) return severityDiff;
    const typeDiff = (typePriority[a.type] || 999) - (typePriority[b.type] || 999);
    return typeDiff;
  });
  
  // Build agentHints based on detected changes
  const agentHints: AgentHints = {};
  let requiresMultiRpc = false;
  let requiresTxCorrelation = false;
  const escalationReasons: string[] = [];
  
  for (const change of changes) {
    if (change.type === "OWNER_CHANGED") {
      requiresMultiRpc = true;
      requiresTxCorrelation = true;
      escalationReasons.push("owner changed");
    } else if (change.type === "PRIVILEGE_ESCALATION") {
      requiresMultiRpc = true;
      requiresTxCorrelation = true;
      escalationReasons.push("privilege escalation");
    } else if (change.type === "HOOKS_CHANGED" && change.severity === "high") {
      // Check if withdraw/transfer hook changed
      const evidence = change.evidence as any;
      const allHooks = [...(evidence?.added || []), ...(evidence?.removed || [])];
      const hasWithdrawOrTransfer = allHooks.some((h: any) => {
        const fnName = (h.function_name || "").toLowerCase();
        return fnName.includes("withdraw") || fnName.includes("transfer");
      });
      if (hasWithdrawOrTransfer) {
        requiresMultiRpc = true;
        requiresTxCorrelation = true;
        escalationReasons.push("withdraw/transfer hook changed");
      }
    } else if (change.type === "SUPPLY_CHANGED_LARGE") {
      requiresMultiRpc = true;
      requiresTxCorrelation = false;
      escalationReasons.push("large supply change");
    }
  }
  
  if (requiresMultiRpc || requiresTxCorrelation || escalationReasons.length > 0) {
    agentHints.requiresMultiRpc = requiresMultiRpc;
    agentHints.requiresTxCorrelation = requiresTxCorrelation;
    if (escalationReasons.length > 0) {
      agentHints.escalationReason = escalationReasons.join("; ");
    }
  }
  
  debugLog("Diff complete", {
    totalChanges: changes.length,
    changeTypes: changes.map(c => c.type),
    agentHints,
  });
  
  // Add debug summary fields (stderr only, never in JSON)
  if (DEBUG_DIFF) {
    const prevSummary = {
      type: "objectOwner" in prev.identity ? "FA" : "Coin",
      supply: prev.supply.supplyCurrentBase,
      capabilities: Object.keys(prev.capabilities).filter(k => (prev.capabilities as any)[k] === true),
      modules: prev.control_surface.relevantModules.length,
      findings: prev.findings.length,
    };
    const currSummary = {
      type: "objectOwner" in curr.identity ? "FA" : "Coin",
      supply: curr.supply.supplyCurrentBase,
      capabilities: Object.keys(curr.capabilities).filter(k => (curr.capabilities as any)[k] === true),
      modules: curr.control_surface.relevantModules.length,
      findings: curr.findings.length,
    };
    console.error("[DIFF DEBUG] prevSummary:", JSON.stringify(prevSummary, null, 2));
    console.error("[DIFF DEBUG] currSummary:", JSON.stringify(currSummary, null, 2));
  }
  
  const result: DiffResult = {
    changed: changes.length > 0,
    changes,
  };
  
  if (Object.keys(agentHints).length > 0) {
    result.agentHints = agentHints;
  }
  
  return result;
}


// src/analyzers/shared/privilegeModel.ts

export enum PrivilegeClass {
  MINT = "MINT",
  BURN = "BURN",
  FREEZE_RESTRICT = "FREEZE_RESTRICT",
  ADMIN_OWNERSHIP = "ADMIN_OWNERSHIP",
  UPGRADE_PUBLISH = "UPGRADE_PUBLISH",
  METADATA_MUTATION = "METADATA_MUTATION",
  HOOK_CONFIG = "HOOK_CONFIG",
  UNKNOWN_PRIVILEGE = "UNKNOWN_PRIVILEGE",
}

export interface PrivilegeFinding {
  class: PrivilegeClass;
  fnName: string;
  moduleId: string;
  evidence?: any;
}

export interface PrivilegeReport {
  byClass: Record<PrivilegeClass, PrivilegeFinding[]>;
  all: PrivilegeFinding[];
  hasOpaqueControl: boolean;
}

/**
 * Extract privileges from ABI based on function names and ABI hints
 */
export function extractPrivilegesFromAbi(
  abi: any,
  moduleId: string,
  entryFunctions: string[],
  exposedFunctions: string[]
): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];
  const allFunctions = [...new Set([...entryFunctions, ...exposedFunctions])];

  // MINT patterns
  const mintPattern = /\b(mint|issue|create|increase_supply|emit|mint_to|faucet)\b/i;
  // BURN patterns
  const burnPattern = /\b(burn|destroy|burn_from|decrease_supply)\b/i;
  // FREEZE_RESTRICT patterns
  const freezePattern = /\b(freeze|pause|blacklist|deny|restrict|whitelist|lock|unfreeze|disable|enable)\b/i;
  // ADMIN_OWNERSHIP patterns
  const adminPattern = /\b(set_admin|set_owner|transfer_ownership|rotate|set_operator|set_authority)\b/i;
  // UPGRADE_PUBLISH patterns
  const upgradePattern = /\b(upgrade|migrate|publish|deploy|update_module|set_code)\b/i;
  // METADATA_MUTATION patterns
  const metadataPattern = /\b(set_name|set_symbol|set_decimals|set_uri|set_icon|set_metadata|update_metadata|change_metadata)\b/i;
  // HOOK_CONFIG patterns
  const hookPattern = /\b(set_hook|set_dispatch|dispatch|route|configure|update|set_config|set_router|register_hook|unregister_hook)\b/i;

  for (const fnName of allFunctions) {
    let privilegeClass: PrivilegeClass | null = null;

    if (mintPattern.test(fnName)) {
      privilegeClass = PrivilegeClass.MINT;
    } else if (burnPattern.test(fnName)) {
      privilegeClass = PrivilegeClass.BURN;
    } else if (freezePattern.test(fnName)) {
      privilegeClass = PrivilegeClass.FREEZE_RESTRICT;
    } else if (adminPattern.test(fnName)) {
      privilegeClass = PrivilegeClass.ADMIN_OWNERSHIP;
    } else if (upgradePattern.test(fnName)) {
      privilegeClass = PrivilegeClass.UPGRADE_PUBLISH;
    } else if (metadataPattern.test(fnName)) {
      privilegeClass = PrivilegeClass.METADATA_MUTATION;
    } else if (hookPattern.test(fnName)) {
      privilegeClass = PrivilegeClass.HOOK_CONFIG;
    }

    if (privilegeClass) {
      findings.push({
        class: privilegeClass,
        fnName,
        moduleId,
        evidence: {
          isEntry: entryFunctions.includes(fnName),
          isExposed: exposedFunctions.includes(fnName),
        },
      });
    }
  }

  return findings;
}

/**
 * Merge multiple privilege reports into one
 */
export function mergePrivilegeReports(reports: PrivilegeReport[]): PrivilegeReport {
  const merged: PrivilegeReport = {
    byClass: {
      [PrivilegeClass.MINT]: [],
      [PrivilegeClass.BURN]: [],
      [PrivilegeClass.FREEZE_RESTRICT]: [],
      [PrivilegeClass.ADMIN_OWNERSHIP]: [],
      [PrivilegeClass.UPGRADE_PUBLISH]: [],
      [PrivilegeClass.METADATA_MUTATION]: [],
      [PrivilegeClass.HOOK_CONFIG]: [],
      [PrivilegeClass.UNKNOWN_PRIVILEGE]: [],
    },
    all: [],
    hasOpaqueControl: false,
  };

  for (const report of reports) {
    for (const finding of report.all) {
      merged.byClass[finding.class].push(finding);
      merged.all.push(finding);
    }
    if (report.hasOpaqueControl) {
      merged.hasOpaqueControl = true;
    }
  }

  return merged;
}

/**
 * Create an empty privilege report
 */
export function createEmptyPrivilegeReport(): PrivilegeReport {
  return {
    byClass: {
      [PrivilegeClass.MINT]: [],
      [PrivilegeClass.BURN]: [],
      [PrivilegeClass.FREEZE_RESTRICT]: [],
      [PrivilegeClass.ADMIN_OWNERSHIP]: [],
      [PrivilegeClass.UPGRADE_PUBLISH]: [],
      [PrivilegeClass.METADATA_MUTATION]: [],
      [PrivilegeClass.HOOK_CONFIG]: [],
      [PrivilegeClass.UNKNOWN_PRIVILEGE]: [],
    },
    all: [],
    hasOpaqueControl: false,
  };
}


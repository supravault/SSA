import type { ModuleId } from "../core/types.js";

/**
 * Validate Move module address format (0x followed by hex)
 */
export function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]+$/.test(address) && address.length >= 3;
}

/**
 * Validate module name format (alphanumeric + underscores)
 */
export function isValidModuleName(name: string): boolean {
  return /^[a-zA-Z0-9_]+$/.test(name) && name.length > 0;
}

/**
 * Validate module ID
 */
export function validateModuleId(moduleId: ModuleId): { valid: boolean; error?: string } {
  if (!isValidAddress(moduleId.address)) {
    return { valid: false, error: `Invalid address format: ${moduleId.address}` };
  }
  if (!isValidModuleName(moduleId.module_name)) {
    return { valid: false, error: `Invalid module name format: ${moduleId.module_name}` };
  }
  return { valid: true };
}


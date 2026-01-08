// src/analyzers/shared/functionClassification.ts

export interface ClassifiedFunctions {
  mint: string[];
  burn: string[];
  admin: string[];
  freeze: string[];
  hookConfig: string[];
  upgrade: string[];
  metadata: string[];
}

/**
 * Classify entry function names into categories
 */
export function classifyEntryFunctions(entryFunctions: string[]): ClassifiedFunctions {
  const mintPattern = /\b(mint|issue|create|increase_supply|emit|mint_to|faucet)\b/i;
  const burnPattern = /\b(burn|destroy|burn_from|decrease_supply)\b/i;
  const adminPattern = /\b(set_admin|set_owner|transfer_ownership|rotate|set_operator|set_authority)\b/i;
  const freezePattern = /\b(freeze|pause|blacklist|deny|restrict|whitelist|lock|unfreeze|disable|enable)\b/i;
  const hookConfigPattern = /\b(set_hook|set_dispatch|dispatch|route|configure|update|set_config|set_router|register_hook|unregister_hook)\b/i;
  const upgradePattern = /\b(upgrade|migrate|publish|deploy|update_module|set_code)\b/i;
  const metadataPattern = /\b(set_name|set_symbol|set_decimals|set_uri|set_icon|set_metadata|update_metadata|change_metadata)\b/i;

  const classified: ClassifiedFunctions = {
    mint: [],
    burn: [],
    admin: [],
    freeze: [],
    hookConfig: [],
    upgrade: [],
    metadata: [],
  };

  for (const fn of entryFunctions) {
    if (mintPattern.test(fn)) {
      classified.mint.push(fn);
    }
    if (burnPattern.test(fn)) {
      classified.burn.push(fn);
    }
    if (adminPattern.test(fn)) {
      classified.admin.push(fn);
    }
    if (freezePattern.test(fn)) {
      classified.freeze.push(fn);
    }
    if (hookConfigPattern.test(fn)) {
      classified.hookConfig.push(fn);
    }
    if (upgradePattern.test(fn)) {
      classified.upgrade.push(fn);
    }
    if (metadataPattern.test(fn)) {
      classified.metadata.push(fn);
    }
  }

  return classified;
}


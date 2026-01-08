/**
 * Source parser for Move .move files
 * Extracts functions, access control markers, and event patterns
 * Supra/Move generic (not chain-specific)
 */

export interface ParsedSource {
  entryFunctions: string[];
  publicFunctions: string[];
  allFunctions: string[];
  gatingMarkers: string[]; // Access control patterns found
  eventMarkers: string[]; // Event emission patterns found
  strings: string[]; // Extracted string literals and identifiers
}

/**
 * Parse Move source code to extract function names and patterns
 */
export function parseMoveSource(sourceText: string): ParsedSource {
  const result: ParsedSource = {
    entryFunctions: [],
    publicFunctions: [],
    allFunctions: [],
    gatingMarkers: [],
    eventMarkers: [],
    strings: [],
  };

  // Extract entry functions: "public entry fun" or "entry fun"
  const entryFunRegex = /(?:public\s+)?entry\s+fun\s+([a-z_][a-z0-9_]*)/gi;
  const entryMatches = [...sourceText.matchAll(entryFunRegex)];
  for (const match of entryMatches) {
    if (match[1]) {
      result.entryFunctions.push(match[1]);
      result.allFunctions.push(match[1]);
    }
  }

  // Extract public functions: "public fun" (but not entry, already captured)
  const publicFunRegex = /public\s+fun\s+([a-z_][a-z0-9_]*)/gi;
  const publicMatches = [...sourceText.matchAll(publicFunRegex)];
  for (const match of publicMatches) {
    if (match[1] && !result.entryFunctions.includes(match[1])) {
      result.publicFunctions.push(match[1]);
      result.allFunctions.push(match[1]);
    }
  }

  // Extract all function definitions (including private/internal)
  const allFunRegex = /fun\s+([a-z_][a-z0-9_]*)\s*\(/gi;
  const allFunMatches = [...sourceText.matchAll(allFunRegex)];
  for (const match of allFunMatches) {
    if (match[1] && !result.allFunctions.includes(match[1])) {
      result.allFunctions.push(match[1]);
    }
  }

  // Extract gating markers / access control hints
  const gatingPatterns = [
    /\bassert!\s*\(/gi,
    /\bassert\s*\(/gi,
    /\brequire_/gi,
    /\bonly_/gi,
    /\bis_admin\b/gi,
    /\badmin\b/gi,
    /\bowner\b/gi,
    /\bcapability\b/gi,
    /\bsigner\b/gi,
    /\bborrow_global\b/gi,
    /\bexists\b/gi,
    /\bhas_capability\b/gi,
    /\bcheck_capability\b/gi,
    /\bverify_signer\b/gi,
    /\brequire_admin\b/gi,
    /\bassert_owner\b/gi,
  ];

  for (const pattern of gatingPatterns) {
    const matches = sourceText.match(pattern);
    if (matches) {
      result.gatingMarkers.push(...matches.map((m) => m.trim()));
    }
  }

  // Deduplicate gating markers
  result.gatingMarkers = [...new Set(result.gatingMarkers)];

  // Extract event emission markers
  const eventPatterns = [
    /\bevent::emit\b/gi,
    /\bemit_event\b/gi,
    /\bEventHandle\b/gi,
    /\bemit\s*\(/gi,
    /\bevent\s*\{/gi,
  ];

  for (const pattern of eventPatterns) {
    const matches = sourceText.match(pattern);
    if (matches) {
      result.eventMarkers.push(...matches.map((m) => m.trim()));
    }
  }

  // Deduplicate event markers
  result.eventMarkers = [...new Set(result.eventMarkers)];

  // Extract string literals
  const stringLiteralRegex = /"([^"\\]|\\.)*"/g;
  const stringMatches = sourceText.match(stringLiteralRegex);
  if (stringMatches) {
    result.strings.push(...stringMatches.map((m) => m.slice(1, -1))); // Remove quotes
  }

  // Extract module name and address from module declaration
  const moduleRegex = /module\s+([a-z0-9_]+)::([a-z_][a-z0-9_]*)/gi;
  const moduleMatch = sourceText.match(moduleRegex);
  if (moduleMatch) {
    result.strings.push(...moduleMatch);
  }

  // Deduplicate strings
  result.strings = [...new Set(result.strings)];

  // Deduplicate function arrays
  result.entryFunctions = [...new Set(result.entryFunctions)];
  result.publicFunctions = [...new Set(result.publicFunctions)];
  result.allFunctions = [...new Set(result.allFunctions)];

  return result;
}

/**
 * Extract module ID from source code (if present)
 */
export function extractModuleIdFromSource(sourceText: string): { address?: string; moduleName?: string } | null {
  // Try to match: module 0xADDR::MODULE_NAME
  const moduleRegex = /module\s+(0x[a-f0-9]+)::([a-z_][a-z0-9_]*)/i;
  const match = sourceText.match(moduleRegex);
  
  if (match && match[1] && match[2]) {
    return {
      address: match[1].toLowerCase(),
      moduleName: match[2],
    };
  }

  return null;
}


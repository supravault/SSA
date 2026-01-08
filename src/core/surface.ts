/**
 * Level 1: Surface Area Verification Helpers
 * Static pattern scanning for capability-like powers
 */

/**
 * Capability patterns to search for in ABI and bytecode
 */
const CAPABILITY_PATTERNS = [
  "SignerCapability",
  "Capability",
  "MintCap",
  "MintCapability",
  "BurnCap",
  "BurnCapability",
  "AdminCap",
  "OwnerCap",
];

/**
 * Scan ABI for capability patterns
 */
export function scanAbiForCapabilities(abi: any): string[] {
  const hits: string[] = [];

  if (!abi || typeof abi !== "object") {
    return hits;
  }

  // Search in structs
  if (Array.isArray(abi.structs)) {
    for (const struct of abi.structs) {
      if (struct.name) {
        const structName = String(struct.name);
        for (const pattern of CAPABILITY_PATTERNS) {
          if (structName.includes(pattern)) {
            hits.push(`${structName} (struct)`);
          }
        }
      }
      // Search in struct fields
      if (Array.isArray(struct.fields)) {
        for (const field of struct.fields) {
          if (field.type) {
            const fieldType = String(field.type);
            for (const pattern of CAPABILITY_PATTERNS) {
              if (fieldType.includes(pattern)) {
                hits.push(`${fieldType} (struct field)`);
              }
            }
          }
        }
      }
    }
  }

  // Search in exposed functions (params and return types)
  if (Array.isArray(abi.exposed_functions)) {
    for (const func of abi.exposed_functions) {
      // Check params
      if (Array.isArray(func.params)) {
        for (const param of func.params) {
          const paramType = typeof param === "string" ? param : param.type || "";
          for (const pattern of CAPABILITY_PATTERNS) {
            if (String(paramType).includes(pattern)) {
              hits.push(`${paramType} (function param)`);
            }
          }
        }
      }
      // Check return types
      if (Array.isArray(func.return)) {
        for (const ret of func.return) {
          const retType = typeof ret === "string" ? ret : ret.type || "";
          for (const pattern of CAPABILITY_PATTERNS) {
            if (String(retType).includes(pattern)) {
              hits.push(`${retType} (function return)`);
            }
          }
        }
      }
    }
  }

  return [...new Set(hits)]; // Deduplicate
}

/**
 * Scan bytecode text for capability patterns (best-effort)
 */
export function scanBytecodeForCapabilities(bytecode: string | Buffer | null): string[] {
  const hits: string[] = [];

  if (!bytecode) {
    return hits;
  }

  // Convert to string if Buffer
  let bytecodeText: string;
  if (Buffer.isBuffer(bytecode)) {
    // Extract printable ASCII strings from bytecode
    const buffer = bytecode;
    let currentString = "";
    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];
      if (byte >= 32 && byte <= 126) {
        currentString += String.fromCharCode(byte);
      } else {
        if (currentString.length >= 3) {
          for (const pattern of CAPABILITY_PATTERNS) {
            if (currentString.includes(pattern)) {
              hits.push(`${pattern} (bytecode string)`);
            }
          }
        }
        currentString = "";
      }
    }
    if (currentString.length >= 3) {
      for (const pattern of CAPABILITY_PATTERNS) {
        if (currentString.includes(pattern)) {
          hits.push(`${pattern} (bytecode string)`);
        }
      }
    }
  } else {
    bytecodeText = String(bytecode).toLowerCase();
    for (const pattern of CAPABILITY_PATTERNS) {
      if (bytecodeText.includes(pattern.toLowerCase())) {
        hits.push(`${pattern} (bytecode)`);
      }
    }
  }

  return [...new Set(hits)]; // Deduplicate
}

/**
 * Extract entry functions from ABI
 */
export function extractEntryFunctionsFromAbi(abi: any): string[] {
  const entryFunctions: string[] = [];

  if (!abi || typeof abi !== "object") {
    return entryFunctions;
  }

  if (Array.isArray(abi.exposed_functions)) {
    for (const func of abi.exposed_functions) {
      if (func.name && (func.is_entry === true || func.visibility === "public" || func.visibility === "entry")) {
        entryFunctions.push(String(func.name));
      }
    }
  }

  return entryFunctions;
}


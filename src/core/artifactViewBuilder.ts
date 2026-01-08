/**
 * Build ArtifactView from hybrid sources (view results + local artifacts)
 * Supports liveState (view results) + code (local artifacts) structure
 */

import type { ArtifactView, ModuleId } from "./types.js";
import type { LoadedArtifact } from "./artifactLoader.js";
import { extractEntryFunctions } from "../rpc/supra.js";

/**
 * Extract function names from ABI
 */
function extractFunctionNames(abi: any): string[] {
  if (!abi || typeof abi !== "object") {
    return [];
  }

  const functions: string[] = [];

  if (Array.isArray(abi.functions)) {
    for (const fn of abi.functions) {
      if (typeof fn.name === "string") {
        functions.push(fn.name);
      }
    }
  }

  if (Array.isArray(abi.entry_functions)) {
    for (const fn of abi.entry_functions) {
      if (typeof fn.name === "string") {
        functions.push(fn.name);
      }
    }
  }

  return [...new Set(functions)]; // Deduplicate
}

/**
 * Extract strings from source code (best-effort)
 */
function extractStringsFromSource(sourceText: string): string[] {
  const strings: string[] = [];
  
  // Extract string literals (basic regex)
  const stringLiteralRegex = /"([^"\\]|\\.)*"/g;
  const matches = sourceText.match(stringLiteralRegex);
  if (matches) {
    strings.push(...matches.map((m) => m.slice(1, -1))); // Remove quotes
  }

  // Extract function names (basic pattern matching)
  const functionRegex = /(?:public\s+)?(?:entry\s+)?fun\s+([a-z_][a-z0-9_]*)/gi;
  const fnMatches = sourceText.matchAll(functionRegex);
  for (const match of fnMatches) {
    if (match[1]) {
      strings.push(match[1]);
    }
  }

  return strings;
}

/**
 * Build ArtifactView from hybrid sources
 */
export function buildArtifactViewHybrid(
  moduleId: ModuleId,
  viewResults: Record<string, any>,
  loadedArtifact?: LoadedArtifact | null
): ArtifactView {
  const artifactView: ArtifactView = {
    moduleId,
    bytecode: null,
    abi: null,
    functionNames: [],
    entryFunctions: [],
    strings: [],
    metadata: {},
  };

  // Load from local artifact if available
  if (loadedArtifact) {
    // Validate module ID match if source provides it
    if (loadedArtifact.moduleIdFromSource) {
      const sourceAddr = loadedArtifact.moduleIdFromSource.address.toLowerCase();
      const sourceMod = loadedArtifact.moduleIdFromSource.moduleName;
      const targetAddr = moduleId.address.toLowerCase();
      const targetMod = moduleId.module_name;

      if (sourceAddr !== targetAddr || sourceMod !== targetMod) {
        // Module ID mismatch - mark in metadata but don't fail
        artifactView.metadata = {
          ...artifactView.metadata,
          artifactMismatch: {
            source: `${sourceAddr}::${sourceMod}`,
            target: `${targetAddr}::${targetMod}`,
            warning: "Local artifact module ID does not match scan target",
          },
        };
      }
    }

    // Set ABI
    if (loadedArtifact.abi) {
      artifactView.abi = loadedArtifact.abi;
      artifactView.functionNames = extractFunctionNames(loadedArtifact.abi);
      artifactView.entryFunctions = extractEntryFunctions(loadedArtifact.abi);
    }

    // Set bytecode
    if (loadedArtifact.bytecodeBuffer) {
      artifactView.bytecode = loadedArtifact.bytecodeBuffer;
    }

    // Use parsed source if available (preferred over raw extraction)
    if (loadedArtifact.parsedSource) {
      // Merge parsed functions
      artifactView.entryFunctions.push(...loadedArtifact.parsedSource.entryFunctions);
      artifactView.functionNames.push(...loadedArtifact.parsedSource.allFunctions);
      artifactView.strings.push(...loadedArtifact.parsedSource.strings);
      
      // Add gating markers and event markers to strings for rule matching
      artifactView.strings.push(...loadedArtifact.parsedSource.gatingMarkers);
      artifactView.strings.push(...loadedArtifact.parsedSource.eventMarkers);
    } else if (loadedArtifact.sourceText) {
      // Fallback: extract strings from source
      const sourceStrings = extractStringsFromSource(loadedArtifact.sourceText);
      artifactView.strings.push(...sourceStrings);
    }

    // Extract strings from bytecode (if available)
    if (loadedArtifact.bytecodeBuffer) {
      // Basic string extraction from bytecode (printable ASCII)
      const buffer = loadedArtifact.bytecodeBuffer;
      let currentString = "";
      for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        if (byte >= 32 && byte <= 126) {
          // Printable ASCII
          currentString += String.fromCharCode(byte);
        } else {
          if (currentString.length >= 3) {
            artifactView.strings.push(currentString);
          }
          currentString = "";
        }
      }
      if (currentString.length >= 3) {
        artifactView.strings.push(currentString);
      }
    }

    artifactView.metadata = {
      ...artifactView.metadata,
      localArtifact: {
        hasSource: !!loadedArtifact.sourceText,
        hasAbi: !!loadedArtifact.abi,
        hasBytecode: !!loadedArtifact.bytecodeBuffer,
        origin: loadedArtifact.artifactOrigin,
      },
    };
  }

  // Merge with view results (if available)
  if (Object.keys(viewResults).length > 0) {
    // Extract function names from view results keys
    const viewFunctionNames = Object.keys(viewResults);
    artifactView.functionNames.push(...viewFunctionNames);
    
    // Deduplicate
    artifactView.functionNames = [...new Set(artifactView.functionNames)];

    // Infer entry functions from view function names (if not already set from ABI)
    if (artifactView.entryFunctions.length === 0) {
      artifactView.entryFunctions = viewFunctionNames.filter((fn) => 
        fn.startsWith("view_") || 
        fn.includes("_of") || 
        fn.includes("stats") ||
        fn.includes("length")
      );
    }

    // Extract strings from view results (best-effort)
    for (const [key, value] of Object.entries(viewResults)) {
      if (typeof value === "string") {
        artifactView.strings.push(value);
      } else if (typeof value === "object" && value !== null) {
        try {
          const jsonStr = JSON.stringify(value);
          const matches = jsonStr.match(/"([a-z_][a-z0-9_]*)"/gi);
          if (matches) {
            artifactView.strings.push(...matches.map((m) => m.slice(1, -1)));
          }
        } catch {
          // Ignore JSON stringify errors
        }
      }
    }

    artifactView.metadata = {
      ...artifactView.metadata,
      viewResults,
    };
  }

  // Deduplicate strings
  artifactView.strings = [...new Set(artifactView.strings)];

  return artifactView;
}


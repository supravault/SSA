import { computeArtifactHash } from "../utils/hash.js";
import type { Artifact, ModuleId } from "./types.js";
import type { LoadedArtifact } from "./artifactLoader.js";

/**
 * Build artifact object for ScanResult from view results
 */
export function buildArtifactFromViews(
  moduleId: ModuleId,
  viewResults: Record<string, any>,
  fetchMethod: "proxy" | "rpc" | "raw_rpc"
): Artifact {
  // Compute hash from view results (canonical JSON)
  const canonical = JSON.stringify({
    moduleId,
    viewResults: Object.keys(viewResults).sort().reduce((acc, key) => {
      acc[key] = viewResults[key];
      return acc;
    }, {} as Record<string, any>),
  });
  const { hash, note } = computeArtifactHash(canonical, null, null, moduleId);

  return {
    fetch_method: fetchMethod === "proxy" ? "rpc" : fetchMethod, // Normalize proxy to rpc
    bytecode_b64: undefined, // Not available via view calls
    abi_json: undefined, // Not available via view calls
    artifact_hash: hash,
    binding_note: `SHA256 hash of canonical JSON (view results + moduleId) for ${moduleId.address}::${moduleId.module_name}`,
    metadata: viewResults, // Store view results in metadata for inspection
  };
}

/**
 * Build artifact object from hybrid sources (view results + local artifacts)
 */
export function buildArtifactHybrid(
  moduleId: ModuleId,
  viewResults: Record<string, any>,
  fetchMethod: "proxy" | "rpc" | "raw_rpc",
  loadedArtifact?: LoadedArtifact | null
): Artifact {
  // If no local artifact, fall back to view-only
  if (!loadedArtifact) {
    return buildArtifactFromViews(moduleId, viewResults, fetchMethod);
  }

  // Build canonical representation including local artifacts
  const canonical: any = {
    moduleId,
  };

  // Include view results if available
  if (Object.keys(viewResults).length > 0) {
    canonical.viewResults = Object.keys(viewResults).sort().reduce((acc, key) => {
      acc[key] = viewResults[key];
      return acc;
    }, {} as Record<string, any>);
  }

  // Include local artifact components
  if (loadedArtifact.sourceText) {
    canonical.sourceText = loadedArtifact.sourceText;
  }
  if (loadedArtifact.abi) {
    canonical.abi = loadedArtifact.abi;
  }
  if (loadedArtifact.bytecodeHex) {
    canonical.bytecodeHex = loadedArtifact.bytecodeHex;
  }

  // Compute hash from canonical representation
  const canonicalStr = JSON.stringify(canonical);
  const bytecodeBuffer = loadedArtifact.bytecodeBuffer || null;
  const { hash, note } = computeArtifactHash(
    canonicalStr,
    bytecodeBuffer,
    loadedArtifact.abi || null,
    moduleId
  );

  // Build binding note
  const components = [];
  if (loadedArtifact.sourceText) components.push("source");
  if (loadedArtifact.abi) components.push("ABI");
  if (loadedArtifact.bytecodeBuffer) components.push("bytecode");
  if (Object.keys(viewResults).length > 0) components.push("view results");

  const bindingNote = `SHA256 hash of canonical representation (${components.join(" + ")}) for ${moduleId.address}::${moduleId.module_name}`;

  return {
    fetch_method: fetchMethod === "proxy" ? "rpc" : fetchMethod,
    bytecode_b64: loadedArtifact.bytecodeBuffer ? loadedArtifact.bytecodeBuffer.toString("base64") : undefined,
    abi_json: loadedArtifact.abi || undefined,
    source_text: loadedArtifact.sourceText || undefined,
    artifact_hash: hash,
    binding_note: bindingNote,
    metadata: {
      viewResults: Object.keys(viewResults).length > 0 ? viewResults : undefined,
      localArtifact: {
        hasSource: !!loadedArtifact.sourceText,
        hasAbi: !!loadedArtifact.abi,
        hasBytecode: !!loadedArtifact.bytecodeBuffer,
      },
    },
    artifact_origin: loadedArtifact.artifactOrigin,
  };
}


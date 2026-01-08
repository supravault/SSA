import { createHash } from "crypto";

/**
 * Compute SHA256 hash of input buffer or string
 */
export function sha256(input: Buffer | string): string {
  const hash = createHash("sha256");
  if (Buffer.isBuffer(input)) {
    hash.update(input);
  } else {
    hash.update(input, "utf8");
  }
  return hash.digest("hex");
}

/**
 * Compute canonical hash for artifact binding
 * Supports both bytecode-based and view-based artifacts
 */
export function computeArtifactHash(
  bytecodeOrCanonical: Buffer | string | null,
  abi: any | null,
  metadata: any | null,
  moduleId: { address: string; module_name: string }
): { hash: string; note: string } {
  // If first param is a Buffer, treat as bytecode
  if (Buffer.isBuffer(bytecodeOrCanonical)) {
    const hash = sha256(bytecodeOrCanonical);
    return {
      hash,
      note: `SHA256 hash of module bytecode for ${moduleId.address}::${moduleId.module_name}`,
    };
  }

  // If first param is a string, treat as canonical JSON
  if (typeof bytecodeOrCanonical === "string") {
    const hash = sha256(bytecodeOrCanonical);
    return {
      hash,
      note: `SHA256 hash of canonical JSON for ${moduleId.address}::${moduleId.module_name}`,
    };
  }

  // Fallback: hash canonical JSON representation
  const canonical = JSON.stringify({
    moduleId,
    abi: abi || null,
    metadata: metadata || null,
  });
  const hash = sha256(canonical);
  return {
    hash,
    note: `SHA256 hash of canonical JSON (ABI + metadata + moduleId) for ${moduleId.address}::${moduleId.module_name}`,
  };
}


/**
 * Artifact Loader for Supra IDE exports
 * Supports loading local Move source, ABI, and bytecode files
 * Also supports Supra RPC v3 bytecode fetching
 */

import fs from "fs";
import path from "path";
import { parseMoveSource, extractModuleIdFromSource } from "./sourceParser.js";
import { fetchAccountModuleV3 } from "../rpc/supraAccountsV3.js";
import { fetchModuleV1 } from "../rpc/supraAccountsV1.js";
import type { RpcClientOptions } from "../rpc/supraRpcClient.js";
import type { ModuleId } from "./types.js";

export interface LoadedArtifact {
  sourceText?: string;
  bytecodeHex?: string;
  bytecodeBuffer?: Buffer;
  abi?: any;
  parsedSource?: {
    entryFunctions: string[];
    publicFunctions: string[];
    allFunctions: string[];
    gatingMarkers: string[];
    eventMarkers: string[];
    strings: string[];
  };
  moduleIdFromSource?: {
    address: string;
    moduleName: string;
  };
  artifactOrigin: {
    kind: "supra_ide_export" | "manual" | "supra_rpc_v1" | "supra_rpc_v3";
    path: string;
  };
  onChainBytecodeFetched?: boolean;
}

export interface ArtifactComponents {
  hasSource: boolean;
  hasAbi: boolean;
  hasBytecode: boolean;
  sourcePath?: string;
  abiPath?: string;
  bytecodePath?: string;
}

/**
 * Find artifact files for a module in a directory
 */
export function findModuleArtifacts(
  artifactDir: string,
  moduleName: string
): ArtifactComponents | null {
  if (!fs.existsSync(artifactDir) || !fs.statSync(artifactDir).isDirectory()) {
    return null;
  }

  const files = getAllFiles(artifactDir);
  const moduleFiles = files.filter((f) => {
    const basename = path.basename(f, path.extname(f));
    return basename.includes(moduleName) || basename === moduleName;
  });

  if (moduleFiles.length === 0) {
    return null;
  }

  // Find source file (.move)
  const sourceFile = moduleFiles.find((f) => f.endsWith(".move"));
  
  // Find ABI file (.json)
  const abiFile = moduleFiles.find((f) => f.endsWith(".json"));
  
  // Find bytecode files (.mv, .blob, .bin)
  const bytecodeFile = moduleFiles.find((f) => 
    f.endsWith(".mv") || f.endsWith(".blob") || f.endsWith(".bin")
  );

  // Prefer exact match, then latest modified time
  const components: ArtifactComponents = {
    hasSource: !!sourceFile,
    hasAbi: !!abiFile,
    hasBytecode: !!bytecodeFile,
    sourcePath: sourceFile,
    abiPath: abiFile,
    bytecodePath: bytecodeFile,
  };

  return components;
}

/**
 * Load artifact from a single file path
 */
export function loadArtifactFromPath(filePath: string): LoadedArtifact | null {
  if (!fs.existsSync(filePath)) {
    return null;
  }

  const ext = path.extname(filePath).toLowerCase();
  const artifact: LoadedArtifact = {
    artifactOrigin: {
      kind: "manual",
      path: filePath,
    },
  };

  try {
    if (ext === ".move") {
      artifact.sourceText = fs.readFileSync(filePath, "utf-8");
      artifact.parsedSource = parseMoveSource(artifact.sourceText);
      const moduleId = extractModuleIdFromSource(artifact.sourceText);
      if (moduleId && moduleId.address && moduleId.moduleName) {
        artifact.moduleIdFromSource = {
          address: moduleId.address,
          moduleName: moduleId.moduleName,
        };
      }
    } else if (ext === ".json") {
      const content = fs.readFileSync(filePath, "utf-8");
      artifact.abi = JSON.parse(content);
    } else if (ext === ".mv" || ext === ".blob" || ext === ".bin") {
      const buffer = fs.readFileSync(filePath);
      artifact.bytecodeBuffer = buffer;
      artifact.bytecodeHex = buffer.toString("hex");
    } else {
      return null; // Unknown format
    }

    return artifact;
  } catch (error) {
    console.warn(`Failed to load artifact from ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Load artifacts from directory (best match for module)
 */
export function loadArtifactsFromDir(
  artifactDir: string,
  moduleName: string
): LoadedArtifact | null {
  const components = findModuleArtifacts(artifactDir, moduleName);
  if (!components) {
    return null;
  }

  const artifact: LoadedArtifact = {
    artifactOrigin: {
      kind: "supra_ide_export",
      path: artifactDir,
    },
  };

  try {
    // Load source
    if (components.sourcePath) {
      artifact.sourceText = fs.readFileSync(components.sourcePath, "utf-8");
    }

    // Load ABI
    if (components.abiPath) {
      const abiContent = fs.readFileSync(components.abiPath, "utf-8");
      artifact.abi = JSON.parse(abiContent);
    }

    // Load bytecode
    if (components.bytecodePath) {
      const buffer = fs.readFileSync(components.bytecodePath);
      artifact.bytecodeBuffer = buffer;
      artifact.bytecodeHex = buffer.toString("hex");
    }

    // Only return if at least one component was loaded
    if (artifact.sourceText || artifact.abi || artifact.bytecodeBuffer) {
      return artifact;
    }
  } catch (error) {
    console.warn(`Failed to load artifacts from ${artifactDir}: ${error instanceof Error ? error.message : String(error)}`);
  }

  return null;
}

/**
 * Load artifact from path or directory
 */
export function loadArtifact(
  artifactPath?: string,
  artifactDir?: string,
  moduleName?: string
): LoadedArtifact | null {
  // Try explicit path first
  if (artifactPath) {
    const loaded = loadArtifactFromPath(artifactPath);
    if (loaded) {
      return loaded;
    }
  }

  // Try directory with module name
  if (artifactDir && moduleName) {
    const loaded = loadArtifactsFromDir(artifactDir, moduleName);
    if (loaded) {
      return loaded;
    }
  }

  return null;
}

/**
 * Load artifacts using new SSA_LOCAL_* env vars
 */
export async function loadArtifactsFromEnv(
  moduleId: ModuleId,
  rpcUrl?: string
): Promise<LoadedArtifact | null> {
  const artifactDir = process.env.SSA_LOCAL_ARTIFACT_DIR;
  const sourcePath = process.env.SSA_LOCAL_SOURCE;
  const bytecodePath = process.env.SSA_LOCAL_BYTECODE;
  const abiPath = process.env.SSA_LOCAL_ABI;

  const artifact: LoadedArtifact = {
    artifactOrigin: {
      kind: "manual",
      path: "env_vars",
    },
  };

  let hasAnyArtifact = false;

  // Load source file
  if (sourcePath && fs.existsSync(sourcePath)) {
    try {
      artifact.sourceText = fs.readFileSync(sourcePath, "utf-8");
      artifact.parsedSource = parseMoveSource(artifact.sourceText);
      const moduleId = extractModuleIdFromSource(artifact.sourceText);
      if (moduleId && moduleId.address && moduleId.moduleName) {
        artifact.moduleIdFromSource = {
          address: moduleId.address,
          moduleName: moduleId.moduleName,
        };
      }
      artifact.artifactOrigin.path = sourcePath;
      hasAnyArtifact = true;
    } catch (error) {
      console.warn(`Failed to load source from ${sourcePath}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Load bytecode file
  if (bytecodePath && fs.existsSync(bytecodePath)) {
    try {
      const buffer = fs.readFileSync(bytecodePath);
      artifact.bytecodeBuffer = buffer;
      artifact.bytecodeHex = buffer.toString("hex");
      artifact.artifactOrigin.path = bytecodePath;
      hasAnyArtifact = true;
    } catch (error) {
      console.warn(`Failed to load bytecode from ${bytecodePath}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Load ABI file
  if (abiPath && fs.existsSync(abiPath)) {
    try {
      const abiContent = fs.readFileSync(abiPath, "utf-8");
      artifact.abi = JSON.parse(abiContent);
      artifact.artifactOrigin.path = abiPath;
      hasAnyArtifact = true;
    } catch (error) {
      console.warn(`Failed to load ABI from ${abiPath}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Try artifact directory
  if (artifactDir && !hasAnyArtifact) {
    const loaded = loadArtifactsFromDir(artifactDir, moduleId.module_name);
    if (loaded) {
      Object.assign(artifact, loaded);
      hasAnyArtifact = true;
    }
  }

  // Try fetching bytecode from Supra RPC v3 (optional, if no local bytecode)
  if (!artifact.bytecodeBuffer && rpcUrl) {
    try {
      // Use canonical v3-first, v2-fallback RPC client
      const rpcOptions: RpcClientOptions = {
        rpcUrl,
        timeout: 10000,
        retries: 2,
        retryDelay: 500,
      };
      
      const rpcResult = await fetchAccountModuleV3(moduleId.address, moduleId.module_name, rpcOptions);
      if (rpcResult.module) {
        const module = rpcResult.module;
        
        // Extract bytecode
        if (module.bytecode) {
          // Convert hex/base64 to buffer
          let bytecodeHex = module.bytecode;
          if (bytecodeHex.startsWith("0x")) {
            bytecodeHex = bytecodeHex.slice(2);
          }
          artifact.bytecodeBuffer = Buffer.from(bytecodeHex, "hex");
          artifact.bytecodeHex = bytecodeHex;
          artifact.artifactOrigin.kind = "supra_rpc_v3";
          artifact.artifactOrigin.path = `${rpcUrl}/rpc/v3/accounts/${moduleId.address}/modules/${moduleId.module_name}`;
          artifact.onChainBytecodeFetched = true;
          hasAnyArtifact = true;
        }
        
        // Extract ABI
        if (module.abi) {
          artifact.abi = module.abi;
          hasAnyArtifact = true;
        }
      }
    } catch (error) {
      // Silently fail - RPC v3 is optional
      console.debug(`Supra RPC v3 bytecode fetch failed (optional): ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Parse source if loaded but not parsed yet
  if (artifact.sourceText && !artifact.parsedSource) {
    artifact.parsedSource = parseMoveSource(artifact.sourceText);
    const moduleId = extractModuleIdFromSource(artifact.sourceText);
    if (moduleId && moduleId.address && moduleId.moduleName) {
      artifact.moduleIdFromSource = {
        address: moduleId.address,
        moduleName: moduleId.moduleName,
      };
    }
  }

  return hasAnyArtifact ? artifact : null;
}

/**
 * Get all files recursively from a directory
 */
function getAllFiles(dir: string): string[] {
  const files: string[] = [];
  
  if (!fs.existsSync(dir)) {
    return files;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      files.push(...getAllFiles(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}


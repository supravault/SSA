import { mkdirSync, writeFileSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import type { ScanResult } from "../core/types.js";
import { memoryStore } from "./memoryStore.js";

const DATA_DIR = join(process.cwd(), "data");

/**
 * Ensure data directory exists
 */
function ensureDataDir(): void {
  if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
  }
}

/**
 * Get file path for a request ID
 */
function getFilePath(requestId: string): string {
  return join(DATA_DIR, `${requestId}.json`);
}

/**
 * File-backed store (optional persistence)
 */
class FileStore {
  /**
   * Store a scan result (both in memory and file)
   */
  set(requestId: string, result: ScanResult): void {
    // Store in memory
    memoryStore.set(requestId, result);

    // Persist to file if PERSIST env is set
    if (process.env.PERSIST === "1") {
      try {
        ensureDataDir();
        const filePath = getFilePath(requestId);
        writeFileSync(filePath, JSON.stringify(result, null, 2), "utf-8");
      } catch (error) {
        console.error(`Failed to persist scan result ${requestId}:`, error);
      }
    }
  }

  /**
   * Get a scan result by request ID
   * Tries memory first, then file
   */
  get(requestId: string): ScanResult | undefined {
    // Try memory first
    const memResult = memoryStore.get(requestId);
    if (memResult) {
      return memResult;
    }

    // Try file if PERSIST is enabled
    if (process.env.PERSIST === "1") {
      try {
        const filePath = getFilePath(requestId);
        if (existsSync(filePath)) {
          const content = readFileSync(filePath, "utf-8");
          const result = JSON.parse(content) as ScanResult;
          // Restore to memory
          memoryStore.set(requestId, result);
          return result;
        }
      } catch (error) {
        console.error(`Failed to load scan result ${requestId} from file:`, error);
      }
    }

    return undefined;
  }

  /**
   * Check if a request ID exists
   */
  has(requestId: string): boolean {
    if (memoryStore.has(requestId)) {
      return true;
    }

    if (process.env.PERSIST === "1") {
      const filePath = getFilePath(requestId);
      return existsSync(filePath);
    }

    return false;
  }
}

export const fileStore = new FileStore();


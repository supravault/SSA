import type { ScanResult } from "../core/types.js";

/**
 * In-memory store for scan results
 */
class MemoryStore {
  private store: Map<string, ScanResult> = new Map();

  /**
   * Store a scan result
   */
  set(requestId: string, result: ScanResult): void {
    this.store.set(requestId, result);
  }

  /**
   * Get a scan result by request ID
   */
  get(requestId: string): ScanResult | undefined {
    return this.store.get(requestId);
  }

  /**
   * Check if a request ID exists
   */
  has(requestId: string): boolean {
    return this.store.has(requestId);
  }

  /**
   * Delete a scan result
   */
  delete(requestId: string): boolean {
    return this.store.delete(requestId);
  }

  /**
   * Get all stored request IDs
   */
  keys(): string[] {
    return Array.from(this.store.keys());
  }

  /**
   * Clear all stored results
   */
  clear(): void {
    this.store.clear();
  }
}

export const memoryStore = new MemoryStore();


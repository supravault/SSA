/**
 * Safe, idempotent shutdown helper for Node.js scripts
 * Ensures all async handles are properly closed before exit
 */

let cleaned = false;

/**
 * Cleanup function to ensure all async handles are closed
 * Idempotent: can be called multiple times safely
 */
export async function shutdown(exitCode: number = 0): Promise<void> {
  if (cleaned) {
    return; // Already cleaned up
  }
  cleaned = true;

  try {
    // 1. Close undici dispatcher if available (Node.js 18+ uses undici for fetch)
    try {
      // @ts-ignore - undici may not be in types, use dynamic import for ES modules
      const undiciModule = await import("undici").catch(() => null);
      if (undiciModule) {
        const undici = undiciModule as any;
        if (undici && typeof undici.getGlobalDispatcher === "function") {
          const dispatcher = undici.getGlobalDispatcher();
          if (dispatcher && typeof dispatcher.close === "function") {
            await dispatcher.close().catch(() => {});
          }
        }
      }
    } catch {
      // undici not available or already closed
    }

    // 2. Close HTTP/HTTPS agents if they exist (built-in modules, always available)
    try {
      const http = await import("http");
      const https = await import("https");
      
      // Destroy default agents to close keep-alive connections
      if (http.globalAgent) {
        http.globalAgent.destroy();
      }
      if (https.globalAgent) {
        https.globalAgent.destroy();
      }
    } catch {
      // Agents already destroyed or not available
    }

    // 3. Set exit code (don't call process.exit immediately - let event loop drain)
    process.exitCode = exitCode;

    // 4. Debug instrumentation (if enabled)
    if (process.env.SSA_DEBUG_HANDLES === "1") {
      const handles = (process as any)._getActiveHandles?.() || [];
      const requests = (process as any)._getActiveRequests?.() || [];
      
      console.error("[DEBUG] Active handles:", handles.map((h: any) => h.constructor?.name || "unknown"));
      console.error("[DEBUG] Active requests:", requests.map((r: any) => r.constructor?.name || "unknown"));
      console.error(`[DEBUG] Handle count: ${handles.length}, Request count: ${requests.length}`);
    }
  } catch (error) {
    // Ignore cleanup errors, but log in debug mode
    if (process.env.SSA_DEBUG_HANDLES === "1") {
      console.error("[DEBUG] Cleanup error:", error);
    }
  }
}

/**
 * Reset cleanup state (useful for tests)
 */
export function resetShutdown(): void {
  cleaned = false;
}


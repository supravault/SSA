const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 8787;

// Configuration
const VIEW_ALLOWLIST_FILE = process.env.VIEW_ALLOWLIST_FILE || path.join(__dirname, "view_allowlist.json");
const SUPRA_RPC_URL = process.env.SUPRA_RPC_URL || "https://rpc.supra.com";

// Middleware
app.use(express.json());
app.use(express.static("public")); // Serve static files

// ============================================================================
// ALLOWLIST MANAGEMENT
// ============================================================================

let allowlistCache = null;
let allowlistLoadTime = 0;

/**
 * Load allowlist from JSON file
 * Returns object or null if missing/invalid
 * Must not crash if file is missing or invalid
 */
function loadAllowlist() {
  try {
    if (!fs.existsSync(VIEW_ALLOWLIST_FILE)) {
      console.warn(`Allowlist file not found: ${VIEW_ALLOWLIST_FILE}`);
      return null;
    }

    const content = fs.readFileSync(VIEW_ALLOWLIST_FILE, "utf-8");
    const parsed = JSON.parse(content);

    // Validate structure: must be object with string keys and array values
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      console.error("Invalid allowlist: must be an object");
      return null;
    }

    // Validate each entry
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof key !== "string" || !Array.isArray(value)) {
        console.error(`Invalid allowlist entry: ${key} must map to an array`);
        return null;
      }
      // Validate function names are strings
      for (const fn of value) {
        if (typeof fn !== "string") {
          console.error(`Invalid function name in allowlist: ${fn} must be a string`);
          return null;
        }
      }
    }

    allowlistCache = parsed;
    allowlistLoadTime = Date.now();
    console.log(`Allowlist loaded: ${Object.keys(parsed).length} modules`);
    return parsed;
  } catch (error) {
    console.error(`Error loading allowlist: ${error.message}`);
    return null;
  }
}

/**
 * Check if a view function is allowed
 * @param {string} fullFn - Full function ID: "0xADDR::module::function"
 * @returns {boolean} - true if allowed, false otherwise
 */
function isAllowedView(fullFn) {
  // Reload allowlist if cache is empty or file was modified
  const stats = fs.existsSync(VIEW_ALLOWLIST_FILE) ? fs.statSync(VIEW_ALLOWLIST_FILE) : null;
  if (!allowlistCache || (stats && stats.mtimeMs > allowlistLoadTime)) {
    loadAllowlist();
  }

  // Deny if allowlist is missing or invalid
  if (!allowlistCache) {
    return false;
  }

  // Parse fullFn: "0xADDR::module::function"
  const parts = fullFn.split("::");
  if (parts.length !== 3) {
    return false;
  }

  const [addr, moduleName, functionName] = parts;

  // Validate address format (0x followed by hex)
  if (!/^0x[0-9a-fA-F]+$/.test(addr)) {
    return false;
  }

  // Form key: "<addrLower>::<moduleName>"
  const key = `${addr.toLowerCase()}::${moduleName}`;

  // Check if module exists in allowlist
  const allowedFunctions = allowlistCache[key];
  if (!allowedFunctions) {
    return false;
  }

  // Check if function is in allowed list
  return allowedFunctions.includes(functionName);
}

// Load allowlist on startup
loadAllowlist();

// ============================================================================
// SUPRA RPC HELPERS
// ============================================================================

/**
 * Call Supra RPC view endpoint
 * @param {string} functionId - Full function ID: "0xADDR::module::function"
 * @param {string[]} args - Function arguments
 * @returns {Promise<{ok: boolean, result?: any, error?: string}>}
 */
async function callSupraView(functionId, args = []) {
  try {
    const response = await fetch(`${SUPRA_RPC_URL}/rpc/v1/view`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        function: functionId,
        type_arguments: [],
        arguments: args,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return {
        ok: false,
        error: `RPC error (${response.status}): ${errorText}`,
      };
    }

    const result = await response.json();
    return {
      ok: true,
      result: result,
    };
  } catch (error) {
    return {
      ok: false,
      error: error.message || String(error),
    };
  }
}

// ============================================================================
// API ENDPOINTS
// ============================================================================

/**
 * GET /api/health
 * Health check endpoint
 */
app.get("/api/health", (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

/**
 * GET /api/allowlist
 * Debug endpoint: returns allowlist keys and count (not full contents)
 */
app.get("/api/allowlist", (req, res) => {
  if (!allowlistCache) {
    return res.json({
      ok: false,
      error: "Allowlist not loaded",
    });
  }

  const keys = Object.keys(allowlistCache);
  const counts = {};
  for (const key of keys) {
    counts[key] = allowlistCache[key].length;
  }

  res.json({
    ok: true,
    keys: keys,
    count: keys.length,
    function_counts: counts,
  });
});

/**
 * GET /api/view
 * Proxy Supra RPC view call with allowlist validation
 * Query params:
 *   - fn: Full function ID (required): "0xADDR::module::function"
 *   - args: Comma-separated arguments (optional)
 */
app.get("/api/view", async (req, res) => {
  try {
    const { fn, args } = req.query;

    if (!fn || typeof fn !== "string") {
      return res.status(400).json({
        ok: false,
        error: "Missing required parameter: fn",
      });
    }

    // Validate function is allowed
    if (!isAllowedView(fn)) {
      return res.status(403).json({
        ok: false,
        error: "Function not allowed",
      });
    }

    // Parse arguments (comma-separated string or array, optional)
    let argsArray = [];
    if (args) {
      if (Array.isArray(args)) {
        argsArray = args;
      } else if (typeof args === "string") {
        // Handle comma-separated string, trim whitespace
        argsArray = args.split(",").map((a) => a.trim()).filter((a) => a.length > 0);
      }
    }

    // Call Supra RPC
    const rpcResult = await callSupraView(fn, argsArray);

    if (!rpcResult.ok) {
      return res.status(500).json({
        ok: false,
        error: rpcResult.error,
      });
    }

    res.json({
      ok: true,
      result: rpcResult.result,
    });
  } catch (error) {
    console.error("View endpoint error:", error);
    res.status(500).json({
      ok: false,
      error: error.message || String(error),
    });
  }
});

/**
 * POST /api/view/batch
 * Batch view calls with allowlist validation
 * Body: { calls: [ { fn: "0xADDR::module::function", args: ["..."] }, ... ] }
 * Hard cap: max 40 calls
 */
app.post("/api/view/batch", async (req, res) => {
  try {
    const { calls } = req.body;

    if (!Array.isArray(calls)) {
      return res.status(400).json({
        ok: false,
        error: "Body must contain 'calls' array",
      });
    }

    // Hard cap at 40 calls
    if (calls.length > 40) {
      return res.status(400).json({
        ok: false,
        error: "Maximum 40 calls allowed per batch",
      });
    }

    if (calls.length === 0) {
      return res.status(400).json({
        ok: false,
        error: "Calls array cannot be empty",
      });
    }

    // Process each call sequentially
    const results = [];
    for (const call of calls) {
      const { fn, args } = call;

      if (!fn || typeof fn !== "string") {
        results.push({
          ok: false,
          fn: fn || "<missing>",
          error: "Missing or invalid 'fn' parameter",
        });
        continue;
      }

      // Validate function is allowed
      if (!isAllowedView(fn)) {
        results.push({
          ok: false,
          fn: fn,
          error: "Function not allowed",
        });
        continue;
      }

      // Parse arguments (array or comma-separated string)
      let argsArray = [];
      if (args) {
        if (Array.isArray(args)) {
          argsArray = args;
        } else if (typeof args === "string") {
          // Handle comma-separated string, trim whitespace
          argsArray = args.split(",").map((a) => a.trim()).filter((a) => a.length > 0);
        }
      }

      // Call Supra RPC (sequential to avoid overwhelming RPC)
      const rpcResult = await callSupraView(fn, argsArray);

      if (!rpcResult.ok) {
        results.push({
          ok: false,
          fn: fn,
          error: rpcResult.error,
        });
      } else {
        results.push({
          ok: true,
          fn: fn,
          result: rpcResult.result,
        });
      }
    }

    res.json({
      ok: true,
      results: results,
    });
  } catch (error) {
    console.error("Batch view endpoint error:", error);
    res.status(500).json({
      ok: false,
      error: error.message || String(error),
    });
  }
});

// ============================================================================
// LEGACY ENDPOINTS (preserve existing functionality)
// ============================================================================

// Add your existing endpoints here (quiz, leaderboard, worker health, etc.)
// Example placeholders:

/**
 * GET /api/quiz/key
 * Quiz key endpoint (preserve existing)
 */
// app.get("/api/quiz/key", (req, res) => {
//   // Your existing quiz key logic
// });

/**
 * GET /api/leaderboard
 * Leaderboard endpoint (preserve existing)
 */
// app.get("/api/leaderboard", (req, res) => {
//   // Your existing leaderboard logic
// });

/**
 * GET /api/worker/health
 * Worker health endpoint (preserve existing)
 */
// app.get("/api/worker/health", (req, res) => {
//   // Your existing worker health logic
// });

// ============================================================================
// SERVER START
// ============================================================================

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Supra RPC URL: ${SUPRA_RPC_URL}`);
  console.log(`Allowlist file: ${VIEW_ALLOWLIST_FILE}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`View endpoint: GET http://localhost:${PORT}/api/view?fn=<FULL_FN>&args=<ARGS>`);
  console.log(`Batch endpoint: POST http://localhost:${PORT}/api/view/batch`);
});


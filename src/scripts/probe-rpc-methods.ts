// src/scripts/probe-rpc-methods.ts
// Debug script to probe RPC endpoints for transaction/event methods

import { writeJsonAtomic, ensureDir } from "../agent/storage.js";
import { dirname } from "path";

interface ProbeResult {
  endpoint: string;
  method?: string;
  requestType: "GET" | "POST";
  status: "ok" | "error" | "not_found" | "timeout";
  statusCode?: number;
  summary: string;
  keys?: string[];
  arrayLengths?: Record<string, number>;
  error?: string;
}

interface ProbeResults {
  rpcUrl: string;
  timestamp: string;
  results: ProbeResult[];
}

/**
 * Summarize response data for human-readable output
 */
function summarizeResponse(data: unknown): {
  keys: string[];
  arrayLengths: Record<string, number>;
  summary: string;
} {
  const keys: string[] = [];
  const arrayLengths: Record<string, number> = {};
  let summary = "";

  if (typeof data === "object" && data !== null && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;
    keys.push(...Object.keys(obj));

    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        arrayLengths[key] = value.length;
        summary += `${key}: ${value.length} items; `;
      } else if (typeof value === "object" && value !== null) {
        const nestedKeys = Object.keys(value);
        summary += `${key}: object with ${nestedKeys.length} keys; `;
      } else if (typeof value === "string") {
        const truncated = value.length > 50 ? value.substring(0, 47) + "..." : value;
        summary += `${key}: "${truncated}"; `;
      } else {
        summary += `${key}: ${String(value)}; `;
      }
    }
  } else if (Array.isArray(data)) {
    arrayLengths["root"] = data.length;
    summary = `Array with ${data.length} items`;
  } else {
    summary = String(data);
  }

  return { keys, arrayLengths, summary: summary.trim() || "empty response" };
}

/**
 * Probe a GET endpoint
 */
async function probeGet(
  rpcUrl: string,
  endpoint: string,
  timeoutMs: number = 5000
): Promise<ProbeResult> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const fullEndpoint = `${normalizedUrl}${endpoint}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(fullEndpoint, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 404) {
        return {
          endpoint,
          requestType: "GET",
          status: "not_found",
          statusCode: 404,
          summary: "Endpoint not found (404)",
        };
      }

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        return {
          endpoint,
          requestType: "GET",
          status: "error",
          statusCode: response.status,
          summary: `HTTP ${response.status}: ${errorText.substring(0, 100)}`,
          error: errorText.substring(0, 200),
        };
      }

      const data = await response.json().catch(() => null);
      if (data === null) {
        return {
          endpoint,
          requestType: "GET",
          status: "error",
          statusCode: response.status,
          summary: "Failed to parse JSON response",
        };
      }

      const summary = summarizeResponse(data);
      return {
        endpoint,
        requestType: "GET",
        status: "ok",
        statusCode: response.status,
        summary: summary.summary,
        keys: summary.keys,
        arrayLengths: summary.arrayLengths,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("aborted") || errorMsg.includes("timeout")) {
      return {
        endpoint,
        requestType: "GET",
        status: "timeout",
        summary: "Request timeout",
        error: errorMsg,
      };
    }
    return {
      endpoint,
      requestType: "GET",
      status: "error",
      summary: `Error: ${errorMsg}`,
      error: errorMsg,
    };
  }
}

/**
 * Probe a JSON-RPC POST endpoint with a method name
 */
async function probeJsonRpc(
  rpcUrl: string,
  endpoint: string,
  method: string,
  params: any[] = [],
  timeoutMs: number = 5000
): Promise<ProbeResult> {
  const normalizedUrl = rpcUrl.replace(/\/+$/, "");
  const fullEndpoint = `${normalizedUrl}${endpoint}`;

  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method,
    params,
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(fullEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 404) {
        return {
          endpoint,
          method,
          requestType: "POST",
          status: "not_found",
          statusCode: 404,
          summary: "Endpoint not found (404)",
        };
      }

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        return {
          endpoint,
          method,
          requestType: "POST",
          status: "error",
          statusCode: response.status,
          summary: `HTTP ${response.status}: ${errorText.substring(0, 100)}`,
          error: errorText.substring(0, 200),
        };
      }

      const data = await response.json().catch(() => null);
      if (data === null) {
        return {
          endpoint,
          method,
          requestType: "POST",
          status: "error",
          statusCode: response.status,
          summary: "Failed to parse JSON response",
        };
      }

      // Type guard for JSON-RPC response
      const rpcResponse = data as { error?: { message?: string; code?: number }; result?: unknown };
      
      // Check for JSON-RPC error response
      if (rpcResponse.error) {
        return {
          endpoint,
          method,
          requestType: "POST",
          status: "error",
          statusCode: response.status,
          summary: `JSON-RPC error: ${rpcResponse.error.message || JSON.stringify(rpcResponse.error)}`,
          error: JSON.stringify(rpcResponse.error),
        };
      }

      const result = rpcResponse.result !== undefined ? rpcResponse.result : data;
      const summary = summarizeResponse(result);
      return {
        endpoint,
        method,
        requestType: "POST",
        status: "ok",
        statusCode: response.status,
        summary: summary.summary,
        keys: summary.keys,
        arrayLengths: summary.arrayLengths,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    if (errorMsg.includes("aborted") || errorMsg.includes("timeout")) {
      return {
        endpoint,
        method,
        requestType: "POST",
        status: "timeout",
        summary: "Request timeout",
        error: errorMsg,
      };
    }
    return {
      endpoint,
      method,
      requestType: "POST",
      status: "error",
      summary: `Error: ${errorMsg}`,
      error: errorMsg,
    };
  }
}

async function main(): Promise<void> {
  const rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc-mainnet.supra.com";

  console.log(`Probing RPC methods at: ${rpcUrl}`);
  console.log("");

  const results: ProbeResult[] = [];

  // Test REST-style endpoints (GET) - similar to rpc_v3
  const getEndpoints = [
    "/rpc/v3/transactions",
    "/rpc/v3/events",
    "/rpc/v3/transactions/latest",
    "/rpc/v3/events/latest",
    "/rpc/v2/transactions",
    "/rpc/v2/events",
    "/rpc/v1/transactions",
    "/rpc/v1/events",
  ];

  console.log("Testing REST-style endpoints (GET)...");
  for (const endpoint of getEndpoints) {
    process.stdout.write(`  ${endpoint}... `);
    const result = await probeGet(rpcUrl, endpoint, 5000);
    results.push(result);
    const statusIcon = result.status === "ok" ? "✓" : result.status === "not_found" ? "-" : "✗";
    console.log(`${statusIcon} ${result.statusCode || ""} ${result.summary.substring(0, 60)}`);
  }
  console.log("");

  // Test JSON-RPC endpoints (POST) - common JSON-RPC methods
  const jsonRpcEndpoints = [
    "/rpc/v1",
    "/rpc/v2",
    "/rpc/v3",
    "/rpc",
  ];

  // Candidate JSON-RPC methods for transactions/events
  const candidateMethods = [
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionCount",
    "eth_getTransactionCountByHash",
    "eth_sendRawTransaction",
    "eth_getBlockTransactionCountByNumber",
    "eth_getBlockByNumber",
    "eth_getTransactionByBlockNumberAndIndex",
    "get_transactions",
    "get_transaction",
    "get_transaction_by_hash",
    "get_transactions_by_address",
    "get_account_transactions",
    "get_transaction_count",
    "get_events",
    "get_event",
    "get_events_by_address",
    "get_account_events",
    "get_event_count",
    "query_transactions",
    "query_events",
    "list_transactions",
    "list_events",
    "supra_getTransactions",
    "supra_getTransaction",
    "supra_getEvents",
    "supra_getEvent",
    "supra_queryTransactions",
    "supra_queryEvents",
  ];

  console.log("Testing JSON-RPC endpoints (POST)...");
  for (const endpoint of jsonRpcEndpoints) {
    // Test a few key methods per endpoint to avoid too many requests
    const keyMethods = [
      "get_transactions",
      "get_transaction_by_hash",
      "get_events",
      "eth_getTransactionByHash",
    ];

    for (const method of keyMethods) {
      process.stdout.write(`  ${endpoint} method=${method}... `);
      // Try with empty params first
      const result = await probeJsonRpc(rpcUrl, endpoint, method, [], 5000);
      results.push(result);
      const statusIcon = result.status === "ok" ? "✓" : result.status === "not_found" ? "-" : "✗";
      console.log(`${statusIcon} ${result.statusCode || ""} ${result.summary.substring(0, 60)}`);
      
      // Skip remaining methods for this endpoint if it's not found
      if (result.status === "not_found" && endpoint !== "/rpc/v1") {
        break;
      }
    }
  }
  console.log("");

  // Test with a sample address (if provided or use a common one)
  const testAddress = process.env.PROBE_TEST_ADDRESS || "0x1";
  console.log(`Testing endpoints with address parameter: ${testAddress}...`);
  
  const addressEndpoints = [
    `/rpc/v3/accounts/${testAddress}/transactions`,
    `/rpc/v3/accounts/${testAddress}/events`,
    `/rpc/v2/accounts/${testAddress}/transactions`,
    `/rpc/v2/accounts/${testAddress}/events`,
  ];

  for (const endpoint of addressEndpoints) {
    process.stdout.write(`  ${endpoint}... `);
    const result = await probeGet(rpcUrl, endpoint, 5000);
    results.push(result);
    const statusIcon = result.status === "ok" ? "✓" : result.status === "not_found" ? "-" : "✗";
    console.log(`${statusIcon} ${result.statusCode || ""} ${result.summary.substring(0, 60)}`);
  }
  console.log("");

  // Compile results
  const probeResults: ProbeResults = {
    rpcUrl,
    timestamp: new Date().toISOString(),
    results,
  };

  // Write to tmp/rpc_probe.json
  const outputPath = "tmp/rpc_probe.json";
  ensureDir(dirname(outputPath));
  writeJsonAtomic(outputPath, probeResults);

  console.log(`\nResults written to: ${outputPath}`);
  console.log(`\nSummary:`);
  const okCount = results.filter(r => r.status === "ok").length;
  const errorCount = results.filter(r => r.status === "error").length;
  const notFoundCount = results.filter(r => r.status === "not_found").length;
  console.log(`  OK: ${okCount}`);
  console.log(`  Error: ${errorCount}`);
  console.log(`  Not Found: ${notFoundCount}`);
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});


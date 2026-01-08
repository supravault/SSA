// src/agent/txBehavior.test.ts
// Unit tests for transaction behavior sampling

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { normalizeV2TxResponse, normalizeV3TxResponse } from "./txBehavior.js";
import type { SampleBehaviorOptions } from "./txBehavior.js";
import { sampleRecentTxBehavior } from "./txBehavior.js";

describe("normalizeV2TxResponse", () => {
  it("handles { record: [] } -> []", () => {
    const result = normalizeV2TxResponse({ record: [] });
    expect(result).toEqual([]);
  });

  it("handles { record: [...] } -> [...]", () => {
    const txs = [{ hash: "0x1" }, { hash: "0x2" }];
    const result = normalizeV2TxResponse({ record: txs });
    expect(result).toEqual(txs);
  });

  it("handles { record: {} } -> []", () => {
    const result = normalizeV2TxResponse({ record: {} });
    expect(result).toEqual([]);
  });

  it("handles { record: null } -> []", () => {
    const result = normalizeV2TxResponse({ record: null });
    expect(result).toEqual([]);
  });

  it("handles { record: { transactions: [...] } } -> [...]", () => {
    const txs = [{ hash: "0x1" }];
    const result = normalizeV2TxResponse({ record: { transactions: txs } });
    expect(result).toEqual(txs);
  });

  it("handles { record: { data: [...] } } -> [...]", () => {
    const txs = [{ hash: "0x1" }];
    const result = normalizeV2TxResponse({ record: { data: txs } });
    expect(result).toEqual(txs);
  });
});

describe("normalizeV3TxResponse", () => {
  it("handles [] -> []", () => {
    const result = normalizeV3TxResponse([]);
    expect(result).toEqual([]);
  });

  it("handles [...] -> [...]", () => {
    const txs = [{ hash: "0x1" }, { hash: "0x2" }];
    const result = normalizeV3TxResponse(txs);
    expect(result).toEqual(txs);
  });

  it("handles { value: [], Count: 0 } -> []", () => {
    const result = normalizeV3TxResponse({ value: [], Count: 0 });
    expect(result).toEqual([]);
  });

  it("handles { value: [...] } -> [...]", () => {
    const txs = [{ hash: "0x1" }];
    const result = normalizeV3TxResponse({ value: txs, Count: 1 });
    expect(result).toEqual(txs);
  });

  it("handles non-array non-value -> []", () => {
    const result = normalizeV3TxResponse({ other: "data" });
    expect(result).toEqual([]);
  });
});

describe("preferV2 ordering", () => {
  // Mock fetch to control responses
  const originalFetch = globalThis.fetch;
  
  beforeEach(() => {
    globalThis.fetch = vi.fn() as any;
  });
  
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("preferV2=true tries v2 first", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    
    // Mock v2 success
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ record: [{ hash: "0x1" }] }),
    } as Response);

    const opts: SampleBehaviorOptions = {
      probeAddresses: ["0x" + "1".repeat(64)],
      rpcUrl: "https://rpc.test",
      preferV2: true,
      limit: 10,
      timeoutMs: 1000,
    };

    const result = await sampleRecentTxBehavior(opts);

    expect(result.attempted_sources).toEqual(["rpc_accounts_v2", "rpc_accounts_v3"]);
    expect(result.prefer_v2).toBe(true);
    expect(result.source).toBe("rpc_accounts_v2");
  });

  it("preferV2=false (default) tries v3 first", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    
    // Mock v3 success
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [{ hash: "0x1" }],
    } as Response);

    const opts: SampleBehaviorOptions = {
      probeAddresses: ["0x" + "1".repeat(64)],
      rpcUrl: "https://rpc.test",
      preferV2: false,
      limit: 10,
      timeoutMs: 1000,
    };

    const result = await sampleRecentTxBehavior(opts);

    expect(result.attempted_sources).toEqual(["rpc_accounts_v3", "rpc_accounts_v2"]);
    expect(result.prefer_v2).toBe(false);
    expect(result.source).toBe("rpc_accounts_v3");
  });
});


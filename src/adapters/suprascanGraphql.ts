// src/adapters/suprascanGraphql.ts
import { gunzipSync } from "zlib";

export type SupraScanEnv = "mainnet" | "testnet";

export interface SupraScanGraphqlOptions {
  endpoint?: string; // default: https://suprascan.io/api/graphql
  env?: SupraScanEnv; // default: mainnet
  timeoutMs?: number; // default: 12000
  headers?: Record<string, string>;
}

export interface GraphqlResponse<T> {
  data?: T;
  errors?: Array<{ message: string }>;
}

const DEFAULT_ENDPOINT = "https://suprascan.io/api/graphql";

/**
 * Normalize GraphQL endpoint URL - always use https://suprascan.io/api/graphql
 * Normalize any //api/graphql to /api/graphql to avoid 308 redirect noise
 */
function normalizeEndpoint(url?: string): string {
  // Always use default endpoint
  const base = DEFAULT_ENDPOINT;
  
  // Normalize: strip double slashes everywhere, then fix protocol separator
  // This handles cases like: https://suprascan.io//api/graphql -> https://suprascan.io/api/graphql
  // Specifically handles //api/graphql -> /api/graphql
  let normalized = base.replace(/\/+/g, "/"); // Replace all multiple slashes with single slash
  normalized = normalized.replace(/:\//, "://"); // Fix protocol separator (https:/ -> https://)
  
  return normalized;
}

/**
 * Parse operationName from GraphQL query string
 * HARs may omit operationName, so derive it by parsing the query string
 * Pattern: query\s+([A-Za-z0-9_]+)\s*\(
 * 
 * @param query - GraphQL query string
 * @returns Operation name if found, undefined otherwise
 */
function parseOperationName(query: string): string | undefined {
  if (!query || typeof query !== "string") {
    return undefined;
  }

  // Try to extract operation name from query
  // Pattern: query\s+([A-Za-z0-9_]+)\s*\(
  // Handles: query GetFaDetails(..., query GetCoinDetails(..., query AddressDetail(...
  const match = query.match(/query\s+([A-Za-z0-9_]+)\s*\(/);
  if (match && match[1]) {
    return match[1];
  }

  // Also try mutation and subscription patterns
  const mutationMatch = query.match(/mutation\s+([A-Za-z0-9_]+)\s*\(/);
  if (mutationMatch && mutationMatch[1]) {
    return mutationMatch[1];
  }

  const subscriptionMatch = query.match(/subscription\s+([A-Za-z0-9_]+)\s*\(/);
  if (subscriptionMatch && subscriptionMatch[1]) {
    return subscriptionMatch[1];
  }

  return undefined;
}

/**
 * SupraScan GraphQL Client Wrapper
 * 
 * Supports two GraphQL fetch paths from SupraScan:
 * 1. Token/FA details query (from token page): GetFaDetails, GetCoinDetails
 * 2. Address resources query (from wallet/creator page): AddressDetail
 * 
 * Endpoint: POST https://suprascan.io/api/graphql (normalized, no //api/graphql redirects)
 * Headers: content-type: application/json, accept: application/json
 * Body: { query, variables } - operationName is optional (parsed from query if present in HAR)
 * 
 * Parses operationName from query string using regex (HARs may omit it).
 * If found, includes it in request body as optional field.
 * 
 * Expected response path: data.getFaDetails, data.getCoinDetails, data.addressDetail, etc.
 * 
 * @param query - GraphQL query string
 * @param variables - Query variables
 * @param opts - Optional configuration (endpoint will always be normalized)
 * @returns GraphQL response data
 */
export async function suprascanGraphql<T>(
  query: string,
  variables: Record<string, any>,
  opts: SupraScanGraphqlOptions = {}
): Promise<T> {
  const endpoint = normalizeEndpoint(opts.endpoint);
  const timeoutMs = opts.timeoutMs ?? 12000;

  // Parse operationName from query if not provided (HARs may omit it)
  const operationName = parseOperationName(query);

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // Build request body with optional operationName
    const requestBody: { query: string; variables: Record<string, any>; operationName?: string } = {
      query,
      variables,
    };
    if (operationName) {
      requestBody.operationName = operationName;
    }

    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json",
        ...(opts.headers ?? {}),
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`SupraScan GraphQL HTTP ${res.status}: ${text.slice(0, 200)}`);
    }

    const json = (await res.json()) as GraphqlResponse<T>;

    if (json.errors?.length) {
      throw new Error(`SupraScan GraphQL errors: ${json.errors.map(e => e.message).join(" | ")}`);
    }
    if (!json.data) {
      throw new Error("SupraScan GraphQL: missing data");
    }

    return json.data;
  } finally {
    clearTimeout(t);
  }
}

// -----------------------------
// High-level helpers (additive)
// -----------------------------

export interface SupraScanAddressDetailSupra {
  resources?: string | null;
  ownerAddress?: string | null;
  decimals?: number | null;
  totalSupply?: string | number | null;
  // Allow additional fields without schema breaks
  [key: string]: any;
}

export interface SupraScanAddressDetailResult {
  isError?: boolean;
  errorType?: string | null;
  addressDetailSupra?: SupraScanAddressDetailSupra | null;
}

/**
 * Fetch SupraScan AddressDetail for an address (FA or Coin publisher address).
 * This is a minimal wrapper around `suprascanGraphql` so call sites don't need to inline queries.
 *
 * IMPORTANT: Query only fields we already use elsewhere (resources/ownerAddress/decimals/totalSupply)
 * to avoid breaking if SupraScan schema evolves.
 */
export async function fetchAddressDetailSupra(
  address: string,
  env: SupraScanEnv = "mainnet",
  opts: SupraScanGraphqlOptions = {}
): Promise<SupraScanAddressDetailResult | null> {
  const ADDRESS_DETAIL_QUERY = `
    query AddressDetail(
      $address: String,
      $blockchainEnvironment: BlockchainEnvironment,
      $isAddressName: Boolean
    ) {
      addressDetail(
        address: $address,
        blockchainEnvironment: $blockchainEnvironment,
        isAddressName: $isAddressName
      ) {
        isError
        errorType
        addressDetailSupra {
          resources
          ownerAddress
          decimals
          totalSupply
        }
      }
    }
  `;

  const data = await suprascanGraphql<{
    addressDetail: SupraScanAddressDetailResult | null;
  }>(
    ADDRESS_DETAIL_QUERY,
    {
      address,
      blockchainEnvironment: env,
      isAddressName: false,
    },
    { ...opts, env }
  );

  return data.addressDetail ?? null;
}

// -----------------------------
// Address Resources Parser
// -----------------------------

/**
 * Raw resource item from SupraScan (after JSON.parse of resources string)
 */
interface RawResourceItem {
  type: string;
  data?: any;
}

/**
 * PackageRegistry data structure from SupraScan
 */
interface PackageRegistryData {
  packages?: Array<{
    package_name?: string;
    account?: string;
    upgrade_number?: number | string;
    upgrade_policy?: {
      policy?: number | string;
    };
    modules?: Array<{
      name?: string;
      source?: string; // gzip hex string with 0x prefix
      source_map?: string;
    }>;
    deps?: Array<{
      account?: string;
      package_name?: string;
    }>;
    source_digest?: string;
  }>;
}

/**
 * Normalized package structure
 */
export interface NormalizedPackage {
  publisher: string;
  name: string;
  upgradeNumber?: number | string;
  upgradePolicy?: number | string;
  sourceDigest?: string;
  deps: Array<{ publisher: string; name: string }>;
  modules: Array<{
    moduleName: string;
    sourceHex: string;
    decodedMoveSource?: string; // Only if decompression succeeds
  }>;
}

/**
 * Normalized address resources
 */
export interface NormalizedAddressResources {
  address: string;
  env: "mainnet" | "testnet";
  rawResourcesCount: number;
  hasPackageRegistry: boolean;
  packages: NormalizedPackage[];
}

/**
 * Custom error for SupraScan resource parsing
 */
export class SupraScanResourceError extends Error {
  constructor(
    message: string,
    public readonly errorType?: string,
    public readonly code?: string
  ) {
    super(message);
    this.name = "SupraScanResourceError";
  }
}

/**
 * Decompress gzip-compressed module source from hex string
 * @param sourceHex - Hex string with 0x prefix containing gzip-compressed bytes
 * @returns Decompressed UTF-8 text, or null if decompression fails
 */
export function decompressModuleSource(sourceHex: string): string | null {
  if (!sourceHex || !sourceHex.startsWith("0x")) {
    return null;
  }

  try {
    // Remove 0x prefix and convert hex to buffer
    const hexWithoutPrefix = sourceHex.slice(2);
    const compressedBuffer = Buffer.from(hexWithoutPrefix, "hex");

    // Decompress using Node.js zlib
    const decompressed = gunzipSync(compressedBuffer);

    // Convert to UTF-8 string
    return decompressed.toString("utf-8");
  } catch (error) {
    // Decompression failed - return null (non-fatal)
    return null;
  }
}

/**
 * Parse resources JSON string and extract PackageRegistry
 */
function parseResourcesString(resourcesStr: string | null | undefined): {
  resources: RawResourceItem[];
  packageRegistry: PackageRegistryData | null;
} {
  if (!resourcesStr || typeof resourcesStr !== "string") {
    throw new SupraScanResourceError(
      "Resources field is missing or not a string",
      undefined,
      "bad_resources_payload"
    );
  }

  let resources: RawResourceItem[];
  try {
    // First JSON.parse: convert string to array
    resources = JSON.parse(resourcesStr);
  } catch (error) {
    throw new SupraScanResourceError(
      `Failed to parse resources JSON string: ${error instanceof Error ? error.message : String(error)}`,
      undefined,
      "bad_resources_payload"
    );
  }

  if (!Array.isArray(resources)) {
    throw new SupraScanResourceError(
      "Resources is not an array",
      undefined,
      "bad_resources_payload"
    );
  }

  // Find PackageRegistry resource
  const packageRegistryItem = resources.find(
    (item) => item.type === "0x1::code::PackageRegistry"
  );

  const packageRegistry: PackageRegistryData | null = packageRegistryItem?.data || null;

  return { resources, packageRegistry };
}

/**
 * Normalize a single package from PackageRegistry
 */
function normalizePackage(
  pkg: NonNullable<PackageRegistryData["packages"]>[number],
  decompressSource: boolean = false
): NormalizedPackage | null {
  if (!pkg || !pkg.package_name || !pkg.account) {
    return null;
  }

  const normalized: NormalizedPackage = {
    publisher: pkg.account,
    name: pkg.package_name,
    upgradeNumber: pkg.upgrade_number,
    upgradePolicy: pkg.upgrade_policy?.policy,
    sourceDigest: pkg.source_digest,
    deps: [],
    modules: [],
  };

  // Normalize dependencies
  if (Array.isArray(pkg.deps)) {
    for (const dep of pkg.deps) {
      if (dep.account && dep.package_name) {
        normalized.deps.push({
          publisher: dep.account,
          name: dep.package_name,
        });
      }
    }
  }

  // Normalize modules
  if (Array.isArray(pkg.modules)) {
    for (const mod of pkg.modules) {
      if (mod.name && mod.source) {
        const moduleData: NormalizedPackage["modules"][0] = {
          moduleName: mod.name,
          sourceHex: mod.source,
        };

        // Optionally decompress source
        if (decompressSource) {
          const decoded = decompressModuleSource(mod.source);
          if (decoded) {
            moduleData.decodedMoveSource = decoded;
          }
        }

        normalized.modules.push(moduleData);
      }
    }
  }

  return normalized;
}

/**
 * Fetch and normalize address resources from SupraScan GraphQL
 * 
 * @param address - Address to fetch resources for
 * @param env - Blockchain environment (mainnet or testnet)
 * @param opts - Optional configuration
 * @returns Normalized address resources
 * @throws SupraScanResourceError if addressDetail.isError is true or resources are invalid
 */
export async function fetchSupraScanAddressResources(
  address: string,
  env: "mainnet" | "testnet" = "mainnet",
  opts: SupraScanGraphqlOptions & { decompressSource?: boolean } = {}
): Promise<NormalizedAddressResources> {
  const decompressSource = opts.decompressSource ?? false;

  // Fetch address detail
  const addressDetail = await fetchAddressDetailSupra(address, env, opts);

  if (!addressDetail) {
    throw new SupraScanResourceError(
      "Address detail not found",
      undefined,
      "not_found"
    );
  }

  // Check for errors
  if (addressDetail.isError) {
    throw new SupraScanResourceError(
      `SupraScan returned error: ${addressDetail.errorType || "unknown"}`,
      addressDetail.errorType || undefined,
      "supra_scan_error"
    );
  }

  // Get resources string
  const resourcesStr = addressDetail.addressDetailSupra?.resources;

  // Parse resources
  const { resources, packageRegistry } = parseResourcesString(resourcesStr);

  // Normalize packages
  const normalizedPackages: NormalizedPackage[] = [];

  if (packageRegistry?.packages && Array.isArray(packageRegistry.packages)) {
    for (const pkg of packageRegistry.packages) {
      const normalized = normalizePackage(pkg, decompressSource);
      if (normalized) {
        normalizedPackages.push(normalized);
      }
    }
  }

  return {
    address,
    env,
    rawResourcesCount: resources.length,
    hasPackageRegistry: packageRegistry !== null,
    packages: normalizedPackages,
  };
}


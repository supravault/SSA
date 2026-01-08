# SSA RPC Call Map

This document maps the exact Supra RPC endpoints and payloads that SSA uses for module scans, FA token scans, and coin-type scans.

## Overview

SSA uses a **hybrid scanning approach**:
- **Module scans**: View calls (capability detection) + On-chain bytecode/ABI fetching
- **FA scans**: RPC resources/views (primary) → SupraScan GraphQL (fallback)
- **Coin scans**: Framework view calls (optional, legacy support)

---

## A) Module Scan RPC Plan

**Input**: Publisher address + module name  
**Goal**: Fetch module bytecode/ABI + capability probes via view calls  
**Mode**: Hybrid (view + on-chain bytecode/ABI)

### 1. View Function Calls (Capability Probes) - PRIMARY

**Endpoint**: `POST {RPC_URL}/rpc/v1/view`

**Payload Format**:
```json
{
  "function": "0xADDR::module::function_name",
  "type_arguments": [],
  "arguments": []
}
```

**View Calls Made** (in order):
- `pool_stats` - Required capability probe
- `total_staked` - Required capability probe
- `view_withdraw_requests` - v24 queue probe
- `view_claim_requests` - v24 queue probe
- `withdraw_queue_length` - Legacy queue probe (if v24 fails)
- `claim_queue_length` - Legacy queue probe (if v24 fails)
- `view_withdrawal_amount_of` - User-specific (if TARGET_USER provided)
- `view_claim_amount_of` - User-specific (if TARGET_USER provided)

**Response**: JSON with `result` field containing view output

**When to Stop**: Continue even if some views fail (graceful degradation)

### 2. Module List Discovery - SECONDARY

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{publisher_address}/modules`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{publisher_address}/modules`

**Purpose**: Discover available modules at publisher address (optional, for validation)

**Response**: Array of module objects:
```json
[
  {
    "name": "module_name",
    "bytecode": "0x...",
    "abi": { ... }
  }
]
```

**When to Stop**: If v3 fails, try v2. If both fail, continue (not critical).

### 3. Module Bytecode/ABI Fetch - SECONDARY

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{publisher_address}/modules/{module_name}`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{publisher_address}/modules/{module_name}`  
**Fallback v1**: `GET {RPC_URL}/rpc/v1/accounts/{publisher_address}/modules/{module_name}`

**Purpose**: Fetch bytecode and ABI for evidence-based scanning

**Response**: Module object:
```json
{
  "bytecode": "0x...",  // Hex or base64 encoded
  "abi": {
    "address": "0x...",
    "name": "module_name",
    "exposed_functions": [...],
    "structs": [...]
  }
}
```

**Fields Used by SSA**:
- `bytecode`: Decoded to Buffer for bytecode analysis
- `abi.exposed_functions`: Function signatures for rule analysis
- `abi.structs`: Type information for validation

**Capability Flags** (set after fetch):
- `hasBytecodeOrSource = true` when bytecode present
- `hasAbi = true` when ABI present
- `viewOnly = false` when either bytecode or ABI present

**Severity Gating**:
- HIGH/CRITICAL findings **only allowed** if `hasBytecodeOrSource === true` OR `hasAbi === true`
- View-only scans cap findings at MEDIUM/LOW severity

**When to Stop**: Try v3 → v2 → v1. If all fail, continue in view-only mode.

---

## B) FA Token Scan RPC Plan

**Input**: FA token address  
**Goal**: Fetch FA metadata (symbol, decimals, supply, name, creator)  
**Mode**: Chain-first (resources/views) → Indexer fallback (SupraScan GraphQL)

### Provider Order (when `FA_METADATA_PROVIDER=auto`):

#### 1. Resources Endpoint (PRIMARY)

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{fa_address}/resources`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{fa_address}/resources`  
**Fallback v1**: `GET {RPC_URL}/rpc/v1/accounts/{fa_address}/resources`

**Purpose**: Fetch FA metadata from on-chain resources

**Response**: Array of resource objects:
```json
[
  {
    "type": "0x1::fungible_asset::Metadata<0x...::module::TYPE>",
    "data": {
      "symbol": "SYMBOL",
      "decimals": 8,
      "supply": "1000000",
      "name": "Token Name",
      "creator": "0x..."
    }
  }
]
```

**Fields Extracted**:
- `data.symbol` → `metadata.symbol`
- `data.decimals` → `metadata.decimals`
- `data.supply` or `data.total_supply` → `metadata.totalSupply`
- `data.name` → `metadata.name`
- `data.creator` → `metadata.creator`

**Success Criteria**: If any metadata fields found, mark `fetchMethod = "supra_rpc_v3_resources"` (or v2/v1)

**When to Stop**: If resources found, stop. Otherwise, continue to framework views.

#### 2. Framework Views (OPTIONAL, Feature-Flagged)

**Feature Flag**: `FA_ENABLE_FRAMEWORK_VIEWS=1` (default: **disabled**)

**Endpoint**: `POST {RPC_URL}/rpc/v1/view`

**Payload Format**:
```json
{
  "function": "0x1::fungible_asset::{symbol|decimals|supply|name}",
  "type_arguments": ["0x...::module::TYPE"],
  "arguments": ["ARG_STRING"]
}
```

**Views Called** (if feature flag enabled):
- `0x1::fungible_asset::symbol`
- `0x1::fungible_asset::decimals`
- `0x1::fungible_asset::supply`
- `0x1::fungible_asset::name`

**Argument Convention**:
- `type_arguments[0]`: Always `TARGET_COIN_TYPE` (Move struct tag)
- `arguments[0]`: Determined via probe script or `FA_VIEW_ARG_CONVENTION` env var
  - Default: `TARGET_COIN_TYPE`
  - Override: `FA_VIEW_ARG_CONVENTION=fa_address` → use `TARGET_FA`

**Success Criteria**: If any view succeeds, mark `fetchMethod = "supra_framework_fa_views"`

**When to Stop**: If views succeed, stop. Otherwise, continue to SupraScan GraphQL.

#### 3. SupraScan GraphQL (SECONDARY FALLBACK)

**Endpoint**: `https://suprascan.io/api/graphql` (or `SUPRASCAN_GRAPHQL_URL`)

**Purpose**: Public indexer fallback (metadata only, **NOT** bytecode/ABI)

**Query**:
```graphql
query GetFaDetails($faAddress: String, $blockchainEnvironment: BlockchainEnvironment) {
  getFaDetails(faAddress: $faAddress, blockchainEnvironment: $blockchainEnvironment) {
    faName
    faSymbol
    decimals
    totalSupply
    creatorAddress
    holders
    iconUrl
    verified
    isDualNature
  }
}
```

**Variables**:
```json
{
  "faAddress": "0x...",
  "blockchainEnvironment": "mainnet"  // lowercase, not "MAINNET"
}
```

**Response Fields Used**:
- `faName` → `metadata.name`
- `faSymbol` → `metadata.symbol`
- `decimals` → `metadata.decimals`
- `totalSupply` → `metadata.totalSupply`
- `creatorAddress` → `metadata.creator`
- `holders` → `metadata.holdersCount`

**Success Criteria**: If GraphQL returns data, mark `fetchMethod = "suprascan_graphql"`

**When to Stop**: If GraphQL succeeds, stop. If it fails, scan completes with `INCONCLUSIVE` verdict.

**Note**: SupraScan is a **metadata indexer fallback only**. It does NOT provide bytecode/ABI evidence.

---

## C) Coin-Type Scan RPC Plan (Optional, Legacy)

**Input**: Coin type struct tag (e.g., `0x...::module::COIN`)  
**Goal**: Fetch coin metadata via framework views  
**Mode**: View-only (no bytecode/ABI for framework coins)

### 1. Framework Coin Views

**Endpoint**: `POST {RPC_URL}/rpc/v1/view`

**Views Called**:
- `0x1::coin::name<T>()`
- `0x1::coin::symbol<T>()`
- `0x1::coin::decimals<T>()`
- `0x1::coin::supply<T>()`

**Type Arguments**: `[TARGET_COIN_TYPE]`

**Response**: JSON with `result` field

**When to Stop**: If views succeed, stop. If they fail, scan completes with `INCONCLUSIVE`.

### 2. Module Publisher Discovery (Optional)

If coin type has a custom module publisher (not `0x1`):
- Use module scan RPC plan (Section A) to fetch bytecode/ABI
- Enable evidence-based scanning for custom coin modules

---

## Verdict Semantics

### Verdict Tiers

1. **PASS_VERIFIED** (or `pass` with `verdict_tier: "verified"`):
   - Requires: `hasBytecodeOrSource === true` OR `hasAbi === true`
   - Requires: No HIGH/CRITICAL findings
   - Meaning: Code-level security verified
   - Badge: "Security Verified"

2. **PASS_METADATA** (or `pass` with `verdict_tier: "metadata"`):
   - Requires: Metadata successfully fetched
   - Requires: No HIGH/CRITICAL findings (but findings may be capped at MEDIUM/LOW)
   - Meaning: Metadata-only scan; code-level security **NOT verified**
   - Badge: "Metadata Verified" (NOT "Security Verified")
   - Console output: `"PASS (metadata-only) — code-level security not verified."`

3. **INCONCLUSIVE**:
   - Triggered when: Metadata missing, required views failed, or insufficient evidence
   - Meaning: Scan incomplete or insufficient data

4. **FAIL**:
   - Triggered when: HIGH/CRITICAL findings present AND `hasBytecodeOrSource === true`
   - Meaning: Code-level security issues detected

### Badge Eligibility

**Security Verified Badge**:
- Requires: `hasBytecodeOrSource === true` AND no HIGH/CRITICAL findings
- FA tokens: Framework-managed (no custom modules) → verified via framework views/resources
- FA tokens: Custom modules exist → verified only if custom modules bytecode-scanned

**Metadata Verified**:
- `metadata_verified = true` if metadata fetched via any method
- Does NOT imply code-level security
- **Cannot** claim "no backdoors" without bytecode/ABI evidence

**Code Verified**:
- `code_verified = true` if:
  - Framework-managed FA: `hasMetadata && !hasCustomModules`
  - Custom modules: `hasCreatorBytecode === true`

---

## Environment Variables

### Module Scan
- `RPC_URL`: Supra RPC endpoint (default: `https://rpc-mainnet.supra.com`)
- `TARGET_USER`: User address for user-specific views (optional)
- `SUPRA_RPC_URL`: Alias for `RPC_URL`

### FA Scan
- `TARGET_COIN_TYPE`: Move struct tag (required for framework views)
- `TARGET_FA`: FA token address
- `FA_ENABLE_FRAMEWORK_VIEWS`: Enable framework view calls (default: disabled)
- `FA_VIEW_ARG_CONVENTION`: Argument convention (`coin_type` | `fa_address`)
- `FA_METADATA_PROVIDER`: Provider mode (`auto` | `rpc` | `suprascan`)
- `SUPRASCAN_GRAPHQL_URL`: SupraScan GraphQL endpoint
- `SUPRASCAN_ENV`: Blockchain environment (`mainnet` | `testnet`, lowercase)

### Coin Scan
- `TARGET_COIN_TYPE`: Move struct tag (required)

### Debug
- `SSA_DEBUG_VIEW=1`: Print view call payloads
- `SSA_DEBUG_FA=1`: Print FA scan debug info
- `DEBUG_VIEW=1`: Alias for `SSA_DEBUG_VIEW`

---

## RPC Plan Debug Output

### Module Scan
```
[RPC Plan] Module Scan: {publisher}::{module}
  - View calls: pool_stats, total_staked, ... (8 calls)
  - Bytecode fetch: GET /rpc/v3/accounts/{publisher}/modules/{module} ✅
  - ABI present: ✅
  - Capabilities: hasBytecodeOrSource=true, hasAbi=true
```

### FA Scan
```
[RPC Plan] FA Scan: {fa_address}
  - Provider chain: resources → framework_views (disabled) → suprascan_graphql
  - Resources: GET /rpc/v3/accounts/{fa_address}/resources ✅
  - Framework views: disabled (FA_ENABLE_FRAMEWORK_VIEWS not set)
  - SupraScan GraphQL: ✅ (fallback)
  - Metadata verified: ✅
  - Code verified: ❌ (no bytecode/ABI)
```

---

## Fallback Order Summary

### Module Scan
1. View calls (always)
2. RPC v3 module fetch → v2 fallback → v1 fallback
3. If all fail: view-only mode (safe default)

### FA Scan (auto mode)
1. Resources (v3 → v2 → v1)
2. Framework views (if `FA_ENABLE_FRAMEWORK_VIEWS=1`)
3. SupraScan GraphQL (if resources/views fail)
4. If all fail: `INCONCLUSIVE` verdict

### Coin Scan
1. Framework coin views
2. Module publisher scan (if custom publisher)
3. If all fail: `INCONCLUSIVE` verdict

---

## Important Notes

- **Do NOT claim "no backdoors"** unless bytecode/ABI has been fetched and analyzed
- Metadata-only scans must explicitly state: "code-level security not verified"
- HIGH/CRITICAL findings are **gated** by bytecode/ABI presence
- View-only mode is the **default-safe path** (graceful degradation)
- SupraScan GraphQL uses **lowercase** `"mainnet"` not `"MAINNET"`


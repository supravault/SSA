# SSA RPC Call Map

This document maps the exact Supra RPC endpoints and payloads that SSA uses for module scans and FA token scans.

## A) Module Scan RPC Plan

**Input**: Publisher address + module name  
**Goal**: Fetch module bytecode/ABI + capability probes via view calls

### 1. View Function Calls (Capability Probes)

**Endpoint**: `POST {RPC_URL}/rpc/v1/view`

**Payload Format**:
```json
{
  "function": "0xADDR::module::function_name",
  "type_arguments": [],
  "arguments": []
}
```

**View Calls Made**:
- `pool_stats` - Required capability probe
- `total_staked` - Required capability probe
- `view_withdraw_requests` - v24 queue probe
- `view_claim_requests` - v24 queue probe
- `withdraw_queue_length` - Legacy queue probe (if v24 fails)
- `claim_queue_length` - Legacy queue probe (if v24 fails)
- `view_withdrawal_amount_of` - User-specific (if TARGET_USER provided)
- `view_claim_amount_of` - User-specific (if TARGET_USER provided)

**Response**: JSON with `result` field containing view output

### 2. Module List Discovery

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{publisher_address}/modules`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{publisher_address}/modules`

**Response**: Array of module objects with `name`, `bytecode`, `abi` fields

### 3. Module Bytecode/ABI Fetch

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{publisher_address}/modules/{module_name}`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{publisher_address}/modules/{module_name}`

**Response**: Module object with:
- `bytecode`: Hex or base64 encoded bytecode
- `abi`: ABI object with `exposed_functions`, `structs`, etc.

**Capability Flags**:
- `hasBytecodeOrSource = true` if bytecode present
- `hasAbi = true` if ABI present
- `viewOnly = false` if either bytecode or ABI present

**Severity Gating**:
- HIGH/CRITICAL findings only allowed if `hasBytecodeOrSource === true` OR `hasAbi === true`
- View-only scans cap findings at MEDIUM/LOW severity

---

## B) FA Token Scan RPC Plan

**Input**: FA token address  
**Goal**: Fetch FA metadata (symbol, decimals, supply, name, creator)

### Primary Chain-First Calls

#### 1. Resources Endpoint (Primary)

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{fa_address}/resources`  
**Fallback**: `GET {RPC_URL}/rpc/v2/accounts/{fa_address}/resources`  
**Fallback v1**: `GET {RPC_URL}/rpc/v1/accounts/{fa_address}/resources`

**Response**: Array of resource objects

**Metadata Extraction**:
- Search for resources with `type` containing `fungible_asset`, `FA`, or `Metadata`
- Extract from `data` field: `symbol`, `decimals`, `supply`, `total_supply`, `name`, `creator`

**Success Criteria**: If any metadata fields found, mark `fetchMethod = "supra_rpc_v3_resources"` (or v2/v1)

#### 2. Framework Views (Optional, Feature-Flagged)

**Feature Flag**: `FA_ENABLE_FRAMEWORK_VIEWS=1` (default: disabled)

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

#### 3. Events Query (Stub, Feature-Flagged)

**Feature Flag**: `FA_ENABLE_EVENTS=1` (default: disabled)

**Endpoint**: `GET {RPC_URL}/rpc/v3/accounts/{fa_address}/events` (if available)  
**Status**: Stub - not implemented yet

### Secondary Fallback

#### 4. SupraScan GraphQL (Metadata Indexer)

**Endpoint**: `https://suprascan.io/api/graphql` (or `SUPRASCAN_GRAPHQL_URL`)

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
  "blockchainEnvironment": "mainnet" | "testnet"
}
```

**Success Criteria**: If GraphQL returns data, mark `fetchMethod = "suprascan_graphql"`

**Note**: SupraScan is a **metadata indexer fallback only**. It does NOT provide bytecode/ABI evidence.

---

## Verdict Semantics

### Verdict Tiers

1. **PASS_VERIFIED** (or `pass` with `verdict_tier: "verified"`):
   - Requires: `hasBytecodeOrSource === true` OR `hasAbi === true`
   - Requires: No HIGH/CRITICAL findings
   - Meaning: Code-level security verified

2. **PASS_METADATA** (or `pass` with `verdict_tier: "metadata"`):
   - Requires: Metadata successfully fetched
   - Requires: No HIGH/CRITICAL findings (but findings may be capped at MEDIUM/LOW)
   - Meaning: Metadata-only scan; code-level security NOT verified
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

**Code Verified**:
- `code_verified = true` if:
  - Framework-managed FA: `hasMetadata && !hasCustomModules`
  - Custom modules: `hasCreatorBytecode === true`

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
- `FA_ENABLE_EVENTS`: Enable events query (default: disabled, stub)
- `SUPRASCAN_GRAPHQL_URL`: SupraScan GraphQL endpoint
- `SUPRASCAN_ENV`: Blockchain environment (`mainnet` | `testnet`)

### Debug
- `SSA_DEBUG_VIEW=1`: Print view call payloads
- `SSA_DEBUG_FA=1`: Print FA scan debug info
- `DEBUG_VIEW=1`: Alias for `SSA_DEBUG_VIEW`


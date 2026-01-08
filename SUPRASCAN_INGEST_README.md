# SupraScan Evidence Ingestion

## Overview

The SupraScan evidence ingestion system allows you to process saved SupraScan bundles and extract Level-1 surface information (flags, risk scores) for inclusion in SSA scanner reports.

## Usage

### 1. Ingest SupraScan Bundle

Process a SupraScan bundle JSON file to extract flags and compute risk:

```bash
npm run build
node dist/src/scripts/suprascan-ingest.js --in tmp/suprascan_fa_DXLYN.json --out state/suprascan_fa_DXLYN.enriched.json
```

**Input Format** (`tmp/suprascan_fa_DXLYN.json`):
```json
{
  "kind": "fa",
  "ts_utc": "2024-01-01T00:00:00Z",
  "fa": {
    "faName": "DXLYN",
    "faSymbol": "DXLYN",
    "verified": true,
    "faAddress": "0x...",
    "decimals": 8,
    "totalSupply": "1000000",
    "creatorAddress": "0x...",
    "holders": 150
  },
  "faResourcesJson": "[{\"type\":\"0x1::fungible_asset::Metadata\",\"data\":{...}}, ...]"
}
```

**Output Format** (`state/suprascan_fa_DXLYN.enriched.json`):
```json
{
  "kind": "fa",
  "ts_utc": "2024-01-01T00:00:00Z",
  "details": {
    "faName": "DXLYN",
    "faSymbol": "DXLYN",
    "verified": true,
    ...
  },
  "flags": {
    "hasMintRef": true,
    "hasBurnRef": false,
    "hasTransferRef": true,
    "hasDepositHook": false,
    "hasWithdrawHook": false,
    "hasDerivedBalanceHook": false,
    "hasDispatchFunctions": false,
    "owner": "0x...",
    "supplyCurrent": "1000000",
    "supplyMax": null,
    "decimals": 8,
    "resourceCount": 5,
    "resourceTypes": ["0x1::fungible_asset::Metadata", ...]
  },
  "risk": {
    "score": 45,
    "labels": ["has_mint_ref", "has_transfer_ref", "verified", "medium_risk"]
  }
}
```

### 2. Include in Level 1 Report

Set the `SUPRASCAN_EVIDENCE_PATH` environment variable to point to the enriched evidence file:

```bash
export SUPRASCAN_EVIDENCE_PATH=state/suprascan_fa_DXLYN.enriched.json
npm run build
node dist/src/index.js scan --type fa --target 0x...
```

The Level 1 surface report will automatically include SupraScan evidence under `surface_report.suprascan_evidence` if the file exists. The scanner will **not fail** if the evidence file is absent.

## Flags Extracted

### FA Flags
- `hasMintRef`: Mint reference capability present
- `hasBurnRef`: Burn reference capability present
- `hasTransferRef`: Transfer reference capability present
- `hasDepositHook`: Deposit hook configured
- `hasWithdrawHook`: Withdraw hook configured
- `hasDerivedBalanceHook`: Derived balance hook configured
- `hasDispatchFunctions`: Dispatch function store present
- `owner`: ObjectCore owner address
- `supplyCurrent`: Current supply (raw base units)
- `supplyMax`: Maximum supply (raw base units)
- `decimals`: Token decimals
- `resourceCount`: Number of resources parsed
- `resourceTypes`: List of resource type strings

### Coin Flags
- `hasMintCap`: Mint capability present
- `hasBurnCap`: Burn capability present
- `hasFreezeCap`: Freeze capability present
- `hasTransferRestrictions`: Transfer restrictions present
- `supplyCurrent`: Current supply (raw base units)
- `decimals`: Token decimals
- `resourceCount`: Number of resources parsed
- `resourceTypes`: List of resource type strings

## Risk Scoring

Risk scores range from 0-100 (higher = worse):

- **Base risk** from capabilities (mint/burn/freeze/hooks)
- **Modifiers** from verification status and holder count
- **Risk tiers**:
  - `high_risk`: score >= 70
  - `medium_risk`: score >= 40
  - `low_risk`: score >= 20
  - `minimal_risk`: score < 20

## Deterministic Output

All output is deterministic and JSON-serializable:
- No network calls in the ingest script
- All computations are pure functions
- Output is stable for GitHub commit + diffing

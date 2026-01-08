# SSA Scanner

Supra-native Security-as-an-Agent scanner MVP. A utility-first security scanner for deployed Supra Move modules that runs deterministic rule-packs and outputs normalized JSON scan results.

**No Supra SDK required** - uses `/rpc/v1/view` endpoint directly via raw RPC calls.

## Features

- **Module Scanning**: Scan deployed Supra Move modules by module ID (address + module name)
- **FA Token Scanning**: Scan Supra FA tokens using on-chain data only (no source files required)
- **On-chain Bytecode Fetching**: Automatically fetches module bytecode from Supra RPC v3 endpoints (default behavior)
- **Deterministic Rules**: 25 security rules (10 fully implemented, 15 stubbed for future implementation)
- **Risk Scoring**: Automated risk scoring (0-100) with verdict (pass/warn/fail/inconclusive)
- **Badge System**: Official SSA verification badges with cryptographic signing
- **Risk States**: Separate risk state system (not badges) for security findings
- **Badge Policy**: Authoritative badge issuance rules (see `docs/ssa-badges-and-risk-policy.md`)
- **CLI & API**: Both command-line and HTTP API interfaces
- **Artifact Binding**: SHA256-based artifact hashing for version tracking
- **Evidence-based Scanning**: View-only scans are marked as INCONCLUSIVE unless state-based critical issues are found

## Installation

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

**Note**: After cloning the repository, always run `npm install` first, then `npm run build` to compile TypeScript to JavaScript.

## Configuration

Create a `.env` file (or copy from `.env.example`):

```env
SUPRA_RPC_URL=https://rpc.supra.com
PERSIST=1  # Optional: Enable file persistence for scan results
```

## Usage

### CLI

#### Full Integrated Report Generation

Generate a Full Integrated Report PDF that aggregates wallet, coin/FA scans, and Supra Pulse Premium/Spotlight reports:

```bash
npm run build
node dist/src/scripts/generate-report.js \
  --scan tmp/fa_scan.json \
  --wallet-scan tmp/wallet_scan.json \
  --pulse tmp/supra_pulse_premium.pdf \
  --project-name MyProject \
  --ts-utc 2026-01-08T12:00:00Z \
  --out reports
```

The report will be archived to `reports/{project_name}/{timestamp}/` with:
- `final_report.pdf` - Full Integrated PDF report with red wax seal
- `inputs.json` - Canonical inputs bundle (for checksum verification)
- `supra_pulse_summary.json` - Pulse summary (if provided)
- `checksum.txt` - SHA256 checksums (input_checksum, pdf_checksum, report_id)

**Note**: Full Integrated Reports require Supra Pulse Premium or Spotlight tier. Free/summary Pulse reports will generate standard SSA reports without the wax seal.

#### Module Scanning

Scan a module:

```bash
# New style (recommended)
npm run build
node dist/src/index.js module --address 0x123... --module staking_v17 --level quick --out result.json

# Old style (backward compatible)
node dist/src/index.js --address 0x123... --module staking_v17 --level quick --out result.json
```

Options:
- `--address <address>`: Module address (required, 0x... format)
- `--module <name>`: Module name (required)
- `--level <level>`: Scan level - `quick` (default), `standard`, `full`, `monitor`
- `--out <file>`: Output file path for full JSON results (optional)
- `--rpc <url>`: Override RPC URL (optional, uses SUPRA_RPC_URL env var by default)

Example output:
```
Scanning 0x123...::staking_v17...
Scan level: quick
RPC URL: https://rpc.supra.com

=== Scan Summary ===
Request ID: abc-123-def
Verdict: WARN
Risk Score: 45/100
Severity Counts:
  Critical: 0
  High: 2
  Medium: 3
  Low: 1
  Info: 0
Total Findings: 6

=== Top Findings ===
1. [HIGH] SVSSA-MOVE-001: Open/Dangerous Entrypoint Detected
   Entry function "withdraw" matches dangerous patterns...
...
```

#### FA Token Scanning

Scan an FA token:

```bash
npm run build
node dist/src/index.js fa --fa <fa_address> [--owner <owner_address>] [--out <file>] [--rpc <url>]
```

FA scan options:

- `--fa <address>`: FA token address (0x...)
- `--owner <address>`: FA owner address (optional)
- `--out <file>`: Output file path (JSON)
- `--rpc <url>`: Supra RPC URL (overrides SUPRA_RPC_URL env)

#### Level 3 Watcher Mode

Watch a token for changes (snapshot persistence + diffing + alert rules):

**Coin Token Watching:**

```powershell
# Set RPC URL
$env:SUPRA_RPC_URL="https://rpc-mainnet.supra.com"

# Build
npm run build

# Baseline create (run once)
node dist/src/index.js watch --type coin --target "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH" --once

# Second run (no change expected)
node dist/src/index.js watch --type coin --target "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH" --once

# Continuous watching (every 60 seconds)
node dist/src/index.js watch --type coin --target "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH" --loop-ms 60000
```

**FA Token Watching:**

```powershell
# Baseline create
node dist/src/index.js watch --type fa --target "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358" --once

# Continuous watching
node dist/src/index.js watch --type fa --target "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358" --loop-ms 60000

# JSON output mode (pure JSON, suitable for PowerShell parsing)
node dist/src/index.js watch --type fa --target "<fa_address>" --once --json | ConvertFrom-Json | ConvertTo-Json -Depth 25
```

Watch command options:

- `--type <type>`: Token type (`coin` or `fa`)
- `--target <target>`: Target identifier
  - For coin: Full coin type string (e.g., `0x123::MODULE::COIN`)
  - For FA: FA address (e.g., `0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358`)
- `--once`: Run once and exit (don't loop)
- `--loop-ms <ms>`: Loop interval in milliseconds (default: 60000)
- `--state-dir <dir>`: State directory for snapshots (default: `state`)
- `--json`: Output pure JSON format (single-line, no other console output)
- `--rpc <url>`: Supra RPC URL (overrides SUPRA_RPC_URL env)
- `--ignore-supply`: Ignore supply changes in diffs (for deterministic testing)
- `--prev-snapshot <path>`: Load previous snapshot from file (test harness mode, requires `--curr-snapshot`)
- `--curr-snapshot <path>`: Load current snapshot from file (test harness mode, requires `--prev-snapshot`)

**Watch Mode Behavior:**

1. On each tick:
   - Runs Level-1 and Level-2 analysis (capability presence + privilege & invariants)
   - Builds current snapshot
   - Loads previous snapshot from `state/` directory
   - Computes diff between snapshots
   - Applies severity rules (critical/high/medium/info)
   - Prints changes (or JSON if `--json` flag)
   - Persists current snapshot (always writes, even if unchanged)

2. Change Detection:
   - **SUPPLY_CHANGED**: Supply increases/decreases
   - **SUPPLY_MAX_CHANGED**: Max supply changes (FA)
   - **OWNER_CHANGED**: Object owner changes (FA)
   - **HOOKS_CHANGED**: Hook modules added/removed (FA)
   - **MODULE_ADDED/MODULE_REMOVED**: Control modules added/removed
   - **ABI_SURFACE_CHANGED**: Function signatures changed (hash comparison)
   - **COVERAGE_CHANGED**: Analysis coverage status changes
   - **FINDINGS_CHANGED**: New findings, removed findings, or severity escalations

3. Severity Rules:
   - **Critical**: Large supply increases, new mint functions, owner+hooks changed together
   - **High**: Owner changes, hooks changed, ABI surface changed, coverage degraded, modules added
   - **Medium**: New mint/burn refs/caps, new findings
   - **Info**: Supply decreases, small increases, coverage improvements

4. State Files:
   - Stored in `state/` directory (gitignored)
   - Coin format: `state/coin_<address>__<module>__<symbol>.json`
   - FA format: `state/fa_<address>.json`
   - Snapshot files are deterministic JSON

#### Unified CLI (One Command Flow)

The unified CLI replaces all manual PowerShell glue with a single command:

```bash
# Build first
npm run build

# Scan a coin (levels 1-5)
ssa scan --kind coin --level 5 --coinType "0x6253...::NANA::NANA" --rpc https://rpc-mainnet.supra.com --out tmp/coin_test --pdf

# Scan an FA (levels 1-5)
ssa scan --kind fa --level 4 --fa 0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee --rpc https://rpc-mainnet.supra.com --out tmp/fa_test --pdf

# Scan a wallet/creator (levels 1-3)
# Wallet scan (Levels 1-3 only)
node dist/src/cli/ssa.js scan --kind wallet --level 3 --address 0x8fd1550a61055c1406e04d1a0ddf7049d00c889b59f6823f21ca7d842e1eaf3c --rpc https://rpc-mainnet.supra.com --out tmp/jones/wallet_out

# Alias: creator is same as wallet
ssa scan --kind creator --level 2 --address 0x123... --rpc https://rpc-mainnet.supra.com --out tmp/creator_test
```

**Output Structure:**
- `<out>/report.json` - Full raw scan report
- `<out>/summary.json` - Stable summary for Base44 ingestion
- `<out>/artifacts/` - Additional files (snapshots, diffs, pulse attachments)
- `<out>/report.pdf` - Human-friendly PDF report (if `--pdf` flag)

**Level 4/5 Features:**
- Level 4: Creates snapshot baseline at `<out>/artifacts/snapshot.json`
- Level 5: Creates diff at `<out>/artifacts/diff.json`
  - If `--prev` and `--curr` provided: diffs those snapshots
  - Otherwise: creates snapshot_v1, waits (default 1s, configurable with `--delay`), creates snapshot_v2, then diffs

**Supra Pulse Integration:**
- `--pulse <path>` attaches a Supra Pulse PDF or JSON report
- File is copied to `<out>/artifacts/supra_pulse.<ext>`
- SHA256 hash computed and included in `report.json` under `external_intel.supra_pulse`
- PDF report includes "Supra Pulse Intelligence (Integrated)" section with extracted key points if available

**Test Scripts:**
```bash
# Test wallet scan
npm run scan:wallet -- --level 3 --address 0x... --rpc https://rpc-mainnet.supra.com --out tmp/wallet_test

# Test coin scan
npm run scan:coin -- --level 5 --coinType "0x...::MODULE::COIN" --rpc https://rpc-mainnet.supra.com --out tmp/coin_test
```

#### Level 3 Agent Mode (agent-verify)

Run agent-mode verification with SupraScan parity for FA tokens:

```powershell
# Set RPC URL and variables
$env:SUPRA_RPC_URL="https://rpc-mainnet.supra.com"
$fa="0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee"
$rpc2="https://rpc-mainnet.supra.com"

# Build
npm run build

# Run agent-verify with SupraScan parity
node dist/src/scripts/agent-verify.js --fa $fa --rpc $env:SUPRA_RPC_URL --rpc2 $rpc2 --mode fast --with-suprascan true --out tmp/fa_agent_suprascan.json
```

This will:
- Fetch FA data from RPC v3, RPC v1, and optionally RPC2
- Query SupraScan for FA owner, supply, hooks, and hook module hashes (if available)
- Compute detailed parity between RPC and SupraScan
- Output comprehensive verification report with parity details and mismatches

**JSON Output Mode:**

When `--json` is set, the command outputs **pure JSON only** to stdout (no other console logs). This makes it suitable for PowerShell parsing:

```powershell
# Parse JSON output in PowerShell
node dist/src/index.js watch --type fa --target "0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee" --once --json | ConvertFrom-Json | ConvertTo-Json -Depth 25
```

The JSON output contains:
- `snapshotPath`: Path to the snapshot file (or current snapshot path in test harness mode)
- `changed`: Boolean indicating if changes were detected
- `changes`: Array of change items with type, severity, before/after, and evidence
- `currentSnapshotIdentity`: Identity information (coinType or faAddress)
- `prevSnapshotPresent`: Boolean indicating if previous snapshot was found
- `prevReadError`: Error message if previous snapshot failed to parse (null if successful)
- `baselineCreated`: Boolean indicating if this was the first run (baseline creation)
- `currSnapshotPath`: Current snapshot path (only in test harness mode)
- `prevSnapshotPath`: Previous snapshot path (only in test harness mode)

**Deterministic Testing Mode (Test Harness):**

For testing diff logic without RPC calls, use `--prev-snapshot` and `--curr-snapshot`:

```powershell
# Test ABI_SURFACE_CHANGED with mint-like function escalation
# 1. Create prev.json (empty entry functions)
# 2. Create curr.json (with entry_fn_names: ["mint_everyone"])
# 3. Run deterministic diff:

node dist/src/index.js watch \
  --type coin \
  --target "0x4742...::JOSH::JOSH" \
  --once \
  --json \
  --prev-snapshot prev.json \
  --curr-snapshot curr.json \
  --ignore-supply | ConvertFrom-Json

# Expected output:
# - changed: true
# - changes[0].type: "ABI_SURFACE_CHANGED"
# - changes[0].severity: "critical"
# - changes[0].evidence.hasMintLikeFunction: true
# - changes[0].evidence.moduleChanges[0].addedEntryFns: ["mint_everyone"]
```

**Test Harness Mode Behavior:**

- When both `--prev-snapshot` and `--curr-snapshot` are provided:
  - **No RPC calls**: Skips all network requests
  - **No snapshot building**: Loads snapshots directly from disk
  - **No state file writes**: Does not overwrite any files in `state/` directory
  - **Same diff logic**: Uses identical diff engine and severity rules
  - **Same JSON output**: Output format is identical to normal watch runs
  - **Works for both coin and FA**: Automatically detects type from snapshot structure
  - **Respects `--ignore-supply`**: Supply changes are skipped if flag is set

**Example: Testing FA ABI Changes:**

```powershell
# Create test snapshots
$prev = @{
  meta = @{ schema_version = "1.0"; timestamp_iso = "2024-01-01T00:00:00Z"; rpc_url = "test"; scanner_version = "test" }
  identity = @{ faAddress = "0x123..." }
  supply = @{}
  capabilities = @{}
  control_surface = @{
    relevantModules = @("0x123::module")
    modules = @{
      "0x123::module" = @{
        abi_fetched = $true
        entry_fn_names = @()
        exposed_fn_names = @()
      }
    }
  }
  coverage = @{ status = "complete"; reasons = @() }
  findings = @()
  hashes = @{ moduleSurfaceHash = @{}; overallSurfaceHash = "abc123" }
} | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 prev.json

$curr = $prev | ConvertFrom-Json
$curr.control_surface.modules."0x123::module".entry_fn_names = @("mint_tokens")
$curr.hashes.overallSurfaceHash = "def456"
$curr | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 curr.json

# Run deterministic test
node dist/src/index.js watch --type fa --target "0x123..." --once --json --prev-snapshot prev.json --curr-snapshot curr.json | ConvertFrom-Json
```

**Testing Watch Mode:**

```powershell
# 1. Baseline create for coin
$env:SUPRA_RPC_URL="https://rpc-mainnet.supra.com"
npm run build
node dist/src/index.js watch --type coin --target "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH" --once

# 2. Second run (should show no changes)
node dist/src/index.js watch --type coin --target "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH" --once

# 3. Baseline create for FA
node dist/src/index.js watch --type fa --target "0x2a0f3e6fb5d0f25c0d75cc4ffb93ace26757939fd4aa497c7f1dbaff7e3c6358" --once

# 4. Simulated diff test (manually edit state/fa_<addr>.json hookModules, then rerun)
# Should emit HOOKS_CHANGED high severity finding

# 5. JSON output test (pure JSON, no other output)
node dist/src/index.js watch --type fa --target "0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee" --once --json
```

### HTTP API

Start the server:

```bash
pnpm dev
```

The server runs on `http://localhost:3000` by default.

#### Endpoints

**POST /scan**
Submit a scan request.

Request body:
```json
{
  "address": "0x123...",
  "module_name": "staking_v17",
  "scan_level": "quick"
}
```

Response:
```json
{
  "request_id": "abc-123-def"
}
```

**GET /scan/:request_id**
Retrieve scan results.

Response: Full `ScanResult` JSON (see Data Model below)

**GET /health**
Health check endpoint.

## Scan Levels

Currently implemented:
- **quick**: Fast scan using all available rules (bytecode/ABI-based)

Future (not yet implemented):
- **standard**: More thorough analysis
- **full**: Complete analysis including source code if available
- **monitor**: Continuous monitoring mode

## Data Model

### ScanResult

```typescript
{
  request_id: string
  target: {
    chain: "supra"
    module_address: string
    module_name: string
    module_id: string  // `${address}::${module_name}`
  }
  scan_level: "quick" | "standard" | "full" | "monitor"
  timestamp_iso: string
  engine: {
    name: "ssa-scanner"
    version: string
    ruleset_version: string
  }
  artifact: {
    fetch_method: "rpc" | "raw_rpc"
    bytecode_b64?: string
    abi_json?: any
    artifact_hash: string
    binding_note: string
  }
  summary: {
    risk_score: number  // 0-100
    verdict: "pass" | "warn" | "fail"
    severity_counts: {
      critical: number
      high: number
      medium: number
      low: number
      info: number
    }
    badge_eligibility: {
      scanned: boolean
      no_critical: boolean
      security_verified: boolean
      continuously_monitored: boolean
      reasons: string[]
      expires_at_iso?: string
    }
  }
  findings: Finding[]
  meta: {
    scan_options: any
    rpc_url: string
    duration_ms: number
    previous_artifact_hash?: string
  }
}
```

### Finding

```typescript
{
  id: string  // e.g., "SVSSA-MOVE-001"
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  confidence: number  // 0-1
  description: string
  recommendation: string
  evidence: {
    kind: "bytecode_pattern" | "abi_pattern" | "metadata" | "heuristic"
    matched: string[]
    locations?: Array<{ fn?: string, note: string }>
    raw_excerpt?: string
  }
  references?: string[]
}
```

## Security Rules

### Implemented Rules (10)

1. **SVSSA-MOVE-001**: Open/Dangerous Entrypoints
2. **SVSSA-MOVE-002**: Privileged Role Hardcoding
3. **SVSSA-MOVE-003**: Re-initialization Risk
4. **SVSSA-MOVE-004**: Upgrade Hooks Risk
5. **SVSSA-MOVE-005**: Asset Outflow Primitives
6. **SVSSA-MOVE-006**: Unbounded Loops
7. **SVSSA-MOVE-007**: Missing Event Emissions
8. **SVSSA-MOVE-008**: Centralization Risk
9. **SVSSA-MOVE-009**: External Dependency/Oracle Usage
10. **SVSSA-MOVE-010**: Emergency Pause Abuse

### Stubbed Rules (15)

Rules 011-025 are stubbed for future implementation:
- Integer overflow/underflow
- Reentrancy risks
- Front-running vulnerabilities
- Access control bypass
- Timestamp dependence
- And more...

## Risk Scoring

Risk scores are calculated using weighted severity:
- Critical: 30 points
- High: 15 points
- Medium: 7 points
- Low: 3 points
- Info: 1 point

Scores are multiplied by confidence (0-1) and capped at 100.

**Verdict Logic**:
- `fail`: Any critical finding OR risk_score >= 60
- `warn`: Any high finding OR risk_score 25-59
- `pass`: Otherwise

## Badge Eligibility

For `quick` scans:
- **scanned**: true if scan succeeded and artifact_hash exists (expires in 30 days)
- **no_critical**: true if no critical findings (expires in 14 days)
- **security_verified**: false (requires full scan)
- **continuously_monitored**: false (requires monitor mode)

## Limitations

### Bytecode-Only Scanning

This MVP scans modules **without source code**, relying on:
- Bytecode analysis (string extraction, pattern matching)
- ABI analysis (function signatures, parameters)
- Metadata (if available)

**Limitations**:
- Cannot perform deep semantic analysis
- May produce false positives/negatives
- Limited ability to detect complex logic flaws
- String extraction is heuristic-based

### Future Enhancements

- **Source Code Analysis**: When source is available, enable deeper semantic analysis
- **Full Scan**: More comprehensive rule execution
- **Continuous Monitoring**: Track module changes over time
- **Onchain Badge Module**: Mint badges based on scan results
- **AI-Augmented Analysis**: (Future, not in scope for MVP)

## Quick Test (Windows PowerShell)

### A) RPC Sanity Test

Verify the Supra view RPC endpoint works:

```powershell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
npm run test:view
```

This tests the raw RPC endpoint without SDK dependencies.

### B) Full Scanner Test

Run a complete scan on a module:

```powershell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
npm run build
npm run test:scan
```

**Note**: Do not run `node scripts/test-scan.ts` directly; build first with `npm run build`.

### Hybrid Scan (Supra IDE artifacts)

The scanner supports hybrid scanning that combines live RPC view calls with optional local Move artifacts (source/ABI/bytecode) exported from Supra IDE. This enables evidence-based scanning with higher confidence findings.

**View-only mode** (default): Uses only `/rpc/v1/view` calls. Findings are capped at MEDIUM severity with lower confidence.

**Hybrid mode**: Combines RPC views with local artifacts. Enables HIGH/CRITICAL severity findings when strong evidence exists.

**Artifact-only mode**: Uses only local artifacts (no RPC calls). Useful for offline analysis.

#### Environment Variables

**New preferred variables:**
- `SSA_LOCAL_ARTIFACT_DIR`: Directory containing artifacts (scanner auto-detects module by name)
- `SSA_LOCAL_SOURCE`: Path to Move source file (.move)
- `SSA_LOCAL_BYTECODE`: Path to compiled bytecode file (.mv, .blob, .bin)
- `SSA_LOCAL_ABI`: Path to ABI/metadata JSON file

**Legacy variables (still supported):**
- `ARTIFACT_PATH`: Path to a single artifact file (.move, .json, .mv, .blob, .bin)
- `ARTIFACT_DIR`: Directory containing artifacts (scanner auto-detects module by name)

**On-chain bytecode fetching:**
The scanner will automatically attempt to fetch module bytecode from Supra RPC v3 endpoints (`/rpc/v3/accounts/{address}/modules/{module_name}`) if no local bytecode is provided. This is optional and will not fail if unavailable.

#### Supported Artifact Formats

- `.move`: Move source code (treated as source)
- `.json`: ABI/metadata file (treated as ABI)
- `.mv` / `.blob` / `.bin`: Compiled bytecode (treated as bytecode)

The scanner automatically detects and loads the best combination of artifacts from `ARTIFACT_DIR` by matching the module name.

#### Examples

**View-only scan** (default):
```powershell
# Windows PowerShell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
npm run test:scan
```

**Hybrid scan** (with artifacts):
```powershell
# Windows PowerShell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
$env:SSA_LOCAL_SOURCE="C:\path\to\staking_v24.move"
$env:SSA_LOCAL_ABI="C:\path\to\staking_v24.json"
npm run test:scan:hybrid
```

**Or using artifact directory:**
```powershell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
$env:SSA_LOCAL_ARTIFACT_DIR="C:\path\to\supra-ide-exports"
npm run test:scan:hybrid
```

**CLI with artifact path**:
```bash
pnpm scan --address 0x123... --module staking_v24 --artifact ./artifacts/staking_v24.move --out result.json
```

**CLI with artifact directory**:
```bash
pnpm scan --address 0x123... --module staking_v24 --artifact-dir ./artifacts --out result.json
```

**With user-specific views**:
```powershell
$env:RPC_URL="https://rpc-mainnet.supra.com"
$env:TARGET_ADDR="0xd1c64ad544a0fe534f4e2641a4515b6a0629b26c29f36d6423014b192b7abee3"
$env:TARGET_MOD="staking_v24"
$env:TARGET_USER="0x1234567890abcdef..."
$env:SSA_LOCAL_SOURCE="C:\path\to\staking_v24.move"
npm run test:scan:hybrid
```

#### Output

The scan summary includes:
- **Artifact Mode**: `VIEW_ONLY`, `ARTIFACT_ONLY`, or `HYBRID`
- **Rule Capabilities**: `viewOnly`, `hasAbi`, `hasBytecodeOrSource`, `artifactMode`
- **Artifact Loaded**: Whether local artifacts were loaded and which components (source/ABI/bytecode)
- **Origin**: `supra_ide_export`, `manual`, or `supra_rpc_v3` with path
- **On-chain bytecode fetched**: Whether bytecode was fetched from Supra RPC v3
- **Module ID match**: Whether local artifact module ID matches scan target (warns if mismatch)

If no artifacts are loaded, a hint is displayed:
```
Artifact Loaded: ❌
  Hint: To enable evidence-based scanning:
    - Export Move source/ABI from Supra IDE
    - Set SSA_LOCAL_SOURCE, SSA_LOCAL_BYTECODE, or SSA_LOCAL_ABI env vars
    - Or set SSA_LOCAL_ARTIFACT_DIR to a directory containing artifacts
```

**Module ID Validation:**
If a local source file contains a module declaration (`module 0xADDR::MODULE_NAME`), the scanner validates that it matches the scan target. If there's a mismatch, the scan result is marked as `INCONCLUSIVE` with a clear reason.

## Testing

Run tests:

```bash
pnpm test
```

Run tests with coverage:

```bash
pnpm test:coverage
```

## Guard Scripts and Contamination Checks

The project includes several guard scripts to prevent incorrect patterns and chain-specific references:

### RPC Guard

Prevents placeholder JSON-RPC methods from being introduced:

```bash
npm run guard:rpc
```

This script checks for forbidden patterns like `supra_getModule`, `sui_*`, `aptos_*`, or placeholder JSON-RPC methods. It runs automatically before builds (`prebuild` hook).

**Important**: All Supra RPC calls must use the `/rpc/v1/view` endpoint with the correct payload format:
```json
{
  "function": "0xADDR::module::function",
  "type_arguments": [],
  "arguments": []
}
```

### Contamination Checks

The `check:contamination` script is the authoritative check for chain-specific references (Sui/Aptos) in source code:

```bash
npm run check:contamination
```

**Note**: Guard scripts (`guard-rpc.js`, `guard-chain-words.js`, `guard-flavor.js`) intentionally contain Sui/Aptos matchers and are excluded from contamination checks. The contamination check scans only:
- `src/**` (source code)
- `scripts/**` (excluding guard scripts)
- Documentation files (excluding `CHANGES_SUMMARY.md`)

The contamination check excludes:
- `node_modules/**` (third-party dependencies)
- `dist/**` (compiled output)
- Guard scripts (which intentionally contain matchers)
- License files (may contain legal terms like "Sui Generis Database Rights")

If contamination is found, the build will fail with clear error messages showing file, line, and context.

## Project Structure

```
/ssa-scanner/
  package.json
  tsconfig.json
  vitest.config.ts
  /src/
    index.ts                 # CLI entry
    server.ts                # Express API entry
    /core/
      scanner.ts             # Scanner orchestrator
      types.ts               # Type definitions
      scoring.ts             # Risk scoring & verdict
      ruleset.ts             # Rule registry
      artifact.ts            # Artifact binding
    /rpc/
      supra.ts               # View-based module data fetcher
      viewRpc.ts             # Raw Supra view RPC implementation
      supraView.ts            # View call helper
      viewCallSmart.ts        # Environment-aware view resolver
    /rules/
      move/
        rule_001_*.ts        # Implemented rules
        ...
        rule_025.ts          # Stubbed rules
    /store/
      memoryStore.ts         # In-memory storage
      fileStore.ts           # File persistence
    /utils/
      hash.ts                # SHA256 helpers
      time.ts                # Timestamp helpers
      validate.ts            # Validation helpers
```

## Roadmap

- [ ] Implement remaining rules (011-025)
- [ ] Add `standard` and `full` scan levels
- [ ] Implement continuous monitoring (`monitor` mode)
- [ ] Onchain badge minting module
- [ ] Source code analysis support
- [ ] Enhanced ABI parsing
- [ ] Rule confidence improvements
- [ ] Historical scan tracking

## License

MIT



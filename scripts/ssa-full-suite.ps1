# scripts/ssa-full-suite.ps1
# Full suite scan for Fungible Assets and legacy coins using agent-verify
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/ssa-full-suite.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/ssa-full-suite.ps1 -Rpc "https://rpc-mainnet.supra.com" -Rpc2 "https://rpc-mainnet.supra.com" -TxLimit 1
#
# This script runs 3 variants for each target:
#   1) WITH_SUPRASCAN  => --with-suprascan true
#   2) NO_SUPRASCAN    => (omit suprascan flag)
#   3) PREFER_V2       => --prefer-v2

param(
    [string]$Rpc = $env:SUPRA_RPC_URL,
    [string]$Rpc2 = $env:SUPRA_RPC_URL,
    [int]$TxLimit = 1
)

# Target arrays - modify these to test different assets
$faTargets = @(
    "0x82ed1f483b5fc4ad105cef5330e480136d58156c30dc70cd2b9c342981997cee"
    # Add more FA addresses as needed
)

$coinTargets = @(
    "0x4742d10cab62d51473bb9b4752046705d40f056abcaa59bcb266078c5945b864::JOSH::JOSH"
    "SUPRA"
    # Add more coin types as needed
)

# Ensure we're in the repo root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

# Check if we're in the right directory (look for package.json)
if (-not (Test-Path "package.json")) {
    Write-Error "Error: package.json not found. Please run this script from the repo root or ensure the repo structure is correct."
    exit 1
}

# Build the project
Write-Host "Building project..." -ForegroundColor Cyan
$buildResult = npm run build 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed. Please fix build errors before running the suite."
    Write-Host $buildResult
    exit 1
}
Write-Host "Build successful." -ForegroundColor Green

# Ensure tmp directory exists
$tmpDir = Join-Path $repoRoot "tmp"
if (-not (Test-Path $tmpDir)) {
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
}

# Validate RPC URL
if ([string]::IsNullOrWhiteSpace($Rpc)) {
    Write-Error "Error: RPC URL not provided. Set SUPRA_RPC_URL environment variable or use -Rpc parameter."
    exit 1
}

# Sanitize filename (remove invalid Windows filename characters)
function Sanitize-Filename {
    param([string]$name)
    $invalidChars = [IO.Path]::GetInvalidFileNameChars()
    foreach ($char in $invalidChars) {
        $name = $name.Replace($char, "_")
    }
    return $name
}

# Safe property accessor (non-throwing)
# Returns $DefaultValue if property path doesn't exist
function SSA-SafeGet {
    param(
        [Parameter(Mandatory=$true)]$Obj,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)]$DefaultValue = $null
    )
    
    if ($null -eq $Obj) {
        return $DefaultValue
    }
    
    $parts = $Path -split '\.'
    $cur = $Obj
    
    foreach ($p in $parts) {
        if ($null -eq $cur) {
            return $DefaultValue
        }
        
        # Check if property exists using PSObject properties
        if ($cur -is [PSCustomObject] -or $cur -is [System.Collections.Specialized.OrderedDictionary] -or $cur.GetType().Name -eq "PSCustomObject") {
            if ($cur.PSObject.Properties.Name -notcontains $p) {
                return $DefaultValue
            }
            $cur = $cur.PSObject.Properties[$p].Value
        } elseif ($cur -is [hashtable]) {
            if (-not $cur.ContainsKey($p)) {
                return $DefaultValue
            }
            $cur = $cur[$p]
        } else {
            # Try dynamic property access as fallback (but check first)
            try {
                $prop = $cur.PSObject.Properties[$p]
                if ($null -eq $prop) {
                    return $DefaultValue
                }
                $cur = $prop.Value
            } catch {
                return $DefaultValue
            }
        }
    }
    
    return $cur
}

# Generate compact report line from JSON report
function Format-CompactReport {
    param(
        [Parameter(Mandatory=$true)]$ReportJson,
        [Parameter(Mandatory=$true)][string]$Label
    )
    
    $kind = SSA-SafeGet -Obj $ReportJson -Path "target.kind" -DefaultValue "unknown"
    $tier = SSA-SafeGet -Obj $ReportJson -Path "overallEvidenceTier" -DefaultValue "unknown"
    $risk = SSA-SafeGet -Obj $ReportJson -Path "risk.risk_level" -DefaultValue "UNKNOWN"
    
    # Kind-aware SupraScan status extraction
    $suprascanStatus = "n/a"
    if ($kind -eq "fa") {
        $suprascanStatus = SSA-SafeGet -Obj $ReportJson -Path "suprascan_fa.status" -DefaultValue "n/a"
    } elseif ($kind -eq "coin") {
        $suprascanStatus = SSA-SafeGet -Obj $ReportJson -Path "suprascan_coin.status" -DefaultValue "n/a"
    }
    
    $supplyParity = SSA-SafeGet -Obj $ReportJson -Path "indexer_parity.details.supplyParity" -DefaultValue "n/a"
    $behaviorSource = SSA-SafeGet -Obj $ReportJson -Path "behavior.source" -DefaultValue "none"
    
    return "${Label} | ${kind} | tier=${tier} risk=${risk} suprascan=${suprascanStatus} supplyParity=${supplyParity} behavior=${behaviorSource}"
}

# Run agent-verify with error handling
function Run-AgentVerify {
    param(
        [string]$TargetKind,  # "fa" or "coin"
        [string]$TargetId,
        [string]$VariantLabel,
        [string[]]$ExtraArgs
    )
    
    # Ensure tmp directory exists before writing
    $tmpDir = Join-Path $repoRoot "tmp"
    if (-not (Test-Path $tmpDir)) {
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    }
    
    $sanitizedTarget = Sanitize-Filename $TargetId
    $sanitizedLabel = Sanitize-Filename $VariantLabel
    $outputFile = "tmp/suite_${TargetKind}_${sanitizedLabel}_${sanitizedTarget}.json"
    # Truncate if too long (Windows path limit)
    if ($outputFile.Length -gt 200) {
        $hash = ($TargetId + $VariantLabel).GetHashCode().ToString("X")
        $outputFile = "tmp/suite_${TargetKind}_${hash}.json"
    }
    
    $targetArg = if ($TargetKind -eq "fa") { "--fa" } else { "--coin" }
    $targetValue = $TargetId
    
    $args = @(
        "dist/src/scripts/agent-verify.js"
        $targetArg
        $targetValue
        "--rpc"
        $Rpc
        "--rpc2"
        $Rpc2
        "--mode"
        "agent"
        "--tx-limit"
        $TxLimit.ToString()
        "--quiet"
        "--out"
        $outputFile
    ) + $ExtraArgs
    
    try {
        # Suppress all output to avoid PowerShell errors in output stream
        $errorOutput = node $args 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            # Read JSON file and generate compact report
            if (Test-Path $outputFile) {
                try {
                    $reportJson = Get-Content $outputFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $compactLine = Format-CompactReport -ReportJson $reportJson -Label $VariantLabel
                    Write-Host $compactLine
                    return $true
                } catch {
                    # Print compact line with error status instead of separate error line
                    $kind = $TargetKind
                    Write-Host "${VariantLabel} | ${kind} | tier=error risk=UNKNOWN suprascan=n/a supplyParity=n/a behavior=none"
                    return $false
                }
            } else {
                # Print compact line with error status
                $kind = $TargetKind
                Write-Host "${VariantLabel} | ${kind} | tier=error risk=UNKNOWN suprascan=n/a supplyParity=n/a behavior=none"
                return $false
            }
        } else {
            # Print compact line with error status (don't print separate error line)
            $kind = $TargetKind
            Write-Host "${VariantLabel} | ${kind} | tier=error risk=UNKNOWN suprascan=n/a supplyParity=n/a behavior=none"
            return $false
        }
    } catch {
        # Print compact line with error status
        $kind = $TargetKind
        Write-Host "${VariantLabel} | ${kind} | tier=error risk=UNKNOWN suprascan=n/a supplyParity=n/a behavior=none"
        return $false
    }
}

# Run suite for a single target
function Run-TargetSuite {
    param(
        [string]$TargetKind,  # "fa" or "coin"
        [string]$TargetId
    )
    
    $header = "=== $($TargetKind.ToUpper()) $TargetId ==="
    Write-Host $header -ForegroundColor Yellow
    
    # Variant 1: WITH_SUPRASCAN
    Run-AgentVerify -TargetKind $TargetKind -TargetId $TargetId -VariantLabel "WITH_SUPRASCAN" -ExtraArgs @("--with-suprascan", "true") | Out-Null
    
    # Variant 2: NO_SUPRASCAN
    Run-AgentVerify -TargetKind $TargetKind -TargetId $TargetId -VariantLabel "NO_SUPRASCAN" -ExtraArgs @() | Out-Null
    
    # Variant 3: PREFER_V2
    Run-AgentVerify -TargetKind $TargetKind -TargetId $TargetId -VariantLabel "PREFER_V2" -ExtraArgs @("--prefer-v2") | Out-Null
}

# Main execution
# (Header and status messages removed to ensure clean output: header + exactly 3 lines per target)

# Run suite for FA targets
if ($faTargets.Count -gt 0) {
    foreach ($fa in $faTargets) {
        Run-TargetSuite -TargetKind "fa" -TargetId $fa
    }
}

# Run suite for Coin targets
if ($coinTargets.Count -gt 0) {
    foreach ($coin in $coinTargets) {
        Run-TargetSuite -TargetKind "coin" -TargetId $coin
    }
}



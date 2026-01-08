# SSA Verification Levels Specification

## Overview

SSA (Supra Security Agent) uses a tiered verification level system to assess security at increasing depths. Verification levels determine both the scope of analysis and badge eligibility.

**Key Principle:** Higher verification levels provide more comprehensive security assessment and enable higher-tier badges.

## Verification Level Structure

### Coins and Fungible Assets (FAs)

Coins and FAs support **Levels 1–5**:

#### Level 1: Surface Verification

**Scope:**
- Basic surface-level analysis
- Entry point inspection
- Metadata verification
- Quick security checks

**Badge Eligibility:**
- ✅ Surface Verified (if pass, no critical/high findings)

**Duration:** Fastest scan (typically seconds)

**Use Case:** Initial security screening, quick verification

#### Level 2: Standard Verification

**Scope:**
- Level 1 analysis plus:
- Function signature analysis
- ABI inspection
- Resource structure verification
- Enhanced rule checking

**Badge Eligibility:**
- ✅ Surface Verified (if Level 1 passes, no critical/high findings)
- ✅ Security Verified (if Levels 1–3 all pass, no critical/high findings)

**Duration:** Moderate scan (typically minutes)

**Use Case:** Standard security verification, pre-deployment checks

#### Level 3: Full Verification

**Scope:**
- Levels 1–2 analysis plus:
- Deep code analysis
- Control flow inspection
- Capability analysis
- Comprehensive rule checking
- Multi-source verification

**Badge Eligibility:**
- ✅ Surface Verified (if pass, no critical/high findings)
- ✅ Security Verified (if Levels 1–3 pass, risk ≤ 10, no critical/high findings)

**Duration:** Longer scan (typically 5–15 minutes)

**Use Case:** Comprehensive security verification, production readiness

#### Level 4: Snapshot Monitoring

**Scope:**
- Levels 1–3 analysis plus:
- Baseline snapshot creation
- State fingerprinting
- Resource tracking
- Change detection preparation

**Badge Eligibility:**
- ✅ Surface Verified (if Level 1 passes, no critical/high findings)
- ✅ Security Verified (if Levels 1, 2, and 3 all pass, no critical/high findings)
- ✅ Continuously Monitored (if Levels 4–5 enabled and active, no critical/high findings, badge includes expiry timestamp)

**Duration:** Extended scan (typically 10–30 minutes)

**Use Case:** Establishing monitoring baseline, change tracking

**Note:** Level 4 creates a snapshot baseline. Level 5 performs diff analysis against this baseline.

#### Level 5: Diff Monitoring

**Scope:**
- Levels 1–4 analysis plus:
- Snapshot comparison
- Change detection
- Drift analysis
- Continuous monitoring

**Badge Eligibility:**
- ✅ Surface Verified (if Level 1 passes, no critical/high findings)
- ✅ Security Verified (if Levels 1, 2, and 3 all pass, no critical/high findings)
- ✅ Continuously Monitored (if Levels 4–5 enabled and active, no critical/high findings, badge includes expiry timestamp)

**Duration:** Extended scan with diff analysis (typically 15–45 minutes)

**Use Case:** Active monitoring, change detection, continuous verification

**Note:** Level 5 requires a previous snapshot (from Level 4) or two snapshots for comparison.

### Wallets

Wallets support **Levels 1–3 only**:

#### Level 1: Wallet Surface Verification

**Scope:**
- Basic wallet address verification
- Module enumeration
- Account status check
- Quick security screening

**Badge Eligibility:**
- ✅ Wallet Verified (if pass, no critical findings)

**Duration:** Fast scan (typically seconds)

**Use Case:** Initial wallet verification

#### Level 2: Wallet Standard Verification

**Scope:**
- Level 1 analysis plus:
- Module-by-module scanning
- Capability analysis
- Resource inspection
- Enhanced security checks

**Badge Eligibility:**
- ✅ Wallet Verified (if Levels 1–2 pass, no critical findings)

**Duration:** Moderate scan (typically minutes)

**Use Case:** Standard wallet verification

#### Level 3: Wallet Full Verification

**Scope:**
- Levels 1–2 analysis plus:
- Comprehensive module analysis
- Deep security inspection
- Multi-source verification
- Complete wallet assessment

**Badge Eligibility:**
- ✅ Wallet Verified (if Levels 1–3 pass, no critical findings)

**Duration:** Longer scan (typically 5–15 minutes)

**Use Case:** Comprehensive wallet verification

#### Levels 4–5: Not Applicable

**Wallets do NOT support Levels 4–5:**

- ❌ Snapshot monitoring (Level 4) is not applicable to wallets
- ❌ Diff monitoring (Level 5) is not applicable to wallets

**Rationale:** Wallets are account addresses, not contracts. Snapshot and diff monitoring are designed for contract state tracking, which does not apply to wallet addresses.

## Level Progression

### Coins/FAs

```
Level 1 → Surface Verified (if passes, no critical/high findings)
Levels 1–3 → Security Verified (if all pass, no critical/high findings)
Levels 4–5 → Continuously Monitored (if enabled and active, badge includes expiry timestamp)
```

### Wallets

```
Level 1 → Wallet Verified (if pass, no critical)
Level 1–3 → Wallet Verified (if all pass, no critical)
Level 4–5 → Not applicable
```

## Badge Eligibility by Level

### Surface Verified

- **Coins/FAs:** Level 1 passes (no critical/high findings)
- **Wallets:** Not applicable (wallets use Wallet Verified)

### Security Verified

- **Coins/FAs:** Levels 1, 2, and 3 all pass (no critical/high findings)
- **Wallets:** Not applicable (wallets use Wallet Verified)

### Continuously Monitored

- **Coins/FAs:** Levels 4–5 enabled and active (no critical/high findings, badge includes expiry timestamp)
- **Wallets:** Not applicable (wallets do not support Levels 4–5)

### Wallet Verified

- **Wallets:** Levels 1–3 must all pass
- **Coins/FAs:** Not applicable (contracts use other badges)

## Level Requirements Summary

| Level | Coins/FAs | Wallets | Badge Eligibility |
|-------|-----------|---------|-------------------|
| 1 | ✅ Surface analysis | ✅ Wallet surface | Surface Verified / Wallet Verified |
| 2 | ✅ Standard analysis | ✅ Wallet standard | Security Verified / Wallet Verified |
| 3 | ✅ Full analysis | ✅ Wallet full | Security Verified / Wallet Verified |
| 4 | ✅ Snapshot baseline | ❌ Not applicable | Continuously Monitored |
| 5 | ✅ Diff monitoring | ❌ Not applicable | Continuously Monitored |

## Verification Failure

If verification fails at any level:

- **No badge is issued**
- Public verification page states: "SSA verification failed — [reason]"
- Full report contains detailed findings
- Risk states are displayed separately (not as badges)

## Level Selection Guidance

### For Quick Verification

- **Coins/FAs:** Level 1 (Surface Verified eligibility)
- **Wallets:** Level 1 (Wallet Verified eligibility)

### For Standard Verification

- **Coins/FAs:** Level 2 (Surface Verified or Security Verified eligibility)
- **Wallets:** Level 2 (Wallet Verified eligibility)

### For Comprehensive Verification

- **Coins/FAs:** Level 3 (Security Verified eligibility)
- **Wallets:** Level 3 (Wallet Verified eligibility)

### For Monitoring

- **Coins/FAs:** Levels 4–5 (Continuously Monitored eligibility)
- **Wallets:** Not applicable (use Levels 1–3 only)

## Implementation Notes

### Level Mapping

Scan levels map to internal scan modes:

- Level 1 → "quick"
- Level 2 → "standard"
- Level 3 → "full"
- Level 4 → "monitor" (snapshot)
- Level 5 → "monitor" (diff)

### Level Validation

- Coins/FAs: Levels 1–5 are valid
- Wallets: Levels 1–3 are valid (Levels 4–5 return error)

### Level Progression

- Levels must be completed sequentially for badge eligibility
- Security Verified requires Levels 1–3 all pass
- Wallet Verified requires Levels 1–3 all pass
- Continuously Monitored requires Levels 4–5 active

## Policy Reference

For complete policy details, see:
- `docs/badges.md` - Badge tier specifications
- `docs/ssa-badges-and-risk-policy.md` - Complete badge and risk policy
- `docs/public-verification.md` - Public verification page guidelines

---

**Specification Version:** 1.0  
**Last Updated:** 2024-01-01  
**Authority:** SSA Scanner Core Team

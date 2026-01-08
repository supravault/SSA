# SSA Badge Specification

## Overview

SSA (Supra Security Agent) issues cryptographically signed verification badges that represent positive security attestations. Badges are **not** risk scores or failure indicators—they are earned verification statuses that indicate a contract or wallet has passed security verification at a specific level.

**Core Principle**: Badges represent **positive verification only**. The absence of a badge indicates that verification requirements were not met, not that a "failure badge" was issued.

## Official Badge Tiers

SSA issues five official verification badge tiers:

### 1. SSA · Fully Integrated

**Issuance Criteria:**
- Scan passes at chosen level (Level 1+ for Surface, Level 3+ for Security, Level 5 for Continuously Monitored)
- Verdict: pass
- No critical severity findings
- No high severity findings
- **Supra Pulse report attached and included in PDF**

**Expiry:** 30 days from scan timestamp (or rolling if Continuously Monitored base)

**Purpose:** Indicates the highest level of verification, combining SSA security analysis with Supra Pulse intelligence integration. This badge represents comprehensive security assessment with external intelligence.

**Display:** Safe for public display (web, PDF, GitHub, Base44, social media)

**Cryptographic Signing:** Yes (Ed25519)

**Note:** This is the highest tier badge. It requires both SSA verification and Supra Pulse integration.

### 2. SSA · Surface Verified

**Issuance Criteria:**
- Scan Level: 1 passes
- Verdict: pass
- No critical severity findings
- No high severity findings

**Expiry:** 14 days from scan timestamp

**Purpose:** Indicates that a contract has passed basic surface-level security verification (Level 1) with no critical or high-severity issues detected.

**Display:** Safe for public display (web, PDF, GitHub, Base44, social media)

**Cryptographic Signing:** Yes (Ed25519)

### 3. SSA · Security Verified

**Issuance Criteria:**
- Scan Levels: 1, 2, and 3 must all pass
- Verdict: pass (at all levels)
- No critical severity findings
- No high severity findings

**Expiry:** 30 days from scan timestamp

**Purpose:** Indicates a higher level of confidence in the contract's security posture, requiring successful verification across all three standard scan levels (1–3) with no critical or high-severity findings.

**Display:** Safe for public display (web, PDF, GitHub, Base44, social media)

**Cryptographic Signing:** Yes (Ed25519)

### 4. SSA · Continuously Monitored

**Issuance Criteria:**
- Scan Levels: 4–5 enabled and active
- Verdict: pass
- Monitoring: enabled and active
- No critical severity findings
- No high severity findings

**Expiry:** Must include expiry timestamp (rolling expiry—badge remains valid as long as monitoring is active)

**Purpose:** Indicates that a contract is under active, continuous security monitoring. This is the highest tier badge and requires ongoing monitoring infrastructure with snapshot and diff analysis (Levels 4–5).

**Display:** Safe for public display (web, PDF, GitHub, Base44, social media)

**Cryptographic Signing:** Yes (Ed25519)

**Note:** Levels 4–5 involve snapshot and diff monitoring, which are not applicable to wallet scans.

### 5. SSA · Wallet Verified

**Issuance Criteria:**
- Target Type: wallet or creator
- Scan Levels: 1, 2, or 3 (must pass all)
- Verdict: pass
- No critical severity findings

**Expiry:** 7 days from scan timestamp

**Purpose:** Indicates that a wallet/creator address has been scanned and verified. **Important**: This badge does NOT guarantee the security of contracts published by the wallet.

**Display:** Safe for public display (web, PDF, GitHub, Base44, social media)

**Cryptographic Signing:** Yes (Ed25519)

**Note:** Wallet scans only support levels 1–3. Levels 4–5 (snapshot/diff monitoring) are not applicable to wallets.

## Badge Eligibility Rules

### Coins and Fungible Assets (FAs)

**Surface Verified:**
- Level 1 passes
- No critical/high findings

**Security Verified:**
- Levels 1, 2, and 3 all pass
- No critical/high findings

**Continuously Monitored:**
- Levels 4–5 enabled and active
- No critical/high findings
- Badge must include expiry timestamp

**Fully Integrated:**
- Any of the above badges (Surface/Security/Continuously Monitored) eligible
- **AND** Supra Pulse report attached and included in PDF
- No critical/high findings

### Wallets

**Wallet Verified:**
- Levels 1–3 all pass (wallet scans only support levels 1–3)
- No critical findings

**Note:** Wallets cannot receive Surface Verified, Security Verified, or Continuously Monitored badges. These badges are contract-specific.

## Badge Suppression Rules

### Critical Findings

**If `critical_findings > 0`:**
- ❌ **All badges are BLOCKED**
- No badge is issued
- Public verification page must display: "SSA verification failed — critical security findings detected"
- Severity details remain visible in full report only

### High Findings

**If `high_findings > 0` AND `critical_findings === 0`:**
- ❌ **Security Verified** is BLOCKED
- ❌ **Continuously Monitored** is BLOCKED
- ✅ **Surface Verified** may be issued (if Level 1 passes)
- ✅ **Wallet Verified** may be issued (if wallet Levels 1–3 pass)

### No Critical or High Findings

**If `critical_findings === 0` AND `high_findings === 0`:**
- ✅ Badges may be issued normally according to tier requirements

## What SSA Does NOT Issue

SSA **explicitly does not** issue:

- ❌ "Critical Risk" badge
- ❌ "High Risk" badge
- ❌ "Unsafe" badge
- ❌ "Failure" badge
- ❌ Any red/danger/warning public badge
- ❌ Any negative attestation badge

**Rationale:** Badges represent positive verification. Risk states and findings are communicated separately as warnings, alerts, or risk indicators—never as badges.

## Badge Display Guidelines

### When Badge is Issued

- Display shield iconography
- Show badge label (e.g., "SSA · Security Verified")
- Show expiry date if applicable
- Show signature fingerprint if signed
- Use positive, verification-focused language

### When Badge is Not Issued

- Do NOT display any badge
- Display verification status message:
  - "SSA verification failed — critical security findings detected" (if critical findings)
  - "SSA verification incomplete — requirements not met" (if other reasons)
- Show risk state separately (not as a badge)
- Link to full report for details

## Cryptographic Verification

All SSA badges are cryptographically signed using Ed25519 signatures:

- **Public Key:** Published in `docs/keys/ssa_public_key.json`
- **Signature:** Included in badge payload
- **Fingerprint:** Short hash (16 hex chars) for quick verification
- **Verification:** Use `verifyBadge()` function from `src/crypto/badgeSigner.ts`

## Badge Files

When a badge is issued, the following files are generated:

- `report.json`: Contains `badge` and `signed_badge` fields
- `summary.json`: Contains `badge` field with tier, label, and expiry
- `badge_<scanId>.json`: Standalone signed badge file
- `report.pdf`: Includes badge information in report metadata

## Integration Points

### Base44 UI

- Consume badge policy from `src/policy/badgePolicy.ts`
- Display badges using shield iconography
- Display verification failure messages when no badge is issued
- Show risk states separately (not as badges)

### PDF Reports

- Include badge section with shield visuals
- Include verification status section
- Show suppression warnings when applicable
- Use consistent terminology throughout

### CLI Output

- Display badge tier clearly when issued
- Display verification failure message when no badge
- Show suppression reasons when badges are blocked
- Use correct terminology in all messages

### API Responses

- Include `badge` field with tier information (or null if no badge)
- Include `verification_status` field ("verified" | "failed" | "incomplete")
- Include `suppression_reason` when badge is blocked
- Never return negative badges

## Absence of Badge

**Important:** The absence of a badge does NOT mean a "failure badge" was issued. It means:

1. Verification requirements were not met
2. Critical or high findings were detected
3. Scan level requirements were not satisfied
4. Verdict was not "pass"

When no badge is issued, the public verification page must clearly state the reason (e.g., "SSA verification failed — critical security findings detected").

## Policy Reference

For complete policy details, see:
- `docs/ssa-badges-and-risk-policy.md` - Complete badge and risk policy
- `docs/verification-levels.md` - Detailed verification level specifications
- `docs/public-verification.md` - Public verification page guidelines

---

**Specification Version:** 1.0  
**Last Updated:** 2024-01-01  
**Authority:** SSA Scanner Core Team

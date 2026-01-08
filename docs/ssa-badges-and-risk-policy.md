# SSA Badges and Risk Policy

## Overview

This document defines the authoritative policy for SSA (Supra Security Agent) badge issuance, risk states, and the relationship between verification badges and security findings. This policy ensures consistency across all SSA outputs: CLI, API, PDF reports, Base44 UI, and public displays.

**Core Principle**: Badges represent **positive verification states only**. Risk findings are communicated separately as warnings, alerts, or risk states—never as badges.

## Part 1: Official SSA Badge Tiers

SSA issues four official verification badges, all representing positive security verification:

### 1. SSA · Surface Verified

**Iconography**: Shield-based badge  
**Purpose**: Basic surface-level security verification  
**Display**: Safe for public display (web, PDF, GitHub, Base44, social media)

**Requirements**:
- Scan level 4 or higher
- Verdict: pass
- No critical severity findings
- No high severity findings

**Expiry**: 14 days from scan timestamp

**Use Case**: Indicates that a contract has passed automated security checks at the surface level with no critical or high-severity issues detected.

### 2. SSA · Security Verified

**Iconography**: Shield-based badge  
**Purpose**: High-confidence security verification  
**Display**: Safe for public display (web, PDF, GitHub, Base44, social media)

**Requirements**:
- Scan level 4 or higher
- Verdict: pass
- Risk score ≤ 10 (configurable threshold)
- No critical severity findings
- No high severity findings

**Expiry**: 30 days from scan timestamp

**Use Case**: Indicates a higher level of confidence in the contract's security posture, requiring both a pass verdict and a low risk score.

### 3. SSA · Continuously Monitored

**Iconography**: Shield-based badge  
**Purpose**: Highest tier for contracts under active monitoring  
**Display**: Safe for public display (web, PDF, GitHub, Base44, social media)

**Requirements**:
- Scan level 5
- Verdict: pass
- Monitoring enabled
- No critical severity findings
- No high severity findings

**Expiry**: None (rolling expiry—badge remains valid as long as monitoring is active)

**Use Case**: Indicates that a contract is under active, continuous security monitoring. This is the highest tier badge.

### 4. SSA · Wallet Verified

**Iconography**: Shield-based badge  
**Purpose**: Wallet/creator address verification  
**Display**: Safe for public display (web, PDF, GitHub, Base44, social media)

**Requirements**:
- Target type: wallet or creator
- Scan level 1-3 (wallet scans only support levels 1-3)
- Verdict: pass

**Expiry**: 7 days from scan timestamp

**Use Case**: Indicates that a wallet/creator address has been scanned and verified. **Important**: This badge does NOT guarantee the security of contracts published by the wallet.

### Badge Naming Rules

**MUST NOT** exist:
- ❌ "Critical Risk"
- ❌ "High Risk"
- ❌ "Unsafe"
- ❌ "Risk Verified"
- ❌ Any negative or risk-based badge name

**MUST** use:
- ✅ Shield-based iconography
- ✅ Positive verification language
- ✅ "Verified" or "Monitored" terminology only

## Part 2: Risk States (Non-Badge)

Risk states are **separate from badges** and represent security findings, warnings, and alerts. They are **never** displayed as badges.

### Risk State Definitions

1. **Info**: Informational findings, no immediate security concern
2. **Low**: Minor security concerns, best practices not followed
3. **Medium**: Moderate security concerns, potential vulnerabilities
4. **High**: Significant security concerns, active vulnerabilities
5. **Critical**: Severe security concerns, immediate threats

### Risk State Display Rules

- Risk states are **NOT badges**
- Risk states are shown as:
  - Banners
  - Alerts
  - Text indicators
  - Warning icons
- Risk states **must never** use shield-style badge visuals
- Risk states are informational/warning only

### Risk State vs Badge

| Concept | Type | Visual | Purpose |
|---------|------|--------|---------|
| Badge | Positive verification | Shield icon | Earned status |
| Risk State | Finding/warning | Alert/banner | Security concern |

## Part 3: Badge Suppression & Blocking Logic

### Authoritative Rules

#### Rule 1: Critical Findings Block All Badges

**If `critical_findings > 0`:**

- ❌ **Security Verified** badge is **BLOCKED**
- ❌ **Wallet Verified** badge is **BLOCKED**
- ⚠️ **Surface Verified** may show **ONLY** with a visible warning banner:
  - Warning text: "⚠️ SSA Alert: Critical Risk Detected. Verification badges are withheld."
  - Badge must be visually suppressed or grayed out
  - Warning must be prominently displayed

**Rationale**: Critical findings represent immediate security threats. No verification badge should be issued when critical issues are present.

#### Rule 2: High Findings Conditionally Block Security Verified

**If `high_findings > 0` AND `critical_findings === 0`:**

- ⚠️ **Security Verified** is **BLOCKED** (high findings disqualify this tier)
- ✅ **Surface Verified** may be issued (with optional warning)
- ✅ **Wallet Verified** may be issued (wallet scans may have different thresholds)

**Rationale**: High findings represent significant security concerns. While Surface Verified may still be appropriate, Security Verified requires a higher standard.

#### Rule 3: No Critical or High Findings

**If `critical_findings === 0` AND `high_findings === 0`:**

- ✅ Badges may be issued normally according to tier requirements
- ✅ No suppression or blocking applies

**Rationale**: When no critical or high findings are present, badges can be issued based on scan level, verdict, and risk score.

### Suppression Implementation

The badge policy module (`src/policy/badgePolicy.ts`) enforces these rules:

1. **Pre-check**: Before badge derivation, check severity counts
2. **Blocking**: Return `NONE` tier if blocking conditions are met
3. **Warning**: Include reason in badge result when suppression occurs
4. **Surface Verified Exception**: May be issued with warning if only critical findings exist (implementation decision)

## Part 4: Terminology Enforcement

### Correct Terminology

**For Badges:**
- ✅ "Verification Badge"
- ✅ "SSA Badge"
- ✅ "Security Verification"
- ✅ "Verified Status"

**For Risk States:**
- ✅ "Risk State"
- ✅ "Risk Alert"
- ✅ "Security Finding"
- ✅ "Risk Warning"

### Incorrect Terminology (MUST NOT USE)

- ❌ "Critical Risk Verified"
- ❌ "High Risk Badge"
- ❌ "Unsafe Badge"
- ❌ "Risk Badge"
- ❌ "Verified Risk"

### Example Usage

**Correct Example:**
```
⚠️ SSA Alert: Critical Risk Detected
Verification badges are withheld.

Risk State: Critical
Findings: 2 critical, 3 high
```

**Incorrect Example:**
```
❌ SSA Critical Risk Verified
❌ High Risk Badge Issued
```

## Part 5: UX Guidance

### Badge Display

**When Badge is Issued:**
- Display shield icon
- Show badge label (e.g., "SSA · Security Verified")
- Show expiry date if applicable
- Show signature fingerprint if signed
- Use positive, verification-focused language

**When Badge is Blocked:**
- Do NOT display badge
- Display risk alert/warning instead
- Explain why badge is withheld
- Show risk state prominently

### Risk State Display

**Visual Treatment:**
- Use alert/banner styling (not shield)
- Use warning colors (yellow/red)
- Use warning icons (⚠️, ⛔)
- Position prominently (top of page/report)
- Include severity level clearly

**Content:**
- State severity level (Critical, High, etc.)
- List finding count by severity
- Provide actionable information
- Link to detailed findings

### Combined Display

When both badge and risk state are present:

```
[Badge Display Area]
SSA · Surface Verified
Expires: 2024-01-15

[Risk Alert Banner]
⚠️ Warning: 1 High severity finding detected
This may affect security posture.
```

## Part 6: Cryptographic Signing

**Badge Signing:**
- Only verification badges are cryptographically signed
- Risk states are **never** signed as badges
- Signed badges include signature fingerprint for verification
- Public key is published in `docs/keys/ssa_public_key.json`

**Signing Scope:**
- ✅ SSA · Surface Verified → Signed
- ✅ SSA · Security Verified → Signed
- ✅ SSA · Continuously Monitored → Signed
- ✅ SSA · Wallet Verified → Signed
- ❌ Risk States → Never signed

## Part 7: Integration Points

### Base44 UI

- Consume badge policy from `src/policy/badgePolicy.ts`
- Display badges using shield iconography
- Display risk states as alerts/banners
- Enforce suppression rules client-side
- Show warnings when badges are blocked

### PDF Reports

- Include badge section with shield visuals
- Include risk alert section (separate from badges)
- Show suppression warnings when applicable
- Use consistent terminology throughout

### CLI Output

- Display badge tier clearly
- Display risk states separately
- Show suppression reasons when badges are blocked
- Use correct terminology in all messages

### API Responses

- Include `badge` field with tier information
- Include `risk_state` field separately
- Include `badge_suppressed` boolean when applicable
- Include `suppression_reason` when suppressed

## Part 8: Rationale

### Why Risk ≠ Badge

1. **Semantic Clarity**: Badges represent positive verification. Risk represents concerns. Mixing these concepts creates confusion.

2. **User Safety**: Displaying a "Critical Risk Badge" could be misinterpreted as a positive status, leading to unsafe decisions.

3. **Trust**: Verification badges must represent trust and safety. Associating badges with risk undermines this trust.

4. **Visual Clarity**: Shield iconography for badges, alert iconography for risks—clear visual distinction prevents confusion.

5. **Regulatory Compliance**: Clear separation of verification status and risk warnings supports compliance and transparency.

## Part 9: Policy Enforcement

### Code Enforcement

The following modules enforce this policy:

- `src/policy/badgePolicy.ts`: Badge derivation and suppression logic
- `src/core/scoring.ts`: Risk score calculation (separate from badges)
- `src/cli/ssa.ts`: CLI badge display
- `src/cli/pdf.ts`: PDF badge rendering
- `src/api/ssaRoutes.ts`: API badge responses

### Validation

All badge issuance must:
1. Check severity counts before badge derivation
2. Apply suppression rules
3. Return `NONE` tier if blocking conditions are met
4. Include suppression reason in badge result

### Testing

Unit tests verify:
- Badges are blocked when critical findings exist
- Badges are blocked when high findings exist (for Security Verified)
- No negative badges are ever issued
- Risk states are separate from badges

## Part 10: Future Considerations

### Monitoring

- Continuous monitoring may adjust badge status based on new findings
- Badges may be revoked if critical findings are discovered post-issuance
- Monitoring status affects badge expiry (rolling vs fixed)

### Policy Updates

- This policy is versioned and authoritative
- Changes require review and approval
- Breaking changes must be documented and communicated

### Integration

- Base44 UI will consume this policy
- PDF reports must follow this logic
- All public displays must adhere to badge/risk separation
- API consumers must understand badge vs risk distinction

---

**Policy Version**: 1.0  
**Last Updated**: 2024-01-01  
**Authority**: SSA Scanner Core Team

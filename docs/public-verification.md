# SSA Public Verification Page Specification

## Overview

This document defines the canonical specification for SSA public verification pages. These pages display verification status, badges, and risk information in a consistent, user-friendly format suitable for public consumption.

**Core Principle:** Public verification pages must clearly communicate verification status, badge eligibility, and risk information without creating confusion between positive verification badges and negative risk indicators.

## Page Structure

### Header Section

**Required Elements:**
- SSA logo/branding
- Target identifier (coin type, FA address, or wallet address)
- Scan timestamp
- Verification status indicator

**Verification Status Values:**
- ✅ "Verified" (badge issued)
- ❌ "Verification Failed" (no badge, critical findings)
- ⚠️ "Verification Incomplete" (no badge, other reasons)

### Badge Display Section

**When Badge is Issued:**

```
┌─────────────────────────────────┐
│  [Shield Icon]                  │
│  SSA · Security Verified        │
│  Expires: 2024-01-15            │
│  Signature: ABC123...           │
│  [Verify Badge] button          │
└─────────────────────────────────┘
```

**Required Elements:**
- Shield-based badge icon
- Badge label (e.g., "SSA · Security Verified")
- Expiry date (if applicable)
- Signature fingerprint (for verification)
- "Verify Badge" button/link

**When Badge is NOT Issued:**

```
┌─────────────────────────────────┐
│  ⚠️ SSA Verification Failed     │
│                                  │
│  Critical security findings     │
│  detected.                      │
│                                  │
│  Verification badges are        │
│  withheld.                       │
│                                  │
│  [View Full Report]             │
└─────────────────────────────────┘
```

**Required Elements:**
- Clear failure message
- Reason for failure
- Link to full report
- NO badge icon or shield imagery

### Risk State Section

**Display Format:**

```
Risk State: Critical
Findings: 2 critical, 3 high, 5 medium

[View Detailed Findings]
```

**Required Elements:**
- Risk state label (Critical, High, Medium, Low, Info)
- Finding counts by severity
- Link to detailed findings
- Visual treatment: Alert/banner style (NOT shield badge style)

**Visual Guidelines:**
- Use alert colors (red for critical, orange for high, yellow for medium)
- Use warning icons (⚠️, ⛔)
- Position prominently but separately from badge section
- Never use shield iconography for risk states

### Verification Details Section

**Required Information:**
- Scan level(s) completed
- Verification timestamp
- Scan duration
- RPC endpoint used
- Scanner version

**Optional Information:**
- Risk score
- Finding summary
- Capabilities detected

### Badge Eligibility Explanation

**When Badge is Issued:**

```
This contract has earned the SSA · Security Verified badge
by passing security verification at Levels 1–3 with no
critical or high severity findings.
```

**When Badge is NOT Issued:**

```
This contract did not meet the requirements for SSA
verification badges. Critical security findings were
detected during scanning.
```

## Badge Display Rules

### Fully Integrated

**Display:**
- Shield icon (gold/premium)
- Label: "SSA · Fully Integrated"
- Expiry: "Expires: [date]" or "Active monitoring (rolling)"
- Explanation: "Comprehensive security verification with Supra Pulse intelligence integration"
- Note: "Includes SSA security analysis + Supra Pulse report"

### Surface Verified

**Display:**
- Shield icon (blue/green)
- Label: "SSA · Surface Verified"
- Expiry: "Expires: [date]"
- Explanation: "Passed Level 1 security verification"

### Security Verified

**Display:**
- Shield icon (green)
- Label: "SSA · Security Verified"
- Expiry: "Expires: [date]"
- Explanation: "Passed Levels 1, 2, and 3 security verification with no critical or high severity findings"

### Continuously Monitored

**Display:**
- Shield icon (green with monitoring indicator)
- Label: "SSA · Continuously Monitored"
- Expiry: "Active monitoring (rolling)" + expiry timestamp displayed
- Explanation: "Under active security monitoring (Levels 4–5 enabled and active)"

### Wallet Verified

**Display:**
- Shield icon (blue)
- Label: "SSA · Wallet Verified"
- Expiry: "Expires: [date]"
- Explanation: "Wallet address verified (Levels 1–3)"
- Disclaimer: "This badge verifies the wallet address only, not contracts published by this wallet."

## Failure Message Templates

### Critical Findings Detected

```
⚠️ SSA Verification Failed

Critical security findings detected.

Verification badges are withheld.

[View Full Report] [View Findings]
```

### High Findings Detected

```
⚠️ SSA Verification Incomplete

High severity findings detected.

Security Verified badge is not available.
Surface Verified may be available.

[View Full Report] [View Findings]
```

### Verification Requirements Not Met

```
⚠️ SSA Verification Incomplete

Verification requirements not met.

Required scan levels were not completed
or verdict was not "pass".

[View Full Report]
```

## Terminology Guidelines

### Correct Language

**For Badges:**
- ✅ "SSA · [Tier] Verified"
- ✅ "Earned verification badge"
- ✅ "Security verification passed"
- ✅ "Verified status"

**For Failures:**
- ✅ "SSA verification failed"
- ✅ "Verification incomplete"
- ✅ "Badge eligibility not met"
- ✅ "Verification requirements not satisfied"

**For Risk:**
- ✅ "Risk state: Critical"
- ✅ "Security findings detected"
- ✅ "Risk alert"
- ✅ "Security concerns"

### Incorrect Language

**MUST NOT USE:**
- ❌ "Critical Risk Badge"
- ❌ "Failure Badge"
- ❌ "Unsafe Badge"
- ❌ "Verified Risk"
- ❌ "Badge: Critical"

## Visual Design Guidelines

### Badge Display

- **Icon:** Shield-based (never use warning/danger icons)
- **Colors:** Green/blue for positive verification
- **Style:** Clean, professional, verification-focused
- **Size:** Prominent but not overwhelming

### Risk Display

- **Icon:** Warning/alert icons (⚠️, ⛔)
- **Colors:** Red/orange/yellow for risk levels
- **Style:** Alert/banner style (not badge style)
- **Position:** Separate from badge section

### Layout

```
┌─────────────────────────────────────┐
│  Header (Logo, Target, Timestamp)  │
├─────────────────────────────────────┤
│  [Badge Section OR Failure Message] │
├─────────────────────────────────────┤
│  [Risk State Alert]                 │
├─────────────────────────────────────┤
│  Verification Details               │
├─────────────────────────────────────┤
│  Badge Eligibility Explanation      │
└─────────────────────────────────────┘
```

## Wallet vs Coin/FA Differences

### Wallet Verification Pages

**Key Differences:**
- Only Wallet Verified badge available (not Surface/Security/Continuously Monitored)
- Levels 1–3 only (Levels 4–5 not applicable)
- Disclaimer about contract security
- Focus on wallet address verification

**Example Disclaimer:**
```
⚠️ Important: This badge verifies the wallet address only.
It does NOT guarantee the security of contracts published
by this wallet. Each contract must be verified separately.
```

### Coin/FA Verification Pages

**Key Differences:**
- Surface Verified, Security Verified, or Continuously Monitored badges available
- Levels 1–5 supported
- Focus on contract security verification
- No wallet disclaimer needed

## Cryptographic Verification

### Badge Verification

**Required Elements:**
- "Verify Badge" button/link
- Signature fingerprint display
- Public key reference
- Verification status indicator

**Verification Flow:**
1. User clicks "Verify Badge"
2. System verifies signature using public key
3. Display verification result (✅ Valid / ❌ Invalid)

### Public Key Display

**Required Information:**
- Public key fingerprint
- Algorithm (Ed25519)
- Key source (docs/keys/ssa_public_key.json)
- Last updated date

## Responsive Design

### Desktop

- Badge prominently displayed
- Full verification details visible
- Risk state clearly separated
- All information accessible

### Mobile

- Badge remains prominent
- Verification details collapsible
- Risk state clearly visible
- Touch-friendly buttons

## Accessibility

### Required Features

- Alt text for badge icons
- Screen reader friendly labels
- High contrast for text
- Keyboard navigation support
- ARIA labels for interactive elements

## Integration with Base44

### Data Consumption

Base44 UI should consume:

- `badge` field from scan result
- `verification_status` field
- `risk_state` field (separate from badge)
- `suppression_reason` when applicable

### Display Logic

```typescript
if (badge.tier !== "NONE") {
  // Display badge with shield icon
  displayBadge(badge);
} else {
  // Display failure message
  displayVerificationFailure(suppressionReason);
}

// Always display risk state separately
displayRiskState(riskState);
```

## Policy Compliance

### Required Checks

1. ✅ No negative badges displayed
2. ✅ Risk states shown separately from badges
3. ✅ Clear failure messages when no badge
4. ✅ Shield iconography only for badges
5. ✅ Alert iconography for risk states
6. ✅ Correct terminology throughout

### Validation

All public verification pages must:

- Follow badge display rules
- Use correct terminology
- Separate badges from risk states
- Provide clear failure messages
- Include cryptographic verification

## Examples

### Example 1: Security Verified Badge

```
┌─────────────────────────────────────┐
│  SSA Public Verification            │
│  Target: 0x123...::MODULE::COIN     │
│  Scanned: 2024-01-01 12:00:00 UTC  │
├─────────────────────────────────────┤
│  [🛡️] SSA · Security Verified      │
│  Expires: 2024-01-31               │
│  Signature: ABC123DEF456...        │
│  [Verify Badge]                     │
├─────────────────────────────────────┤
│  Risk State: Low                   │
│  Findings: 2 medium, 1 low         │
├─────────────────────────────────────┤
│  Verification Details:              │
│  • Levels 1–3: Passed              │
│  • Risk Score: 8/100               │
│  • Scanner: SSA v0.1.0             │
└─────────────────────────────────────┘
```

### Example 2: Verification Failed

```
┌─────────────────────────────────────┐
│  SSA Public Verification            │
│  Target: 0x456...::MODULE::COIN     │
│  Scanned: 2024-01-01 12:00:00 UTC  │
├─────────────────────────────────────┤
│  ⚠️ SSA Verification Failed         │
│                                     │
│  Critical security findings         │
│  detected.                          │
│                                     │
│  Verification badges are withheld.  │
│                                     │
│  [View Full Report]                 │
├─────────────────────────────────────┤
│  ⛔ Risk State: Critical            │
│  Findings: 2 critical, 3 high      │
│  [View Detailed Findings]           │
├─────────────────────────────────────┤
│  Verification Details:              │
│  • Level 1: Failed                 │
│  • Risk Score: 75/100              │
│  • Scanner: SSA v0.1.0             │
└─────────────────────────────────────┘
```

## Policy Reference

For complete policy details, see:
- `docs/badges.md` - Badge tier specifications
- `docs/verification-levels.md` - Verification level specifications
- `docs/ssa-badges-and-risk-policy.md` - Complete badge and risk policy

---

**Specification Version:** 1.0  
**Last Updated:** 2024-01-01  
**Authority:** SSA Scanner Core Team

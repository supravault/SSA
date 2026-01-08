import type { Finding, RuleContext } from "../../core/types.js";
import { normalizeRuleContext } from "../../core/ruleset.js";

/**
 * SVSSA-MOVE-021: Signature replay attacks
 * Detects functions that may be vulnerable to signature replay attacks
 * Requires bytecode/ABI for detection
 */
export function rule_021(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const normalizedCtx = normalizeRuleContext(ctx);
  const { artifact, capabilities } = normalizedCtx;

  // Only run if we have bytecode/ABI evidence
  if (capabilities.viewOnly) {
    return findings; // Skip in view-only mode
  }

  const signatureMarkers = [
    "signature",
    "sign",
    "verify",
    "ecdsa",
    "ed25519",
    "schnorr",
    "crypto",
  ];

  const replayVulnerableOperations = [
    "transfer",
    "mint",
    "withdraw",
    "claim",
    "execute",
    "permit",
  ];

  // Check for signature usage
  const hasSignatureUsage = artifact.strings.some((s) =>
    signatureMarkers.some((marker) => s.toLowerCase().includes(marker))
  );

  if (!hasSignatureUsage) {
    return findings; // No signature usage detected
  }

  // Check entry functions that use signatures
  for (const entryFn of artifact.entryFunctions) {
    const fnLower = entryFn.toLowerCase();
    
    const usesSignatures = signatureMarkers.some((marker) =>
      fnLower.includes(marker)
    );

    const isReplayVulnerable = replayVulnerableOperations.some((op) =>
      fnLower.includes(op)
    );

    if (usesSignatures && isReplayVulnerable) {
      // Check for replay protection
      const replayProtectionMarkers = [
        "nonce",
        "replay",
        "used",
        "consumed",
        "expired",
        "deadline",
        "chain_id",
        "domain_separator",
      ];

      const hasProtection = 
        replayProtectionMarkers.some((marker) => fnLower.includes(marker)) ||
        artifact.strings.some((s) =>
          replayProtectionMarkers.some((marker) => s.toLowerCase().includes(marker))
        );

      if (!hasProtection) {
        let severity: "high" | "medium";
        let confidence: number;
        let evidenceKind: "bytecode_pattern" | "abi_pattern" | "heuristic";

        if (capabilities.hasAbi) {
          severity = "high";
          confidence = 0.7;
          evidenceKind = "abi_pattern";
        } else if (capabilities.hasBytecodeOrSource) {
          severity = "high";
          confidence = 0.6;
          evidenceKind = "bytecode_pattern";
        } else {
          severity = "medium";
          confidence = 0.5;
          evidenceKind = "heuristic";
        }

        findings.push({
          id: "SVSSA-MOVE-021",
          title: "Potential Signature Replay Vulnerability",
          severity,
          confidence,
          description: `Entry function "${entryFn}" uses signatures for authorization but no replay protection detected. Signed messages may be reused maliciously.`,
          recommendation: "Implement replay protection mechanisms such as nonces, expiration timestamps, or chain-specific domain separators. Track used signatures to prevent reuse.",
          evidence: {
            kind: evidenceKind,
            matched: signatureMarkers.filter((m) => fnLower.includes(m)),
            locations: [{ fn: entryFn, note: "Signature-based operation without replay protection" }],
          },
          references: [],
        });
      }
    }
  }

  return findings;
}

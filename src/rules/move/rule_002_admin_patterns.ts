import type { Finding, RuleContext } from "../../core/types.js";

/**
 * SVSSA-MOVE-002: Privileged role hardcoding
 * Detects hardcoded addresses that may indicate privileged roles
 */
export function rule_002_admin_patterns(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const { artifact } = ctx;

  // Look for address patterns (0x followed by hex)
  const addressPattern = /0x[0-9a-fA-F]{40,}/g;
  const privilegedKeywords = ["admin", "owner", "treasury", "authority", "governance"];

  const matchedAddresses: string[] = [];
  const matchedKeywords: string[] = [];

  // Check strings for addresses and privileged keywords
  for (const str of artifact.strings) {
    const addresses = str.match(addressPattern);
    if (addresses) {
      matchedAddresses.push(...addresses);
    }

    const lowerStr = str.toLowerCase();
    for (const keyword of privilegedKeywords) {
      if (lowerStr.includes(keyword)) {
        matchedKeywords.push(keyword);
      }
    }
  }

  // If we found addresses AND privileged keywords, flag it
  if (matchedAddresses.length > 0 && matchedKeywords.length > 0) {
    const uniqueAddresses = [...new Set(matchedAddresses)];
    const uniqueKeywords = [...new Set(matchedKeywords)];

    findings.push({
      id: "SVSSA-MOVE-002",
      title: "Potential Hardcoded Privileged Addresses",
      severity: "medium",
      confidence: 0.7,
      description: `Found hardcoded addresses (${uniqueAddresses.length} unique) alongside privileged role keywords (${uniqueKeywords.join(", ")}). This may indicate hardcoded admin/owner addresses.`,
      recommendation: "Use capability-based access control or store privileged addresses in a configurable storage rather than hardcoding them.",
      evidence: {
        kind: "bytecode_pattern",
        matched: [...uniqueAddresses.slice(0, 5), ...uniqueKeywords], // Limit addresses shown
        raw_excerpt: `Found ${uniqueAddresses.length} address(es) and keywords: ${uniqueKeywords.join(", ")}`,
      },
      references: [],
    });
  }

  return findings;
}


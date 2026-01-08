// src/agent/evidence.ts

export type EvidenceSource = "rpc_v3" | "rpc_v1" | "rpc_v3_2" | "suprascan";

export interface ParityCheck {
  id: string;
  status: "match" | "mismatch" | "unknown";
  detail: string;
  evidence?: any;
}

export interface EvidenceBundle {
  sourcesUsed: EvidenceSource[];
  parity: ParityCheck[];
}

/**
 * Create an empty evidence bundle
 */
export function createEmptyEvidenceBundle(): EvidenceBundle {
  return {
    sourcesUsed: [],
    parity: [],
  };
}

/**
 * Add a parity check for supply comparison
 */
export function addSupplyParityCheck(
  bundle: EvidenceBundle,
  rpcSupply: string | null | undefined,
  suprascanSupply: string | null | undefined
): void {
  if (rpcSupply === null || rpcSupply === undefined || suprascanSupply === null || suprascanSupply === undefined) {
    bundle.parity.push({
      id: "SUPPLY_PARITY",
      status: "unknown",
      detail: "One or both supply sources unavailable",
      evidence: {
        rpcSupply: rpcSupply || null,
        suprascanSupply: suprascanSupply || null,
      },
    });
    return;
  }

  const rpcNum = parseFloat(rpcSupply);
  const scanNum = parseFloat(suprascanSupply);

  if (isNaN(rpcNum) || isNaN(scanNum)) {
    bundle.parity.push({
      id: "SUPPLY_PARITY",
      status: "unknown",
      detail: "Could not parse supply values for comparison",
      evidence: {
        rpcSupply,
        suprascanSupply,
      },
    });
    return;
  }

  const match = Math.abs(rpcNum - scanNum) < 0.0001; // Allow small floating point differences

  bundle.parity.push({
    id: "SUPPLY_PARITY",
    status: match ? "match" : "mismatch",
    detail: match
      ? `Supply matches: ${rpcSupply}`
      : `Supply mismatch: RPC=${rpcSupply}, SupraScan=${suprascanSupply}`,
    evidence: {
      rpcSupply,
      suprascanSupply,
      delta: Math.abs(rpcNum - scanNum),
    },
  });
}

/**
 * Add a parity check for module count comparison
 */
export function addModuleCountParityCheck(
  bundle: EvidenceBundle,
  rpcV3Count: number,
  rpcV1Count: number | null
): void {
  if (rpcV1Count === null) {
    bundle.parity.push({
      id: "MODULE_COUNT_PARITY",
      status: "unknown",
      detail: "RPC v1 module count unavailable",
      evidence: {
        rpcV3Count,
        rpcV1Count: null,
      },
    });
    return;
  }

  const match = rpcV3Count === rpcV1Count;

  bundle.parity.push({
    id: "MODULE_COUNT_PARITY",
    status: match ? "match" : "mismatch",
    detail: match
      ? `Module count matches: ${rpcV3Count}`
      : `Module count mismatch: RPC v3=${rpcV3Count}, RPC v1=${rpcV1Count}`,
    evidence: {
      rpcV3Count,
      rpcV1Count,
    },
  });
}

/**
 * Add a parity check for FA owner comparison
 */
export function addOwnerParityCheck(
  bundle: EvidenceBundle,
  rpcOwner: string | null | undefined,
  suprascanOwner: string | null | undefined
): void {
  if (rpcOwner === null || rpcOwner === undefined || suprascanOwner === null || suprascanOwner === undefined) {
    bundle.parity.push({
      id: "OWNER_PARITY",
      status: "unknown",
      detail: "One or both owner sources unavailable",
      evidence: {
        rpcOwner: rpcOwner || null,
        suprascanOwner: suprascanOwner || null,
      },
    });
    return;
  }

  const normalizedRpc = rpcOwner.toLowerCase().trim();
  const normalizedScan = suprascanOwner.toLowerCase().trim();

  const match = normalizedRpc === normalizedScan;

  bundle.parity.push({
    id: "OWNER_PARITY",
    status: match ? "match" : "mismatch",
    detail: match
      ? `Owner matches: ${rpcOwner}`
      : `Owner mismatch: RPC=${rpcOwner}, SupraScan=${suprascanOwner}`,
    evidence: {
      rpcOwner,
      suprascanOwner,
    },
  });
}


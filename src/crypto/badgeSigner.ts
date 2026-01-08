// src/crypto/badgeSigner.ts
// Cryptographic signing for SSA badges using Ed25519

import { createHash } from "crypto";
import type { BadgeResult } from "../policy/badgePolicy.js";

/**
 * Canonicalize JSON by sorting keys and using consistent formatting
 */
function canonicalizeJson(obj: any): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

/**
 * Generate a short fingerprint from a signature (first 16 hex chars)
 */
export function signatureFingerprint(signature: string): string {
  const hash = createHash("sha256").update(signature).digest("hex");
  return hash.substring(0, 16).toUpperCase();
}

/**
 * Signed badge payload structure
 */
export interface BadgePayload {
  tier: string;
  label: string;
  scan_id: string;
  target: {
    kind: string;
    value: string;
  };
  timestamp_iso: string;
  expires_at_iso: string | null;
  continuously_monitored: boolean;
}

/**
 * Signed badge structure
 */
export interface SignedBadge {
  payload: BadgePayload;
  signature: string;
  fingerprint: string;
  public_key: string;
  algorithm: "ed25519";
}

/**
 * Sign a badge using Ed25519
 * @param payload Badge payload to sign
 * @param privateKey Ed25519 private key (base64 or hex string)
 * @returns Signed badge with signature
 */
export async function signBadge(
  payload: BadgePayload,
  privateKey: string
): Promise<SignedBadge> {
  try {
    // Import tweetnacl for Ed25519 signing
    const nacl = await import("tweetnacl");
    
    // Parse private key
    let keyBytes: Uint8Array;
    try {
      // Try base64 first
      keyBytes = Buffer.from(privateKey, "base64");
    } catch {
      // Fall back to hex
      keyBytes = Buffer.from(privateKey, "hex");
    }

    if (keyBytes.length !== 64) {
      throw new Error("Ed25519 private key must be 64 bytes (512 bits)");
    }

    // Extract public key from private key
    const keyPair = nacl.sign.keyPair.fromSecretKey(keyBytes);
    const publicKey = Buffer.from(keyPair.publicKey).toString("base64");

    // Canonicalize payload JSON
    const canonicalPayload = canonicalizeJson(payload);
    const payloadBytes = Buffer.from(canonicalPayload, "utf-8");

    // Sign the payload
    const signature = nacl.sign.detached(payloadBytes, keyPair.secretKey);
    const signatureBase64 = Buffer.from(signature).toString("base64");

    // Generate fingerprint
    const fingerprint = signatureFingerprint(signatureBase64);

    return {
      payload,
      signature: signatureBase64,
      fingerprint,
      public_key: publicKey,
      algorithm: "ed25519",
    };
  } catch (error) {
    throw new Error(
      `Failed to sign badge: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Verify a signed badge
 * @param signedBadge Signed badge to verify
 * @param publicKey Ed25519 public key (base64 or hex string, optional - uses signedBadge.public_key if not provided)
 * @returns true if signature is valid, false otherwise
 */
export async function verifyBadge(
  signedBadge: SignedBadge,
  publicKey?: string
): Promise<boolean> {
  try {
    const nacl = await import("tweetnacl");

    // Use provided public key or the one in the signed badge
    const keyToUse = publicKey || signedBadge.public_key;
    if (!keyToUse) {
      return false;
    }

    // Parse public key
    let keyBytes: Uint8Array;
    try {
      // Try base64 first
      keyBytes = Buffer.from(keyToUse, "base64");
    } catch {
      // Fall back to hex
      keyBytes = Buffer.from(keyToUse, "hex");
    }

    if (keyBytes.length !== 32) {
      return false;
    }

    // Parse signature
    const signature = Buffer.from(signedBadge.signature, "base64");

    // Canonicalize payload JSON
    const canonicalPayload = canonicalizeJson(signedBadge.payload);
    const payloadBytes = Buffer.from(canonicalPayload, "utf-8");

    // Verify signature
    return nacl.sign.detached.verify(payloadBytes, signature, keyBytes);
  } catch (error) {
    console.error(`Badge verification error: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
}

/**
 * Generate Ed25519 key pair
 * @returns Object with privateKey and publicKey (both base64 encoded)
 */
export async function generateKeyPair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const nacl = await import("tweetnacl");
  const keyPair = nacl.sign.keyPair();
  
  return {
    privateKey: Buffer.from(keyPair.secretKey).toString("base64"),
    publicKey: Buffer.from(keyPair.publicKey).toString("base64"),
  };
}

/**
 * Export public key to JSON file
 */
export async function exportPublicKey(publicKey: string, outputPath: string): Promise<void> {
  const { mkdirSync, writeFileSync } = await import("fs");
  const { dirname } = await import("path");

  // Ensure directory exists
  mkdirSync(dirname(outputPath), { recursive: true });

  const keyInfo = {
    algorithm: "ed25519",
    public_key: publicKey,
    format: "base64",
    created_at: new Date().toISOString(),
    purpose: "SSA Badge Verification",
  };

  writeFileSync(outputPath, JSON.stringify(keyInfo, null, 2), "utf-8");
}

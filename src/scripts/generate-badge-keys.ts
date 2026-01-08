#!/usr/bin/env node
// src/scripts/generate-badge-keys.ts
// Generate Ed25519 key pair for badge signing

import { generateKeyPair, exportPublicKey } from "../crypto/badgeSigner.js";
import { writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function main() {
  console.log("Generating Ed25519 key pair for SSA badge signing...\n");

  const { privateKey, publicKey } = await generateKeyPair();

  // Export public key to docs/keys/ssa_public_key.json
  const publicKeyPath = join(__dirname, "../../docs/keys/ssa_public_key.json");
  await exportPublicKey(publicKey, publicKeyPath);
  console.log(`✓ Public key exported to: ${publicKeyPath}`);

  // Output private key (user should save this to .env)
  console.log("\n=== PRIVATE KEY (save to .env as SSA_BADGE_SIGNING_KEY) ===");
  console.log(privateKey);
  console.log("\n⚠️  WARNING: Keep this private key secure! Do not commit it to version control.");
  console.log("\nAdd to your .env file:");
  console.log(`SSA_BADGE_SIGNING_KEY=${privateKey}`);
}

main().catch((error) => {
  console.error("Error generating keys:", error);
  process.exit(1);
});

#!/usr/bin/env node

/**
 * Doctor script - verifies setup and environment
 */

import { execSync } from "child_process";
import { existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, "..");

console.log("🔍 SSA Scanner - Doctor Check");
console.log("=".repeat(50));
console.log("");

// 1. Node version
console.log("📦 Node Version:");
console.log(`   ${process.version}`);
console.log("");

// 2. TypeScript availability
console.log("🔧 TypeScript:");
try {
  const tscVersion = execSync("npx tsc --version", {
    encoding: "utf-8",
    cwd: rootDir,
    stdio: "pipe",
  }).trim();
  console.log(`   ✅ Available: ${tscVersion}`);
} catch (error) {
  console.log(`   ❌ Not available: ${error instanceof Error ? error.message : String(error)}`);
  console.log("   💡 Run: npm install");
}
console.log("");

// 3. Check if dist/scripts/test-scan.js exists
console.log("📁 Build Output:");
const distScriptPath = join(rootDir, "dist", "scripts", "test-scan.js");
if (existsSync(distScriptPath)) {
  console.log(`   ✅ Found: dist/scripts/test-scan.js`);
} else {
  console.log(`   ⚠️  Missing: dist/scripts/test-scan.js`);
  console.log("   💡 Run: npm run build");
}
console.log("");

// 4. RPC_URL environment variable
console.log("🌐 Environment:");
const rpcUrl = process.env.RPC_URL;
if (rpcUrl) {
  console.log(`   RPC_URL: ${rpcUrl}`);
} else {
  console.log(`   RPC_URL: (not set)`);
  console.log("   💡 Set with: $env:RPC_URL='https://rpc-mainnet.supra.com'");
}

const targetAddr = process.env.TARGET_ADDR;
const targetMod = process.env.TARGET_MOD;
if (targetAddr) {
  console.log(`   TARGET_ADDR: ${targetAddr}`);
} else {
  console.log(`   TARGET_ADDR: (not set)`);
}
if (targetMod) {
  console.log(`   TARGET_MOD: ${targetMod}`);
} else {
  console.log(`   TARGET_MOD: (not set)`);
}
console.log("");

console.log("=".repeat(50));


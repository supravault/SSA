#!/usr/bin/env node

/**
 * Flavor Guard Script
 * Prevents Sui/Aptos-specific references from being introduced
 * Exits with non-zero code if forbidden patterns are found
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Sui-specific patterns (blockchain-specific only, not generic/legal uses)
const SUI_PATTERNS = [
  /docs\.sui\.io/gi,
  /docs\.sui\b/gi, // docs.sui (but not docs.sui.io which is already matched)
  /sui\.io\b/gi, // sui.io domain
  /sui::/gi, // sui:: module prefix
  /\bTxContext\b/gi, // Sui-specific type
  /\bUID\b(?!\w)/gi, // UID but not UUID (negative lookahead)
  /0x2::/gi, // Sui framework address
  /Sui\s+blockchain/gi, // Explicit "Sui blockchain"
  /Sui\s+Move/gi, // "Sui Move"
];

// Aptos-specific patterns (blockchain-specific only)
const APTOS_PATTERNS = [
  /aptos\.dev/gi,
  /aptos::/gi, // aptos:: module prefix
  /aptos_framework/gi,
  /Aptos\s+blockchain/gi, // Explicit "Aptos blockchain"
  /Aptos\s+Move/gi, // "Aptos Move"
];

// Forbidden strings (exact matches, blockchain-specific)
const FORBIDDEN_STRINGS = [
  "docs.sui.io",
  "docs.sui",
  "sui.io",
  "sui::",
  "aptos.dev",
  "aptos::",
  "0x2::",
  "TxContext",
  "aptos_framework",
];

// Allowed contexts (exceptions for legal/generic uses)
const ALLOWED_CONTEXTS = [
  /Move\b/g, // Allow "Move" language references
  /Suite\b/g, // Allow test suite references
  /suite\b/g, // Allow lowercase suite
  /move\s+security/gi, // Allow generic "move security" in comments
  /randomUUID|UUID|uuid/gi, // Allow UUID (Node.js crypto, not Sui UID)
  /Sui\s+Generis/gi, // Allow "Sui Generis" (legal term)
  /sui\s+generis/gi, // Allow lowercase "sui generis"
];

function shouldIgnoreFile(filePath) {
  // Ignore node_modules, dist, coverage, and license files
  const ignorePatterns = [
    /node_modules/,
    /\/dist\//,
    /\/coverage\//,
    /ThirdPartyNoticeText\.txt$/,
    /\.map$/,
  ];
  return ignorePatterns.some((pattern) => pattern.test(filePath));
}

function findFiles(dir, extensions = [".ts", ".js", ".md"], excludeDirs = []) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip ignored directories and files
    if (shouldIgnoreFile(fullPath)) {
      continue;
    }

    if (
      entry.isDirectory() &&
      !entry.name.startsWith(".") &&
      entry.name !== "node_modules" &&
      entry.name !== "dist" &&
      entry.name !== "coverage" &&
      !excludeDirs.includes(entry.name)
    ) {
      files.push(...findFiles(fullPath, extensions, excludeDirs));
    } else if (
      entry.isFile() &&
      extensions.some((ext) => entry.name.endsWith(ext)) &&
      fullPath !== __filename &&
      !shouldIgnoreFile(fullPath)
    ) {
      files.push(fullPath);
    }
  }

  return files;
}

function isAllowedContext(content, matchIndex) {
  // Check if match is in an allowed context
  for (const allowed of ALLOWED_CONTEXTS) {
    const beforeMatch = content.substring(Math.max(0, matchIndex - 50), matchIndex);
    const afterMatch = content.substring(matchIndex, matchIndex + 50);
    if (allowed.test(beforeMatch + afterMatch)) {
      return true;
    }
  }
  return false;
}

function checkFile(filePath) {
  const content = fs.readFileSync(filePath, "utf-8");
  const issues = [];

  // Check for Sui patterns
  for (const pattern of SUI_PATTERNS) {
    const globalPattern = new RegExp(pattern.source, pattern.flags + (pattern.global ? "" : "g"));
    const matches = [...content.matchAll(globalPattern)];
    for (const match of matches) {
      if (match.index !== undefined && !isAllowedContext(content, match.index)) {
        const lines = content.substring(0, match.index).split("\n");
        const lineNum = lines.length;
        const lineContent = content.split("\n")[lineNum - 1]?.trim() || "";
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: `Sui pattern: ${pattern.toString()}`,
          match: match[0],
          context: lineContent.substring(0, 100),
        });
      }
    }
  }

  // Check for Aptos patterns
  for (const pattern of APTOS_PATTERNS) {
    const globalPattern = new RegExp(pattern.source, pattern.flags + (pattern.global ? "" : "g"));
    const matches = [...content.matchAll(globalPattern)];
    for (const match of matches) {
      if (match.index !== undefined && !isAllowedContext(content, match.index)) {
        const lines = content.substring(0, match.index).split("\n");
        const lineNum = lines.length;
        const lineContent = content.split("\n")[lineNum - 1]?.trim() || "";
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: `Aptos pattern: ${pattern.toString()}`,
          match: match[0],
          context: lineContent.substring(0, 100),
        });
      }
    }
  }

  // Check for forbidden strings
  for (const forbidden of FORBIDDEN_STRINGS) {
    let index = content.indexOf(forbidden);
    while (index !== -1) {
      if (!isAllowedContext(content, index)) {
        const lines = content.substring(0, index).split("\n");
        const lineNum = lines.length;
        const lineContent = content.split("\n")[lineNum - 1]?.trim() || "";
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: `forbidden string: ${forbidden}`,
          match: forbidden,
          context: lineContent.substring(0, 100),
        });
      }
      index = content.indexOf(forbidden, index + 1);
    }
  }

  // Special check for "UID" (but allow UUID)
  const uidPattern = /\bUID\b(?!\w)/gi;
  const uidMatches = [...content.matchAll(uidPattern)];
  for (const match of uidMatches) {
    if (match.index !== undefined && !isAllowedContext(content, match.index)) {
      // Check if it's part of UUID
      const beforeMatch = content.substring(Math.max(0, match.index - 5), match.index);
      const afterMatch = content.substring(match.index, match.index + 5);
      if (!beforeMatch.toLowerCase().includes("u") && !afterMatch.toLowerCase().includes("u")) {
        const lines = content.substring(0, match.index).split("\n");
        const lineNum = lines.length;
        const lineContent = content.split("\n")[lineNum - 1]?.trim() || "";
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: `forbidden string: UID (Sui-specific, use UUID for Node.js crypto)`,
          match: match[0],
          context: lineContent.substring(0, 100),
        });
      }
    }
  }

  return issues;
}

function main() {
  const rootDir = process.cwd();
  const srcDir = path.join(rootDir, "src");
  const scriptsDir = path.join(rootDir, "scripts");
  const readmePath = path.join(rootDir, "README.md");

  const files = [];
  if (fs.existsSync(srcDir)) {
    files.push(...findFiles(srcDir, [".ts", ".js"]));
  }
  if (fs.existsSync(scriptsDir)) {
    // Exclude guard scripts and contamination check from checking
    const allFiles = findFiles(scriptsDir, [".ts", ".js"], []);
    files.push(...allFiles.filter((f) => 
      !f.includes("guard-rpc.js") && 
      !f.includes("guard-chain-words.js") && 
      !f.includes("guard-flavor.js") &&
      !f.includes("check-contamination.js")
    ));
  }
  if (fs.existsSync(readmePath)) {
    files.push(readmePath);
  }

  const allIssues = [];
  for (const file of files) {
    const issues = checkFile(file);
    if (issues.length > 0) {
      allIssues.push(...issues);
    }
  }

  if (allIssues.length > 0) {
    console.error("❌ Flavor Guard: Found Sui/Aptos-specific references!\n");
    for (const issue of allIssues) {
      console.error(`  ${issue.file}:${issue.line}`);
      console.error(`    Pattern: ${issue.pattern}`);
      console.error(`    Match: ${issue.match}`);
      console.error(`    Context: ${issue.context}...\n`);
    }
    console.error(
      "Error: Chain-specific references (Sui/Aptos) are not allowed.\n" +
        "Use chain-agnostic wording or Supra-specific documentation.\n" +
        "Allowed: 'Move' (language), 'Suite' (test framework), 'Sui Generis' (legal term)\n"
    );
    process.exit(1);
  }

  console.log("✅ Flavor Guard: No Sui/Aptos-specific references found");
  process.exit(0);
}

main();


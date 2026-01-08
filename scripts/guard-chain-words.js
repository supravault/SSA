#!/usr/bin/env node

/**
 * Chain Words Guard Script
 * Prevents Sui/Aptos-specific references from being introduced
 * Exits with non-zero code if forbidden patterns are found
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Blockchain-specific patterns only (not generic/legal uses)
const FORBIDDEN_PATTERNS = [
  /docs\.sui\.io/gi,
  /docs\.sui\b/gi, // docs.sui (but not docs.sui.io)
  /sui\.io\b/gi, // sui.io domain
  /sui::/gi, // sui:: module prefix
  /aptos\.dev/gi,
  /aptos::/gi, // aptos:: module prefix
  /0x2::/gi, // Sui framework address
  /Sui\s+blockchain/gi, // Explicit "Sui blockchain"
  /Sui\s+Move/gi, // "Sui Move"
  /Aptos\s+blockchain/gi, // Explicit "Aptos blockchain"
  /Aptos\s+Move/gi, // "Aptos Move"
];

const FORBIDDEN_STRINGS = [
  "docs.sui.io",
  "docs.sui",
  "sui.io",
  "sui::",
  "aptos.dev",
  "aptos::",
  "0x2::",
];

// Allow "Move", "Suite", and legal terms
const ALLOWED_CONTEXTS = [
  /Move\b/g, // Allow "Move" language references
  /Suite\b/g, // Allow test suite references
  /suite\b/g, // Allow lowercase suite
  /Sui\s+Generis/gi, // Allow "Sui Generis" (legal term)
  /sui\s+generis/gi, // Allow lowercase "sui generis"
];

function shouldIgnoreFile(filePath) {
  // Ignore node_modules, dist, coverage, guard scripts, and license files
  const ignorePatterns = [
    /node_modules/,
    /\/dist\//,
    /\/coverage\//,
    /guard-flavor\.js$/,
    /guard-rpc\.js$/,
    /guard-chain-words\.js$/,
    /ThirdPartyNoticeText\.txt$/,
    /\.map$/,
  ];
  return ignorePatterns.some((pattern) => pattern.test(filePath));
}

function findFiles(dir, extensions = [".ts", ".js"], excludeDirs = []) {
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
  // Check if match is in an allowed context (like "Move" or "Suite")
  for (const allowed of ALLOWED_CONTEXTS) {
    const beforeMatch = content.substring(Math.max(0, matchIndex - 20), matchIndex);
    const afterMatch = content.substring(matchIndex, matchIndex + 20);
    if (allowed.test(beforeMatch + afterMatch)) {
      return true;
    }
  }
  return false;
}

function checkFile(filePath) {
  const content = fs.readFileSync(filePath, "utf-8");
  const issues = [];

  // Check for forbidden patterns
  for (const pattern of FORBIDDEN_PATTERNS) {
    // Ensure pattern is global for matchAll
    const globalPattern = new RegExp(pattern.source, pattern.flags + (pattern.global ? "" : "g"));
    const matches = [...content.matchAll(globalPattern)];
    for (const match of matches) {
      if (match.index !== undefined && !isAllowedContext(content, match.index)) {
        const lines = content.substring(0, match.index).split("\n");
        const lineNum = lines.length;
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: pattern.toString(),
          match: match[0],
          context: lines[lines.length - 1]?.trim() || "",
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
          context: lineContent,
        });
      }
      index = content.indexOf(forbidden, index + 1);
    }
  }

  return issues;
}

function main() {
  const rootDir = process.cwd();
  const srcDir = path.join(rootDir, "src");
  const scriptsDir = path.join(rootDir, "scripts");

  const files = [];
  if (fs.existsSync(srcDir)) {
    files.push(...findFiles(srcDir, [".ts", ".js"]));
  }
  if (fs.existsSync(scriptsDir)) {
    // Exclude guard scripts and contamination check
    const allFiles = findFiles(scriptsDir, [".ts", ".js"], []);
    files.push(...allFiles.filter((f) => 
      !f.includes("guard-rpc.js") && 
      !f.includes("guard-chain-words.js") && 
      !f.includes("guard-flavor.js") &&
      !f.includes("check-contamination.js")
    ));
  }

  const allIssues = [];
  for (const file of files) {
    const issues = checkFile(file);
    if (issues.length > 0) {
      allIssues.push(...issues);
    }
  }

  if (allIssues.length > 0) {
    console.error("❌ Chain Words Guard: Found forbidden chain-specific references!\n");
    for (const issue of allIssues) {
      console.error(`  ${issue.file}:${issue.line}`);
      console.error(`    Pattern: ${issue.pattern}`);
      console.error(`    Match: ${issue.match}`);
      console.error(`    Context: ${issue.context.substring(0, 100)}...\n`);
    }
    console.error(
      "Error: Chain-specific references (Sui/Aptos) are not allowed.\n" +
        "Use chain-agnostic wording or Supra-specific documentation.\n" +
        "Allowed: 'Move' (language), 'Suite' (test framework), 'Sui Generis' (legal term)\n"
    );
    process.exit(1);
  }

  console.log("✅ Chain Words Guard: No forbidden chain-specific references found");
  process.exit(0);
}

main();


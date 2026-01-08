#!/usr/bin/env node

/**
 * RPC Guard Script
 * Prevents placeholder JSON-RPC methods from being introduced
 * Exits with non-zero code if forbidden patterns are found
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Block placeholder RPC methods and Sui/Aptos-specific RPC patterns
const FORBIDDEN_PATTERNS = [
  /"supra_getModule"/i,
  /"sui_getModule"/i,
  /"sui_/i, // Sui RPC method prefix
  /"suix_/i, // Sui extended RPC prefix
  /"aptos_/i, // Aptos RPC method prefix
  /"aptos::/i, // Aptos module prefix in RPC
  /"sui_get/i, // Sui get methods
  /jsonrpc.*method.*["']sui/i, // JSON-RPC with Sui method
  /jsonrpc.*method.*["']aptos/i, // JSON-RPC with Aptos method
];

const FORBIDDEN_STRINGS = [
  "supra_getModule",
  "sui_getModule",
  "sui_",
  "suix_",
  "aptos_",
  "aptos::",
  "sui_get",
];

function shouldIgnoreFile(filePath) {
  // Ignore node_modules, dist, coverage, guard scripts, and license files
  const ignorePatterns = [
    /node_modules/,
    /\/dist\//,
    /\/coverage\//,
    /guard-rpc\.js$/,
    /guard-chain-words\.js$/,
    /guard-flavor\.js$/,
    /check-contamination\.js$/,
    /ThirdPartyNoticeText\.txt$/,
    /\.map$/,
  ];
  return ignorePatterns.some((pattern) => pattern.test(filePath));
}

function findFiles(dir, extensions = [".ts", ".js"], excludeSelf = true) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip ignored files and directories
    if (shouldIgnoreFile(fullPath)) {
      continue;
    }

    // Skip node_modules, dist, coverage, scripts (guard script itself), etc.
    if (
      entry.isDirectory() &&
      !entry.name.startsWith(".") &&
      entry.name !== "node_modules" &&
      entry.name !== "dist" &&
      entry.name !== "coverage" &&
      entry.name !== "scripts"
    ) {
      files.push(...findFiles(fullPath, extensions, false));
    } else if (
      entry.isFile() &&
      extensions.some((ext) => entry.name.endsWith(ext)) &&
      (!excludeSelf || fullPath !== __filename) &&
      !shouldIgnoreFile(fullPath)
    ) {
      files.push(fullPath);
    }
  }

  return files;
}

function checkFile(filePath) {
  const content = fs.readFileSync(filePath, "utf-8");
  const issues = [];

  // Check for forbidden patterns
  for (const pattern of FORBIDDEN_PATTERNS) {
    const matches = content.match(pattern);
    if (matches) {
      const lines = content.split("\n");
      matches.forEach((match) => {
        const lineNum = content.substring(0, content.indexOf(match)).split("\n").length;
        issues.push({
          file: filePath,
          line: lineNum,
          pattern: pattern.toString(),
          match: match,
        });
      });
    }
  }

  // Check for forbidden strings
  for (const forbidden of FORBIDDEN_STRINGS) {
    if (content.includes(forbidden)) {
      const lines = content.split("\n");
      lines.forEach((line, index) => {
        if (line.includes(forbidden)) {
          issues.push({
            file: filePath,
            line: index + 1,
            pattern: `forbidden string: ${forbidden}`,
            match: line.trim(),
          });
        }
      });
    }
  }

  return issues;
}

function main() {
  const rootDir = process.cwd();
  const srcDir = path.join(rootDir, "src");

  const files = [];
  if (fs.existsSync(srcDir)) {
    files.push(...findFiles(srcDir));
  }

  const allIssues = [];
  for (const file of files) {
    const issues = checkFile(file);
    if (issues.length > 0) {
      allIssues.push(...issues);
    }
  }

  if (allIssues.length > 0) {
    console.error("❌ RPC Guard: Found forbidden patterns!\n");
    for (const issue of allIssues) {
      console.error(`  ${issue.file}:${issue.line}`);
      console.error(`    Pattern: ${issue.pattern}`);
      console.error(`    Match: ${issue.match.substring(0, 80)}...\n`);
    }
    console.error(
      "Error: Placeholder JSON-RPC methods or Sui/Aptos RPC methods are not allowed.\n" +
        "Use Supra view RPC: POST {RPC_URL}/rpc/v1/view with { function, type_arguments, arguments }\n"
    );
    process.exit(1);
  }

  console.log("✅ RPC Guard: No forbidden patterns found");
  process.exit(0);
}

main();


#!/usr/bin/env node

/**
 * Contamination Check Script
 * Checks for chain-specific references (Sui/Aptos) in source code
 * Excludes guard scripts and node_modules (guards intentionally contain matchers)
 * This is the authoritative check for contamination
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Chain-specific patterns to detect
const CONTAMINATION_PATTERNS = [
  /docs\.sui/gi,
  /sui\.io/gi,
  /aptos\.dev/gi,
  /sui::/gi,
  /aptos::/gi,
  /0x2::/gi, // Sui framework address
  /Sui\s+Move/gi,
  /Aptos\s+Move/gi,
];

// Allowed contexts (exceptions)
const ALLOWED_CONTEXTS = [
  /Sui\s+Generis/gi, // Legal term
  /sui\s+generis/gi, // Lowercase legal term
];

function shouldIgnoreFile(filePath) {
  // Ignore node_modules, dist, guard scripts, and license files
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
    /CHANGES_SUMMARY\.md$/,
  ];
  return ignorePatterns.some((pattern) => pattern.test(filePath));
}

function findFiles(dir, extensions = [".ts", ".js", ".md"]) {
  const files = [];
  
  if (!fs.existsSync(dir)) {
    return files;
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip ignored files and directories
    if (shouldIgnoreFile(fullPath)) {
      continue;
    }

    if (entry.isDirectory() && !entry.name.startsWith(".")) {
      files.push(...findFiles(fullPath, extensions));
    } else if (
      entry.isFile() &&
      extensions.some((ext) => entry.name.endsWith(ext)) &&
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

  // Check for contamination patterns
  for (const pattern of CONTAMINATION_PATTERNS) {
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
          pattern: pattern.toString(),
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
  const docsDir = path.join(rootDir, "docs");
  const readmePath = path.join(rootDir, "README.md");

  const files = [];
  
  // Scan src/ directory
  if (fs.existsSync(srcDir)) {
    files.push(...findFiles(srcDir, [".ts", ".js"]));
  }
  
  // Scan scripts/ directory (excluding guard scripts)
  if (fs.existsSync(scriptsDir)) {
    files.push(...findFiles(scriptsDir, [".ts", ".js"]));
  }
  
  // Scan docs/ directory (excluding CHANGES_SUMMARY.md)
  if (fs.existsSync(docsDir)) {
    files.push(...findFiles(docsDir, [".md"]));
  }
  
  // Scan README.md
  if (fs.existsSync(readmePath) && !shouldIgnoreFile(readmePath)) {
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
    console.error("❌ Contamination Check: Found chain-specific references!\n");
    for (const issue of allIssues) {
      console.error(`  ${issue.file}:${issue.line}`);
      console.error(`    Pattern: ${issue.pattern}`);
      console.error(`    Match: ${issue.match}`);
      console.error(`    Context: ${issue.context}...\n`);
    }
    console.error(
      "Error: Chain-specific references (Sui/Aptos) found in source code.\n" +
        "Use chain-agnostic wording or Supra-specific documentation.\n" +
        "Note: Guard scripts intentionally contain matchers and are excluded from this check.\n"
    );
    process.exit(1);
  }

  console.log("✅ Contamination Check: No chain-specific references found");
  process.exit(0);
}

main();


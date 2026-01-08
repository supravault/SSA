#!/usr/bin/env node
// src/scripts/verify-report.ts
// Verify report integrity: recompute and validate inputs.json checksum, PDF SHA-256, and derived report_id

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { createHash } from "crypto";
import {
  computeInputChecksum,
  deriveReportId,
  canonicalizeJson,
  type FullIntegratedInputs,
} from "../report/fullIntegratedGenerator.js";
import { Command } from "commander";

const program = new Command();

program
  .name("verify-report")
  .description("Verify report integrity: checksums and report ID")
  .version("0.1.0");

program
  .requiredOption("--report-dir <path>", "Path to report directory (contains final_report.pdf, inputs.json, checksum.txt)")
  .action(async (options) => {
    const reportDir = options.reportDir;
    if (!existsSync(reportDir)) {
      console.error(`Error: Report directory not found: ${reportDir}`);
      process.exit(1);
    }

    const inputsPath = join(reportDir, "inputs.json");
    const pdfPath = join(reportDir, "final_report.pdf");
    const checksumPath = join(reportDir, "checksum.txt");

    // Verify all required files exist
    if (!existsSync(inputsPath)) {
      console.error(`Error: inputs.json not found: ${inputsPath}`);
      process.exit(1);
    }
    if (!existsSync(pdfPath)) {
      console.error(`Error: final_report.pdf not found: ${pdfPath}`);
      process.exit(1);
    }
    if (!existsSync(checksumPath)) {
      console.error(`Error: checksum.txt not found: ${checksumPath}`);
      process.exit(1);
    }

    console.log("Verifying report integrity...\n");

    // Read and parse inputs.json
    let inputs: FullIntegratedInputs;
    try {
      const inputsContent = readFileSync(inputsPath, "utf-8");
      inputs = JSON.parse(inputsContent);
    } catch (error) {
      console.error(`Error: Failed to parse inputs.json: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }

    // Recompute input checksum from inputs.json
    const computedInputChecksum = computeInputChecksum(inputs);
    const computedReportId = deriveReportId(computedInputChecksum);

    // Read PDF and compute SHA-256
    const pdfBytes = readFileSync(pdfPath);
    const computedPdfChecksum = createHash("sha256").update(pdfBytes).digest("hex");

    // Read checksum.txt and parse
    const checksumContent = readFileSync(checksumPath, "utf-8");
    const checksumLines = checksumContent.trim().split("\n");
    const checksums: Record<string, string> = {};
    for (const line of checksumLines) {
      const [key, value] = line.split("=");
      if (key && value) {
        checksums[key.trim()] = value.trim();
      }
    }

    const storedInputChecksum = checksums["input_checksum"];
    const storedPdfChecksum = checksums["pdf_checksum"];
    const storedReportId = checksums["report_id"];

    // Verify all checksums
    let allValid = true;

    console.log("=== Verification Results ===\n");

    // Verify input checksum
    if (storedInputChecksum) {
      const inputValid = computedInputChecksum.toLowerCase() === storedInputChecksum.toLowerCase();
      console.log(`Input Checksum: ${inputValid ? "✅ VALID" : "❌ MISMATCH"}`);
      if (!inputValid) {
        console.log(`  Expected: ${storedInputChecksum}`);
        console.log(`  Computed: ${computedInputChecksum}`);
        allValid = false;
      } else {
        console.log(`  Value: ${computedInputChecksum}`);
      }
    } else {
      console.log(`Input Checksum: ❌ NOT FOUND in checksum.txt`);
      allValid = false;
    }

    // Verify PDF checksum
    if (storedPdfChecksum) {
      const pdfValid = computedPdfChecksum.toLowerCase() === storedPdfChecksum.toLowerCase();
      console.log(`PDF Checksum: ${pdfValid ? "✅ VALID" : "❌ MISMATCH"}`);
      if (!pdfValid) {
        console.log(`  Expected: ${storedPdfChecksum}`);
        console.log(`  Computed: ${computedPdfChecksum}`);
        allValid = false;
      } else {
        console.log(`  Value: ${computedPdfChecksum}`);
      }
    } else {
      console.log(`PDF Checksum: ❌ NOT FOUND in checksum.txt`);
      allValid = false;
    }

    // Verify report ID
    if (storedReportId) {
      const reportIdValid = computedReportId.toLowerCase() === storedReportId.toLowerCase();
      console.log(`Report ID: ${reportIdValid ? "✅ VALID" : "❌ MISMATCH"}`);
      if (!reportIdValid) {
        console.log(`  Expected: ${storedReportId}`);
        console.log(`  Computed: ${computedReportId}`);
        allValid = false;
      } else {
        console.log(`  Value: ${computedReportId}`);
      }
    } else {
      console.log(`Report ID: ❌ NOT FOUND in checksum.txt`);
      allValid = false;
    }

    // Verify report ID derivation (should match first 12 chars of input checksum)
    const reportIdFromChecksum = computedInputChecksum.substring(0, 12).toUpperCase();
    const reportIdDerivationValid = computedReportId === reportIdFromChecksum;
    console.log(`Report ID Derivation: ${reportIdDerivationValid ? "✅ VALID" : "❌ MISMATCH"}`);
    if (!reportIdDerivationValid) {
      console.log(`  Expected: ${reportIdFromChecksum} (first 12 chars of input checksum)`);
      console.log(`  Computed: ${computedReportId}`);
      allValid = false;
    }

    console.log("\n=== Summary ===");
    if (allValid) {
      console.log("✅ All checksums and report ID are valid. Report integrity verified.");
      process.exit(0);
    } else {
      console.log("❌ Verification failed. One or more checksums do not match.");
      process.exit(1);
    }
  });

program.parse();

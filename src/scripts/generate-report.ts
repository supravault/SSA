#!/usr/bin/env node
// src/scripts/generate-report.ts
// Generate and archive SSA PDF report (Full Integrated Report support)

import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { Command } from "commander";
// Standard reports now use the same HTML->PDF pipeline as Full Integrated
import {
  generateFullIntegratedReport,
  computeInputChecksum,
  deriveReportId,
  canonicalizeJson,
  derivePulseVerdict,
  getScanVerdict,
  type FullIntegratedInputs,
} from "../report/fullIntegratedGenerator.js";
import { deriveBadge, type BadgeResult } from "../policy/badgePolicy.js";
import { deriveRiskBadge } from "../policy/riskBadgePolicy.js";
import { signBadge } from "../crypto/badgeSigner.js";
import type { BadgePayload } from "../crypto/badgeSigner.js";
import type { ScanResult } from "../core/types.js";
import { extractAssetList, normalizeTarget } from "../report/inputAdapters.js";
import { safeJsonRead } from "../report/utils.js";
import { createHash } from "crypto";

const program = new Command();

program
  .name("generate-report")
  .description("Generate and archive SSA PDF report from scan result")
  .version("0.1.0");

program
  .requiredOption("--scan <path>", "Path to primary scan result JSON file")
  .option("--input <path>", "Alias for --scan (deprecated)")
  .option("--wallet-scan <path>", "Path to optional wallet scan result JSON file")
  .option("--wallet <path>", "Alias for --wallet-scan (deprecated)")
  .option("--fa <path>", "Path to optional FA scan result JSON file (agent-verify output)")
  .option("--project <path>", "Path to optional project scan result JSON file")
  .option("--pulse <path>", "Path to Supra Pulse summary JSON (Premium/Spotlight tier required for Full Integrated)")
  .option("--project-name <name>", "Project name for archival (required if cannot derive from inputs)")
  .option("--ts-utc <ISO>", "UTC ISO timestamp for determinism (e.g. 2026-01-08T12:00:00Z)")
  .option("--out <dir>", "Archive base directory (default: reports)", "reports")
  .option("--archive-dir <dir>", "Alias for --out (deprecated)")
  .option("--no-sign", "Skip badge signing (even if SSA_BADGE_SIGNING_PRIVATE_KEY is set)")
  .option("--debug", "Enable debug mode: print missing verdict fields and other diagnostics")
  .action(async (options) => {
    try {
      // Load primary scan result
      const scanPath = options.scan || options.input;
      if (!scanPath || !existsSync(scanPath)) {
        console.error(`Error: Scan file not found: ${scanPath}`);
        process.exit(1);
      }

      const primaryScanData = safeJsonRead(scanPath);
      
      // Debug mode: check for missing verdict
      if (options.debug) {
        const primaryVerdict = getScanVerdict(primaryScanData);
        if (primaryVerdict === "UNKNOWN") {
          console.warn(`[DEBUG] Warning: Primary scan (${scanPath}) lacks verdict field.`);
          console.warn(`[DEBUG]   - scan.summary?.verdict: ${primaryScanData?.summary?.verdict ?? "missing"}`);
          console.warn(`[DEBUG]   - scan.verdict: ${primaryScanData?.verdict ?? "missing"}`);
          console.warn(`[DEBUG]   - scan.risk?.risk_level: ${primaryScanData?.risk?.risk_level ?? "missing"}`);
        }
      }
      
      const primaryScan: ScanResult = primaryScanData;
      const scans: ScanResult[] = [primaryScan];

      // Load optional wallet scan
      const walletPath = options.walletScan || options.wallet;
      if (walletPath) {
        if (!existsSync(walletPath)) {
          console.warn(`Warning: Wallet scan file not found: ${walletPath}`);
        } else {
          console.log(`Loading wallet scan: ${walletPath}...`);
          const walletScanData = safeJsonRead(walletPath);
          
          // Debug mode: check for missing verdict
          if (options.debug) {
            const walletVerdict = getScanVerdict(walletScanData);
            if (walletVerdict === "UNKNOWN") {
              console.warn(`[DEBUG] Warning: Wallet scan (${walletPath}) lacks verdict field.`);
            }
          }
          
          scans.push(walletScanData);
        }
      }

      // Load optional FA scan (agent-verify output)
      // Agent-verify produces VerificationReport, not ScanResult - normalize it
      if (options.fa) {
        if (!existsSync(options.fa)) {
          console.warn(`Warning: FA scan file not found: ${options.fa}`);
        } else {
          console.log(`Loading FA scan: ${options.fa}...`);
          const faData = safeJsonRead(options.fa);
          // Check if it's a VerificationReport (agent-verify output) and normalize to ScanResult
          if (faData.claims && faData.provider_results && !faData.summary) {
            // It's a VerificationReport - convert to ScanResult format
            const normalizedScan: ScanResult = {
              request_id: faData.request_id || `verify_${Date.now()}`,
              target: {
                chain: "supra",
                module_address: faData.target.id || "",
                module_name: "fa_token",
                module_id: faData.target.id || "",
                kind: faData.target.kind || "fa",
              },
              scan_level: "quick",
              timestamp_iso: faData.timestamp_iso || new Date().toISOString(),
              engine: {
                name: "ssa-scanner",
                version: "0.1.0",
                ruleset_version: "move-ruleset-0.1.0",
              },
              artifact: {
                fetch_method: "rpc",
                artifact_hash: `fa_${faData.target.id}`,
                binding_note: `FA agent-verify for ${faData.target.id}`,
              },
              summary: {
                risk_score: (faData as any).riskScore || 0,
                verdict: "pass",
                severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                badge_eligibility: {
                  scanned: true,
                  no_critical: true,
                  security_verified: false,
                  continuously_monitored: false,
                  reasons: [],
                },
                capabilities: {
                  poolStats: false,
                  totalStaked: false,
                  queue: false,
                  userViews: false,
                },
              },
              findings: [],
              meta: {
                scan_options: {},
                rpc_url: faData.rpc_url || "",
                duration_ms: 0,
              },
            };
            // Debug mode: check for missing verdict in normalized scan
            if (options.debug) {
              const faVerdict = getScanVerdict(normalizedScan);
              if (faVerdict === "UNKNOWN") {
                console.warn(`[DEBUG] Warning: FA scan (${options.fa}) normalized from VerificationReport lacks verdict field.`);
              }
            }
            
            scans.push(normalizedScan);
          } else {
            // Assume it's already a ScanResult
            // Debug mode: check for missing verdict
            if (options.debug) {
              const faVerdict = getScanVerdict(faData);
              if (faVerdict === "UNKNOWN") {
                console.warn(`[DEBUG] Warning: FA scan (${options.fa}) lacks verdict field.`);
              }
            }
            
            scans.push(faData);
          }
        }
      }

      // Load optional project scan
      if (options.project) {
        if (!existsSync(options.project)) {
          console.warn(`Warning: Project scan file not found: ${options.project}`);
        } else {
          console.log(`Loading project scan: ${options.project}...`);
          const projectScanData = safeJsonRead(options.project);
          
          // Debug mode: check for missing verdict
          if (options.debug) {
            const projectVerdict = getScanVerdict(projectScanData);
            if (projectVerdict === "UNKNOWN") {
              console.warn(`[DEBUG] Warning: Project scan (${options.project}) lacks verdict field.`);
            }
          }
          
          scans.push(projectScanData);
        }
      }

      // Determine project name
      let projectName = options.projectName;
      if (!projectName) {
        const primaryTarget = primaryScan.target as any;
        projectName = primaryTarget?.module_id || primaryTarget?.address || "UnknownProject";
      }
      projectName = projectName.replace(/[^a-zA-Z0-9]/g, "_").substring(0, 50);

      // Determine timestamp (canonical format: ISO 8601 UTC, filesystem-safe)
      const timestampUtc = options.tsUtc || primaryScan.timestamp_iso || new Date().toISOString();
      // Canonical timestamp folder format: YYYY-MM-DDTHH-MM-SSZ (filesystem-safe, preserves ISO structure)
      // Example: 2026-01-08T12-34-56Z
      const timestampSafe = timestampUtc
        .replace(/:/g, "-") // Replace colons with dashes
        .replace(/\.\d{3}/, "") // Remove milliseconds if present
        .replace(/Z$/, "Z"); // Ensure Z suffix

      console.log(`Generating report for project: ${projectName} (${scans.length} scan(s))...`);

      // Load Supra Pulse summary if provided
      // Accept schema: { tier, score, timestamp_utc, summary, disclosure, verdict? }
      let pulseSummary: FullIntegratedInputs["pulseSummary"] | undefined;
      if (options.pulse) {
        if (!existsSync(options.pulse)) {
          console.warn(`Warning: Pulse file not found: ${options.pulse}`);
        } else {
          console.log(`Loading Supra Pulse summary: ${options.pulse}...`);
          try {
            const pulseData = safeJsonRead(options.pulse);
            
            // Extract tier (required for Full Integrated)
            const tier = pulseData.tier || pulseData.level || "Unknown";
            const tierLower = tier.toLowerCase().trim();
            const isEligibleTier = tierLower === "premium" || tierLower === "spotlight";
            
            if (!isEligibleTier) {
              console.warn(`Warning: Pulse tier "${tier}" is not eligible for Full Integrated Report. Requires Premium or Spotlight tier only.`);
              pulseSummary = undefined; // Will generate standard report (not Full Integrated)
            } else {
              // Extract score
              const score = pulseData.score ?? pulseData.premiumTotalScore;
              
              // Derive verdict if missing
              const { verdict, derived } = derivePulseVerdict(score, pulseData.verdict);
              
              // Debug mode: print verdict derivation info
              if (options.debug) {
                if (derived) {
                  console.log(`[DEBUG] Pulse verdict derived from score ${score}: ${verdict}`);
                } else {
                  console.log(`[DEBUG] Pulse verdict provided: ${verdict}`);
                }
                if (!pulseData.verdict && score === undefined) {
                  console.warn(`[DEBUG] Warning: Pulse JSON lacks both 'verdict' and 'score' fields. Verdict set to UNKNOWN.`);
                }
              }
              
              pulseSummary = {
                tier,
                score,
                timestamp: pulseData.timestamp || pulseData.timestamp_iso,
                timestamp_utc: pulseData.timestamp_utc || pulseData.timestamp || pulseData.timestamp_iso,
                interpretation: pulseData.interpretation,
                summary: pulseData.summary,
                verdict,
                disclosure: pulseData.disclosure,
                verdictDerived: derived,
              };
            }
          } catch (error) {
            console.warn(`Failed to parse Pulse JSON: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      }

      // Determine if Full Integrated Report mode
      const isFullIntegrated = !!pulseSummary;

      // Derive badges for all scans
      const badges: (BadgeResult | null)[] = [];
      const riskBadges: (BadgeResult | null)[] = [];
      const signedBadges: any[] = [];

      for (const scan of scans) {
        const badgeResult = deriveBadge(scan);
        const riskBadgeResult = deriveRiskBadge(scan);
        badges.push(badgeResult);
        riskBadges.push(riskBadgeResult);

        // Sign badge if signing key is available
        if (!options.noSign && badgeResult.tier !== "NONE") {
          const signingKey = process.env.SSA_BADGE_SIGNING_PRIVATE_KEY || process.env.SSA_BADGE_SIGNING_KEY;
          if (signingKey) {
            try {
              const target = scan.target as any;
              const kind = target?.kind || "unknown";
              const badgePayload: BadgePayload = {
                tier: badgeResult.tier,
                label: badgeResult.label,
                scan_id: scan.request_id,
                target: {
                  kind,
                  value: target.module_id || target.address || "",
                },
                timestamp_iso: scan.timestamp_iso,
                expires_at_iso: badgeResult.expires_at_iso,
                continuously_monitored: badgeResult.continuously_monitored,
              };
              const signedBadge = await signBadge(badgePayload, signingKey);
              signedBadges.push(signedBadge);
            } catch (error) {
              console.warn(`Failed to sign badge: ${error instanceof Error ? error.message : String(error)}`);
              signedBadges.push(null);
            }
          } else {
            signedBadges.push(null);
          }
        } else {
          signedBadges.push(null);
        }
      }

      // Create archive directory: reports/{project_name}/{timestamp}/
      const archiveDir = options.out || options.archiveDir || "reports";
      const archivePath = join(archiveDir, projectName, timestampSafe);
      mkdirSync(archivePath, { recursive: true });

      if (isFullIntegrated) {
        // Generate Full Integrated Report
        console.log("Generating Full Integrated Report...");

        // Prepare inputs bundle
        const inputs: FullIntegratedInputs = {
          scans,
          badges,
          riskBadges,
          signedBadges: signedBadges.length > 0 ? signedBadges : undefined,
          pulseSummary,
          generatorVersion: "ssa-report-v1",
          timestampUtc,
        };

        // Compute input checksum and report ID
        const inputChecksum = computeInputChecksum(inputs);
        const reportId = deriveReportId(inputChecksum);

        // Save inputs.json (canonical bundle) - use canonicalizeJson for determinism
        const inputsPath = join(archivePath, "inputs.json");
        writeFileSync(inputsPath, canonicalizeJson(inputs));

        // Save pulse summary if provided
        if (pulseSummary) {
          const pulsePath = join(archivePath, "supra_pulse_summary.json");
          writeFileSync(pulsePath, JSON.stringify(pulseSummary, null, 2));
        }

        // Generate Full Integrated PDF
        const pdfPath = join(archivePath, "final_report.pdf");
        // Determine if this is truly Full Integrated (Pulse tier must be Premium/Spotlight)
        const isFullIntegrated = !!pulseSummary && 
          (pulseSummary.tier === "Premium" || pulseSummary.tier === "Spotlight");
        
        const pdfChecksum = await generateFullIntegratedReport({
          inputs,
          projectName,
          outputPath: pdfPath,
          reportId,
          inputChecksum,
          isFullIntegrated,
        });

        // Write checksum.txt
        const checksumPath = join(archivePath, "checksum.txt");
        writeFileSync(
          checksumPath,
          `input_checksum=${inputChecksum}\npdf_checksum=${pdfChecksum}\nreport_id=${reportId}\n`
        );

        console.log("\n✅ Full Integrated Report generated and archived successfully!");
        console.log(`  PDF: ${pdfPath}`);
        console.log(`  Archive: ${archivePath}`);
        console.log(`  Report ID: ${reportId}`);
        console.log(`  Input Checksum: ${inputChecksum.substring(0, 16)}...`);
        console.log(`  PDF Checksum: ${pdfChecksum.substring(0, 16)}...`);
      } else {
        // Generate standard SSA report using HTML->PDF pipeline
        console.log("Generating standard SSA report...");
        
        const primaryScan = scans[0];
        const primaryBadge = badges[0];
        const primaryRiskBadge = riskBadges[0];

        const pdfPath = join(archivePath, "report.pdf");

        // Build inputs for standard report (single scan)
        const standardInputs: FullIntegratedInputs = {
          scans: [primaryScan],
          badges: [primaryBadge],
          riskBadges: [primaryRiskBadge],
          signedBadges: signedBadges.length > 0 ? [signedBadges[0]] : undefined,
          pulseSummary: undefined, // No pulse for standard report
          generatorVersion: "ssa-report-v1",
          timestampUtc,
        };

        // Compute input checksum and report ID for standard report
        const inputChecksum = computeInputChecksum(standardInputs);
        const reportId = deriveReportId(inputChecksum);

        // Generate PDF using HTML->PDF pipeline (isFullIntegrated = false)
        await generateFullIntegratedReport({
          inputs: standardInputs,
          projectName,
          outputPath: pdfPath,
          reportId,
          inputChecksum,
          isFullIntegrated: false, // Standard report, not Full Integrated
        });

        // Save report.json for standard reports
        writeFileSync(
          join(archivePath, "report.json"),
          JSON.stringify(primaryScan, null, 2)
        );

        // Save badge.json
        if (primaryBadge && primaryBadge.tier !== "NONE") {
          writeFileSync(
            join(archivePath, "badge.json"),
            JSON.stringify(primaryBadge, null, 2)
          );
        }

        // Save badge.sig if signed
        if (signedBadges.length > 0 && signedBadges[0]) {
          const badgeSig = {
            ...signedBadges[0],
            signed_at: new Date().toISOString(),
          };
          writeFileSync(
            join(archivePath, "badge.sig"),
            JSON.stringify(badgeSig, null, 2)
          );
        }

        console.log("\n✅ Standard SSA report generated and archived successfully!");
        console.log(`  PDF: ${pdfPath}`);
        console.log(`  Archive: ${archivePath}`);
        console.log(`\nBadge: ${primaryBadge?.label || "No badge issued"}`);
        if (primaryRiskBadge) {
          console.log(`Risk Badge: ${primaryRiskBadge.label}`);
        }
      }

      // Auto-commit if requested
      if (process.env.GIT_AUTO_COMMIT === "1") {
        const { execSync } = await import("child_process");
        try {
          execSync(`git add ${archivePath}`, { stdio: "inherit" });
          execSync(`git commit -m "Add SSA report: ${projectName}/${timestampSafe}"`, { stdio: "inherit" });
        } catch (error) {
          console.warn("Git auto-commit failed:", error instanceof Error ? error.message : String(error));
        }
      }
    } catch (error) {
      console.error("Error generating report:", error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program.parse(process.argv);

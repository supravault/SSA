// src/cli/pulse.ts
// Supra Pulse report attachment and extraction

import { copyFileSync, readFileSync, existsSync } from "fs";
import { join, basename, extname } from "path";
import { createHash } from "crypto";
import { createReadStream } from "fs";

export interface PulseMetadata {
  attached: boolean;
  kind: "pdf" | "json";
  sha256: string;
  filename: string;
  extracted_summary?: string[];
  raw_text_excerpt?: string;
  projectName?: string;
  tier?: string;
  premiumTotalScore?: number;
  keyBreakdown?: string[];
}

/**
 * Compute SHA256 hash of a file
 */
function computeSha256(filePath: string): string {
  const hash = createHash("sha256");
  const data = readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex");
}

/**
 * Extract text and data from PDF
 */
async function extractPdfText(pdfPath: string): Promise<{
  summary?: string[];
  excerpt?: string;
  projectName?: string;
  tier?: string;
  premiumTotalScore?: number;
  keyBreakdown?: string[];
}> {
  try {
    // Use pdf-parse if available, otherwise return minimal data
    let pdfParse;
    try {
      pdfParse = await import("pdf-parse");
    } catch {
      // pdf-parse not available, return empty
      return {};
    }

    const dataBuffer = readFileSync(pdfPath);
    const data = await pdfParse.default(dataBuffer);

    const text = data.text;
    const lines = text.split("\n").map((l: string) => l.trim()).filter((l: string) => l.length > 0);

    // Extract project name (look for patterns like "Project:", "Name:", etc.)
    let projectName: string | undefined;
    for (const line of lines) {
      if (line.match(/project\s*name/i) || line.match(/^name:/i)) {
        const match = line.match(/:?\s*(.+)/i);
        if (match) projectName = match[1];
        break;
      }
    }

    // Extract tier (look for "Tier:", "Level:", etc.)
    let tier: string | undefined;
    for (const line of lines) {
      if (line.match(/tier/i) || line.match(/level/i)) {
        const match = line.match(/:?\s*([A-Za-z0-9\s]+)/i);
        if (match) tier = match[1].trim();
        break;
      }
    }

    // Extract premium total score (look for "Premium", "Total Score", numbers)
    let premiumTotalScore: number | undefined;
    for (const line of lines) {
      const scoreMatch = line.match(/(?:premium|total)\s*score[:\s]*(\d+(?:\.\d+)?)/i);
      if (scoreMatch) {
        premiumTotalScore = parseFloat(scoreMatch[1]);
        break;
      }
    }

    // Extract key breakdown (look for bullet points, numbered lists, score breakdowns)
    const keyBreakdown: string[] = [];
    let inBreakdown = false;
    for (const line of lines) {
      if (line.match(/(?:breakdown|scores?|metrics?)/i)) {
        inBreakdown = true;
        continue;
      }
      if (inBreakdown && (line.match(/^[•\-\*]\s/) || line.match(/^\d+[\.\)]\s/) || line.match(/:\s*\d+/))) {
        keyBreakdown.push(line);
        if (keyBreakdown.length >= 10) break; // Limit to 10 items
      }
      if (inBreakdown && line.length === 0 && keyBreakdown.length > 0) {
        break; // End of breakdown section
      }
    }

    return {
      summary: lines.slice(0, 20), // First 20 lines as summary
      excerpt: text.substring(0, 500),
      projectName,
      tier,
      premiumTotalScore,
      keyBreakdown: keyBreakdown.length > 0 ? keyBreakdown : undefined,
    };
  } catch (error) {
    console.warn(`Failed to extract PDF text: ${error instanceof Error ? error.message : String(error)}`);
    return {};
  }
}

/**
 * Attach Supra Pulse report
 * Supports local PDF or JSON file paths
 */
export async function attachSupraPulse(
  pulsePathOrUrl: string,
  artifactsDir: string
): Promise<PulseMetadata | null> {
  try {
    // For now, only support local file paths
    // URL support can be added later
    if (pulsePathOrUrl.startsWith("http://") || pulsePathOrUrl.startsWith("https://")) {
      console.warn("URL support for --pulse not yet implemented, skipping");
      return null;
    }

    if (!existsSync(pulsePathOrUrl)) {
      console.warn(`Supra Pulse file not found: ${pulsePathOrUrl}`);
      return null;
    }

    const ext = extname(pulsePathOrUrl).toLowerCase();
    const kind = ext === ".json" ? "json" : "pdf";
    const filename = `supra_pulse${ext}`;
    const destPath = join(artifactsDir, filename);

    // Copy file to artifacts directory
    copyFileSync(pulsePathOrUrl, destPath);

    // Compute SHA256
    const sha256 = computeSha256(destPath);

    // Extract text if PDF
    let extractedSummary: string[] | undefined;
    let rawTextExcerpt: string | undefined;

    if (kind === "pdf") {
      const extracted = await extractPdfText(destPath);
      extractedSummary = extracted.summary;
      rawTextExcerpt = extracted.excerpt;
    } else if (kind === "json") {
      // For JSON, try to extract a summary
      try {
        const jsonData = JSON.parse(readFileSync(destPath, "utf-8"));
        // Extract key points if available
        if (jsonData.summary || jsonData.keyPoints) {
          const points = jsonData.summary || jsonData.keyPoints || [];
          extractedSummary = Array.isArray(points) ? points.slice(0, 10).map(String) : [String(points)];
        }
      } catch {
        // JSON parsing failed, continue without extraction
      }
    }

    return {
      attached: true,
      kind,
      sha256,
      filename,
      extracted_summary: extractedSummary,
      raw_text_excerpt: rawTextExcerpt,
    };
  } catch (error) {
    console.warn(`Failed to attach Supra Pulse report: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

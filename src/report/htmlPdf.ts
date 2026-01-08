// src/report/htmlPdf.ts
// Playwright-based HTML to PDF renderer

import { chromium, type Browser, type Page } from "playwright";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let browser: Browser | null = null;

/**
 * Get or create browser instance (singleton)
 */
async function getBrowser(): Promise<Browser> {
  if (!browser) {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
  }
  return browser;
}

/**
 * Close browser instance
 */
export async function closeHtmlPdfBrowser(): Promise<void> {
  if (browser) {
    await browser.close();
    browser = null;
  }
}

/**
 * Read SVG file and return as data URI
 */
function svgToDataUri(svgPath: string): string {
  // Resolve from repo root (not from dist/)
  // __dirname in dist is dist/src/report, so go up 3 levels to repo root
  const repoRoot = resolve(__dirname, "../../../");
  const fullPath = resolve(repoRoot, svgPath);
  if (!existsSync(fullPath)) {
    console.warn(`Warning: SVG file not found: ${fullPath}`);
    return "";
  }
  const svgContent = readFileSync(fullPath, "utf-8");
  // Encode SVG as data URI
  const encoded = encodeURIComponent(svgContent);
  return `data:image/svg+xml;charset=utf-8,${encoded}`;
}

/**
 * Render HTML to PDF using Playwright
 */
export async function renderHtmlToPdf(html: string, outputPath: string): Promise<void> {
  const browserInstance = await getBrowser();
  const page: Page = await browserInstance.newPage();

  try {
    // Set content and wait for network idle
    await page.setContent(html, { waitUntil: "networkidle" });

    // Footer template with page numbers and branding
    const footerTemplate = `
      <div style="
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        padding: 0 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        font-size: 9px;
        color: #666;
        letter-spacing: 0.5px;
      ">
        <div style="flex: 1; text-align: left;">
          SSA is a byproduct of Supra Vault
        </div>
        <div style="flex: 1; text-align: right;">
          Page <span class="pageNumber"></span> of <span class="totalPages"></span>
        </div>
      </div>
    `;

    // Generate PDF with footer
    await page.pdf({
      path: outputPath,
      format: "A4",
      printBackground: true,
      margin: {
        top: "50px",
        right: "50px",
        bottom: "70px", // Increased bottom margin to accommodate footer
        left: "50px",
      },
      displayHeaderFooter: true,
      footerTemplate: footerTemplate,
      headerTemplate: '<div></div>', // Empty header
    });
  } finally {
    await page.close();
  }
}

/**
 * Helper to embed SVG icons in HTML
 */
export function embedSvgIcon(iconPath: string, width: number = 100, height: number = 100): string {
  const dataUri = svgToDataUri(iconPath);
  if (!dataUri) {
    return `<div style="width: ${width}px; height: ${height}px; background: #ccc; display: inline-block;"></div>`;
  }
  return `<img src="${dataUri}" width="${width}" height="${height}" style="display: inline-block;" />`;
}

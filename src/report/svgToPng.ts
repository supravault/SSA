// src/report/svgToPng.ts
// Convert SVG files to PNG buffers using Playwright (with caching)

import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import type { Browser } from "playwright";

let browserInstance: Browser | null = null;
const cache = new Map<string, Buffer>();

export interface SvgToPngOptions {
  width: number;
  height: number;
  grayscale?: boolean;
  opacity?: number;
  background?: "transparent" | "white";
}

/**
 * Get or create Playwright browser instance (singleton)
 */
async function getBrowser(): Promise<Browser> {
  if (!browserInstance) {
    const { chromium } = await import("playwright");
    browserInstance = await chromium.launch({
      headless: true,
    });
  }
  return browserInstance;
}

/**
 * Close browser instance (call at end of generation)
 */
export async function closeSvgBrowser(): Promise<void> {
  if (browserInstance) {
    await browserInstance.close();
    browserInstance = null;
  }
  cache.clear();
}

/**
 * Convert SVG file to PNG buffer
 * Uses caching to avoid re-rendering the same SVG with same options
 */
export async function svgToPngBuffer(
  svgPath: string,
  options: SvgToPngOptions
): Promise<Buffer> {
  // Resolve absolute path
  const absolutePath = resolve(svgPath);
  if (!existsSync(absolutePath)) {
    throw new Error(`SVG file not found: ${absolutePath}`);
  }

  // Create cache key
  const cacheKey = JSON.stringify({ path: absolutePath, options });
  if (cache.has(cacheKey)) {
    return cache.get(cacheKey)!;
  }

  // Read SVG content
  const svgContent = readFileSync(absolutePath, "utf-8");

  // Create HTML page with SVG inline
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      margin: 0;
      padding: 0;
      width: ${options.width}px;
      height: ${options.height}px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: ${options.background === "white" ? "white" : "transparent"};
    }
    svg {
      width: ${options.width}px;
      height: ${options.height}px;
      ${options.grayscale ? "filter: grayscale(1);" : ""}
      ${options.opacity !== undefined ? `opacity: ${options.opacity};` : ""}
    }
  </style>
</head>
<body>
  ${svgContent}
</body>
</html>
  `;

  // Use Playwright to render
  const browser = await getBrowser();
  const page = await browser.newPage();

  try {
    await page.setContent(html, { waitUntil: "networkidle" });
    
    // Screenshot the SVG element
    const buffer = await page.screenshot({
      type: "png",
      omitBackground: options.background === "transparent",
      clip: {
        x: 0,
        y: 0,
        width: options.width,
        height: options.height,
      },
    });

    // Cache the result
    cache.set(cacheKey, buffer as Buffer);

    return buffer as Buffer;
  } finally {
    await page.close();
  }
}

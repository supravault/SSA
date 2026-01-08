import express from "express";
import dotenv from "dotenv";
import { runScan } from "./core/scanner.js";
import { validateModuleId } from "./utils/validate.js";
import { fileStore } from "./store/fileStore.js";
import type { ModuleId, ScanLevel } from "./core/types.js";
import ssaRoutes from "./api/ssaRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Mount unified SSA API routes
app.use("/api/ssa", ssaRoutes);

/**
 * Health check endpoint
 */
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

/**
 * POST /scan
 * Request body: { address: string, module_name: string, scan_level?: ScanLevel }
 * Returns: { request_id: string }
 */
app.post("/scan", async (req, res) => {
  try {
    const { address, module_name, scan_level } = req.body;

    if (!address || !module_name) {
      return res.status(400).json({
        error: "Missing required fields: address and module_name are required",
      });
    }

    const moduleId: ModuleId = {
      address: address.trim(),
      module_name: module_name.trim(),
    };

    // Validate module ID
    const validation = validateModuleId(moduleId);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Get RPC URL and proxy base from env or use defaults
    const rpcUrl = process.env.SUPRA_RPC_URL || "https://rpc.supra.com";
    const proxyBase = process.env.PROD_API; // Railway proxy base URL (optional)

    // Run scan with view-based inspection
    const result = await runScan(moduleId, {
      scan_level: (scan_level as ScanLevel) || "quick",
      rpc_url: rpcUrl,
      proxy_base: proxyBase,
      allowed_views: req.body.allowed_views, // Optional: specify which views to call
    });

    // Store result
    fileStore.set(result.request_id, result);

    // Return request ID
    res.json({ request_id: result.request_id });
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({
      error: "Scan failed",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

/**
 * GET /scan/:request_id
 * Returns: Full ScanResult JSON
 */
app.get("/scan/:request_id", (req, res) => {
  try {
    const { request_id } = req.params;

    const result = fileStore.get(request_id);
    if (!result) {
      return res.status(404).json({ error: "Scan result not found" });
    }

    res.json(result);
  } catch (error) {
    console.error("Get scan error:", error);
    res.status(500).json({
      error: "Failed to retrieve scan result",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

app.listen(PORT, () => {
  console.log(`SSA Scanner API server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Legacy scan endpoint: POST http://localhost:${PORT}/scan`);
  console.log(`Legacy get result: GET http://localhost:${PORT}/scan/:request_id`);
  console.log(`Unified SSA API: POST http://localhost:${PORT}/api/ssa/scan`);
  console.log(`Get scan result: GET http://localhost:${PORT}/api/ssa/scan/:scanId`);
});

/**
 * Monitoring Registry
 * -------------------
 * Canonical source of truth for SSA continuous monitoring.
 *
 * Design rules (NON-NEGOTIABLE):
 * - Registry ships EMPTY
 * - Scans NEVER auto-register targets
 * - Monitoring must be explicitly enabled
 * - Level 5 scans only UPDATE last_run_* IF already enabled
 * - Registry is auditable, JSON-based, and UI-consumable
 */

import fs from "node:fs";
import path from "node:path";

const REGISTRY_PATH = path.resolve("data/monitor_registry.json");

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

export type MonitorKind = "fa" | "coin" | "wallet";

export interface MonitorEntry {
  kind: MonitorKind;
  target: string;

  enabled: boolean;
  cadence_hours: number;

  started_at: string;         // ISO
  last_run_utc?: string;      // ISO
  last_scan_id?: string;
}

export type MonitorRegistry = Record<string, MonitorEntry>;

export interface MonitoringStatus {
  enabled: boolean;
  monitoring_active: boolean;

  cadence_hours?: number;
  last_run_utc?: string;
  next_scheduled_utc?: string;

  reason?: string;
}

/* ------------------------------------------------------------------ */
/* Utilities                                                          */
/* ------------------------------------------------------------------ */

function ensureRegistryFile(): void {
  if (!fs.existsSync(REGISTRY_PATH)) {
    fs.mkdirSync(path.dirname(REGISTRY_PATH), { recursive: true });
    fs.writeFileSync(REGISTRY_PATH, JSON.stringify({}, null, 2));
  }
}

export function canonicalKey(kind: MonitorKind, target: string): string {
  return `${kind}:${target}`;
}

function parseISO(ts?: string): number | null {
  if (!ts) return null;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? null : t;
}

function nowUTC(): string {
  return new Date().toISOString();
}

/* ------------------------------------------------------------------ */
/* Registry Load / Save                                                */
/* ------------------------------------------------------------------ */

export function loadRegistry(): MonitorRegistry {
  ensureRegistryFile();
  const raw = fs.readFileSync(REGISTRY_PATH, "utf8");
  return JSON.parse(raw || "{}");
}

export function saveRegistry(registry: MonitorRegistry): void {
  fs.writeFileSync(REGISTRY_PATH, JSON.stringify(registry, null, 2));
}

/* ------------------------------------------------------------------ */
/* Registry Access                                                     */
/* ------------------------------------------------------------------ */

export function getEntry(
  kind: MonitorKind,
  target: string
): MonitorEntry | undefined {
  const registry = loadRegistry();
  return registry[canonicalKey(kind, target)];
}

/* ------------------------------------------------------------------ */
/* Enable / Disable Monitoring                                         */
/* ------------------------------------------------------------------ */

export function enableMonitoring(
  kind: MonitorKind,
  target: string,
  cadence_hours: number
): MonitorEntry {
  if (cadence_hours <= 0) {
    throw new Error("cadence_hours must be > 0");
  }

  const registry = loadRegistry();
  const key = canonicalKey(kind, target);

  const entry: MonitorEntry = {
    kind,
    target,
    enabled: true,
    cadence_hours,
    started_at: nowUTC(),
  };

  registry[key] = entry;
  saveRegistry(registry);

  return entry;
}

export function disableMonitoring(
  kind: MonitorKind,
  target: string
): void {
  const registry = loadRegistry();
  const key = canonicalKey(kind, target);

  const entry = registry[key];
  if (!entry) return;

  entry.enabled = false;
  saveRegistry(registry);
}

/* ------------------------------------------------------------------ */
/* Scan Touch (Level 5 only)                                           */
/* ------------------------------------------------------------------ */

export function touchRun(
  kind: MonitorKind,
  target: string,
  scanId: string
): void {
  const registry = loadRegistry();
  const key = canonicalKey(kind, target);

  const entry = registry[key];
  if (!entry) return;
  if (!entry.enabled) return;

  entry.last_run_utc = nowUTC();
  entry.last_scan_id = scanId;

  saveRegistry(registry);
}

/* ------------------------------------------------------------------ */
/* Status Computation (Read-Only, UI Safe)                             */
/* ------------------------------------------------------------------ */

export function computeMonitoringStatus(
  entry?: MonitorEntry
): MonitoringStatus {
  if (!entry) {
    return {
      enabled: false,
      monitoring_active: false,
      reason: "not_registered",
    };
  }

  if (!entry.enabled) {
    return {
      enabled: false,
      monitoring_active: false,
      reason: "monitoring_disabled",
    };
  }

  const lastRunMs = parseISO(entry.last_run_utc);
  if (!lastRunMs) {
    return {
      enabled: true,
      monitoring_active: false,
      cadence_hours: entry.cadence_hours,
      reason: "no_monitor_run_yet",
    };
  }

  const cadenceMs = entry.cadence_hours * 60 * 60 * 1000;
  const nowMs = Date.now();

  const active = nowMs - lastRunMs <= cadenceMs * 2;

  const nextScheduled =
    new Date(lastRunMs + cadenceMs).toISOString();

  return {
    enabled: true,
    monitoring_active: active,
    cadence_hours: entry.cadence_hours,
    last_run_utc: entry.last_run_utc,
    next_scheduled_utc: nextScheduled,
    reason: active ? undefined : "monitoring_stale",
  };
}

/* ------------------------------------------------------------------ */
/* Registry Listing (Dashboard View)                                   */
/* ------------------------------------------------------------------ */

export function listRegistry(): Array<{
  key: string;
  entry: MonitorEntry;
  status: MonitoringStatus;
}> {
  const registry = loadRegistry();

  return Object.entries(registry).map(([key, entry]) => ({
    key,
    entry,
    status: computeMonitoringStatus(entry),
  }));
}

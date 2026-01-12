/**
 * CLI: Monitoring Control & View
 * ------------------------------
 * This file provides explicit, auditable commands to manage SSA monitoring.
 *
 * IMPORTANT RULES:
 * - Enabling monitoring is an explicit user action
 * - Scans NEVER auto-register targets
 * - This CLI is the ONLY place that mutates monitoring state
 * - Output is UI-safe and Base44-consumable
 */

import {
  enableMonitoring,
  disableMonitoring,
  getEntry,
  listRegistry,
  computeMonitoringStatus,
  canonicalKey,
  type MonitorKind,
} from "../monitoring/registry.js";

/* ------------------------------------------------------------------ */
/* Argument Helpers                                                   */
/* ------------------------------------------------------------------ */

function requireArg(
  name: string,
  value?: string
): string {
  if (!value) {
    throw new Error(`Missing required argument: --${name}`);
  }
  return value;
}

function parseKind(raw?: string): MonitorKind {
  if (raw === "fa" || raw === "coin" || raw === "wallet") {
    return raw;
  }
  throw new Error(`Invalid --kind. Expected one of: fa | coin | wallet`);
}

function parseCadence(raw?: string): number {
  const v = Number(raw);
  if (!Number.isFinite(v) || v <= 0) {
    throw new Error(`Invalid --cadence. Must be a positive number (hours)`);
  }
  return v;
}

/* ------------------------------------------------------------------ */
/* Commands                                                          */
/* ------------------------------------------------------------------ */

export async function handleMonitorCommand(
  subcommand: string,
  args: Record<string, string | undefined>
): Promise<void> {
  switch (subcommand) {
    case "enable":
      return cmdEnable(args);
    case "disable":
      return cmdDisable(args);
    case "status":
      return cmdStatus(args);
    case "list":
      return cmdList();
    default:
      throw new Error(
        `Unknown monitor subcommand: ${subcommand}\n` +
        `Expected one of: enable | disable | status | list`
      );
  }
}

/* ------------------------------------------------------------------ */
/* enable                                                            */
/* ------------------------------------------------------------------ */

async function cmdEnable(
  args: Record<string, string | undefined>
): Promise<void> {
  const kind = parseKind(args.kind);
  const target = requireArg("target", args.target);
  const cadence = parseCadence(args.cadence);

  const entry = enableMonitoring(kind, target, cadence);

  const out = {
    action: "monitor_enable",
    key: canonicalKey(kind, target),
    entry,
  };

  console.log(JSON.stringify(out, null, 2));
}

/* ------------------------------------------------------------------ */
/* disable                                                           */
/* ------------------------------------------------------------------ */

async function cmdDisable(
  args: Record<string, string | undefined>
): Promise<void> {
  const kind = parseKind(args.kind);
  const target = requireArg("target", args.target);

  disableMonitoring(kind, target);

  const out = {
    action: "monitor_disable",
    key: canonicalKey(kind, target),
    disabled: true,
  };

  console.log(JSON.stringify(out, null, 2));
}

/* ------------------------------------------------------------------ */
/* status                                                            */
/* ------------------------------------------------------------------ */

async function cmdStatus(
  args: Record<string, string | undefined>
): Promise<void> {
  const kind = parseKind(args.kind);
  const target = requireArg("target", args.target);

  const entry = getEntry(kind, target);
  const status = computeMonitoringStatus(entry);

  const out = {
    kind,
    target,
    key: canonicalKey(kind, target),
    registered: Boolean(entry),
    status,
    entry: entry ?? null,
  };

  console.log(JSON.stringify(out, null, 2));
}

/* ------------------------------------------------------------------ */
/* list                                                              */
/* ------------------------------------------------------------------ */

async function cmdList(): Promise<void> {
  const rows = listRegistry().map(({ key, entry, status }) => ({
    key,
    kind: entry.kind,
    target: entry.target,
    enabled: entry.enabled,
    cadence_hours: entry.cadence_hours,
    last_run_utc: entry.last_run_utc ?? null,
    monitoring_active: status.monitoring_active,
    next_scheduled_utc: status.next_scheduled_utc ?? null,
  }));

  console.log(JSON.stringify(rows, null, 2));
}


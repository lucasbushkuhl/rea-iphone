// Run a generated agent script with the frida CLI and collect its events.
// Requires frida-tools on this computer and frida-server (or a Frida gadget)
// on a device you control.

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../util/exec.js";
import { generateScript } from "./scripts.js";

const BUNDLE_RE = /^[A-Za-z0-9][A-Za-z0-9.\-_]{0,254}$/;

/**
 * device: "usb" (default) | "remote" | { id } | { host }
 * target: { bundleId, spawn } | { name } | { pid } | { frontmost: true }
 */
export function buildFridaArgs({ device = "usb", target, scriptPath, seconds = 20 }) {
  const args = [];
  if (device === "usb") args.push("-U");
  else if (device === "remote") args.push("-R");
  else if (device && typeof device === "object" && device.id) args.push("-D", String(device.id));
  else if (device && typeof device === "object" && device.host) args.push("-H", String(device.host));
  else throw new Error('device must be "usb", "remote", { id }, or { host }');

  if (!target || typeof target !== "object") throw new Error("target is required");
  if (target.bundleId) {
    if (!BUNDLE_RE.test(target.bundleId)) throw new Error(`invalid bundle identifier: ${target.bundleId}`);
    args.push(target.spawn === false ? "-N" : "-f", target.bundleId);
  } else if (target.name) args.push("-n", String(target.name));
  else if (target.pid != null) {
    if (!Number.isInteger(Number(target.pid))) throw new Error("pid must be an integer");
    args.push("-p", String(target.pid));
  } else if (target.frontmost) args.push("-F");
  else throw new Error("target needs bundleId, name, pid, or frontmost");

  const secs = Math.min(600, Math.max(1, Math.trunc(Number(seconds) || 20)));
  args.push("-l", scriptPath, "-q", "-t", String(secs));
  return { args, seconds: secs };
}

export function parseEvents(stdout, { maxLogs = 200 } = {}) {
  const events = [];
  const logs = [];
  for (const line of stdout.split("\n")) {
    const i = line.indexOf("REA_EVT ");
    if (i >= 0) {
      try { events.push(JSON.parse(line.slice(i + 8))); continue; } catch { /* treat as log */ }
    }
    if (line.trim() && logs.length < maxLogs) logs.push(line);
  }
  const counts = {};
  for (const e of events) counts[e.type] = (counts[e.type] ?? 0) + 1;
  return { events, logs, counts };
}

/** Generate + run a session. Returns { ok, events, counts, logs, command, ... }. */
export async function runFridaSession({ mode, patterns, device, target, seconds, scriptOptions = {}, script } = {}) {
  const source = script ?? generateScript(mode, { patterns, ...scriptOptions });
  const dir = mkdtempSync(join(tmpdir(), "rea-iphone-frida-"));
  const scriptPath = join(dir, "agent.js");
  writeFileSync(scriptPath, source, { mode: 0o600 });
  try {
    const { args, seconds: secs } = buildFridaArgs({ device, target, scriptPath, seconds });
    const r = await run("frida", args, { timeoutMs: (secs + 20) * 1000, timeoutIsSuccess: true, maxBytes: 64 * 1024 * 1024 });
    if (r.missing) return { ok: false, error: `${r.stderr}. Install frida-tools (pip install frida-tools) and run frida-server on the device.`, command: r.argv };
    const parsed = parseEvents(r.stdout);
    const ok = parsed.events.some((e) => e.type === "ready") || (r.ok && !/Failed to|unable to/i.test(r.stderr));
    return {
      ok,
      mode: mode ?? "custom",
      seconds: secs,
      exitCode: r.code,
      timedOut: r.timedOut,
      ...parsed,
      stderr: r.stderr.trim().slice(0, 2000) || null,
      command: r.argv.map((a) => (a === scriptPath ? "<agent.js>" : a)),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

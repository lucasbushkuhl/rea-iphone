// iPhone device layer over libimobiledevice — the iOS counterpart of an adb
// adapter. Talks only to devices that are paired with (have "Trusted") this
// computer, which iOS requires the device owner to approve on-screen.
// Every result records the exact argv it ran, for transparency.
//
// Tools (caller-installed): idevice_id, ideviceinfo, ideviceinstaller,
// idevicesyslog, idevicecrashreport, idevicescreenshot, idevicepair.
// Discovery: PATH, or REA_IPHONE_TOOLS_DIR.

import { mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { run } from "../util/exec.js";
import { parsePlist } from "../plist.js";
import { summarizeCrashReport } from "../ips.js";

const UDID_RE = /^[0-9A-Fa-f][0-9A-Fa-f-]{23,39}/;
const SUMMARY_KEYS = [
  "DeviceName", "ProductType", "ProductVersion", "BuildVersion", "CPUArchitecture",
  "HardwareModel", "DeviceClass", "UniqueDeviceID", "ActivationState", "TimeZone",
];

const udidArgs = (udid) => (udid ? ["-u", udid] : []);
const fail = (r, what) => ({ ok: false, error: r.missing ? r.stderr : `${what} failed (exit ${r.code}${r.timedOut ? ", timed out" : ""}): ${(r.stderr || r.stdout).trim().slice(0, 500)}`, command: r.argv });

/** USB- and network-attached devices with a short identity for each. */
export async function listDevices({ withInfo = true } = {}) {
  const usb = await run("idevice_id", ["-l"], { timeoutMs: 15000 });
  if (usb.missing) return fail(usb, "idevice_id");
  const net = await run("idevice_id", ["-n"], { timeoutMs: 15000 });
  const parse = (out, transport) => out.split("\n").map((l) => l.trim().match(UDID_RE)?.[0]).filter(Boolean).map((udid) => ({ udid, transport }));
  const seen = new Set();
  const devices = [];
  for (const d of [...parse(usb.stdout, "usb"), ...(net.ok ? parse(net.stdout, "network") : [])]) {
    if (seen.has(d.udid)) continue;
    seen.add(d.udid);
    devices.push(d);
  }
  if (withInfo) {
    for (const d of devices) {
      const info = await deviceInfo(d.udid, { network: d.transport === "network" });
      if (info.ok) Object.assign(d, { name: info.summary.DeviceName ?? null, product: info.summary.ProductType ?? null, ios: info.summary.ProductVersion ?? null });
      else d.info_error = info.error;
    }
  }
  return { ok: true, devices, command: usb.argv };
}

/** Full device properties (ideviceinfo -x) plus a short summary. */
export async function deviceInfo(udid, { network = false, domain } = {}) {
  const args = [...udidArgs(udid), ...(network ? ["-n"] : []), ...(domain ? ["-q", domain] : []), "-x"];
  const r = await run("ideviceinfo", args, { timeoutMs: 20000 });
  if (!r.ok) return fail(r, "ideviceinfo");
  let props;
  try {
    props = parsePlist(Buffer.from(r.stdout, "utf8"));
  } catch (err) {
    return { ok: false, error: `could not parse ideviceinfo output: ${err.message}`, command: r.argv };
  }
  const summary = {};
  for (const k of SUMMARY_KEYS) if (props?.[k] !== undefined) summary[k] = props[k];
  return { ok: true, summary, properties: props, command: r.argv };
}

/** Pairing status for a device (idevicepair validate). */
export async function validatePairing(udid) {
  const r = await run("idevicepair", [...udidArgs(udid), "validate"], { timeoutMs: 15000 });
  if (r.missing) return fail(r, "idevicepair");
  return { ok: true, paired: r.code === 0 && /SUCCESS/i.test(r.stdout), message: (r.stdout || r.stderr).trim(), command: r.argv };
}

function summarizeApp(a) {
  return {
    bundle_id: a.CFBundleIdentifier ?? null,
    name: a.CFBundleDisplayName ?? a.CFBundleName ?? null,
    version: a.CFBundleShortVersionString ?? null,
    build: a.CFBundleVersion ?? null,
    type: a.ApplicationType ?? null,
    minimum_os: a.MinimumOSVersion ?? null,
    executable: a.CFBundleExecutable ?? null,
    path: a.Path ?? null,
    container: a.Container ?? null,
    signer: a.SignerIdentity ?? null,
    entitlement_keys: a.Entitlements ? Object.keys(a.Entitlements) : null,
  };
}

/** Installed applications: type "user" (default), "system", or "all". */
export async function listApps(udid, { type = "user" } = {}) {
  const legacyOpt = { user: "list_user", system: "list_system", all: "list_all" }[type] ?? "list_user";
  const attempts = [
    [...udidArgs(udid), "-l", "-o", legacyOpt, "-o", "xml"], // ideviceinstaller <= 1.1.x
    [...udidArgs(udid), "list", `--${type}`, "--xml"], // newer subcommand syntax
  ];
  let last;
  for (const args of attempts) {
    const r = await run("ideviceinstaller", args, { timeoutMs: 60000 });
    last = r;
    if (r.missing) return fail(r, "ideviceinstaller");
    if (!r.ok) continue;
    const out = r.stdout;
    const xmlStart = out.indexOf("<?xml");
    if (xmlStart >= 0) {
      try {
        const parsed = parsePlist(Buffer.from(out.slice(xmlStart), "utf8"));
        const apps = (Array.isArray(parsed) ? parsed : []).map(summarizeApp).sort((a, b) => (a.bundle_id ?? "").localeCompare(b.bundle_id ?? ""));
        return { ok: true, type, count: apps.length, apps, command: r.argv };
      } catch { /* try plain-text parse */ }
    }
    // Plain text: "com.example.app, "1.0", "Name""
    const apps = [];
    for (const line of out.split("\n")) {
      const m = /^([A-Za-z0-9.\-_]+),\s*"([^"]*)",\s*"([^"]*)"/.exec(line.trim());
      if (m) apps.push({ bundle_id: m[1], version: m[2], name: m[3] });
    }
    if (apps.length || /CFBundleIdentifier/.test(out)) return { ok: true, type, count: apps.length, apps, command: r.argv };
  }
  return fail(last, "ideviceinstaller");
}

const SYSLOG_RE = /^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+([^[\s(]+)(?:\(([^)]*)\))?\[(\d+)\]\s+<(\w+)>:\s?(.*)$/;

/**
 * Capture device syslog for a bounded duration. Filters are applied locally
 * (process name and/or substring/regex match) so any idevicesyslog version
 * works. seconds is clamped to [1, 300]; maxLines caps output.
 */
export async function captureSyslog(udid, { seconds = 10, match, process: proc, maxLines = 5000 } = {}) {
  const secs = Math.min(300, Math.max(1, Number(seconds) || 10));
  let re = null;
  if (match) {
    try { re = new RegExp(match, "i"); } catch { re = null; }
  }
  const lines = [];
  let dropped = 0;
  const r = await run("idevicesyslog", [...udidArgs(udid)], {
    timeoutMs: secs * 1000,
    timeoutIsSuccess: true,
    maxBytes: 32 * 1024 * 1024,
    onLine: (raw) => {
      const line = raw.replace(/\x1b\[[0-9;]*m/g, ""); // strip color codes
      if (!line.trim()) return;
      const m = SYSLOG_RE.exec(line);
      const entry = m
        ? { time: m[1], device: m[2], process: m[3], library: m[4] ?? null, pid: Number(m[5]), level: m[6], message: m[7] }
        : { raw: line };
      if (proc && entry.process !== proc) return;
      if (match && !(re ? re.test(line) : line.includes(match))) return;
      if (lines.length < maxLines) lines.push(entry);
      else dropped++;
    },
  });
  if (r.missing) return fail(r, "idevicesyslog");
  if (!r.ok && !r.timedOut) return fail(r, "idevicesyslog");
  return { ok: true, seconds: secs, count: lines.length, dropped, lines, command: r.argv };
}

/** Copy crash reports off the device (kept on device) and summarize them. */
export async function pullCrashReports(udid, outDir, { filter, keepOnDevice = true } = {}) {
  mkdirSync(outDir, { recursive: true });
  const args = [...udidArgs(udid), ...(keepOnDevice ? ["-k"] : []), "-e", ...(filter ? ["-f", filter] : []), outDir];
  const r = await run("idevicecrashreport", args, { timeoutMs: 180000 });
  if (!r.ok) return fail(r, "idevicecrashreport");
  const reports = summarizeCrashDirectory(outDir);
  return { ok: true, outDir, count: reports.length, reports, command: r.argv };
}

export function summarizeCrashDirectory(dir) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const f = join(d, n);
      const st = statSync(f);
      if (st.isDirectory()) walk(f);
      else if (/\.(ips|crash)$/i.test(n) && st.size < 16 * 1024 * 1024) {
        try { out.push(summarizeCrashReport(readFileSync(f, "utf8"), f)); } catch { /* unreadable */ }
      }
    }
  };
  walk(dir);
  return out.sort((a, b) => String(b.timestamp ?? "").localeCompare(String(a.timestamp ?? "")));
}

/** Take a screenshot (requires the developer disk image on some iOS versions). */
export async function screenshot(udid, outFile) {
  const r = await run("idevicescreenshot", [...udidArgs(udid), outFile], { timeoutMs: 30000 });
  if (!r.ok) {
    const res = fail(r, "idevicescreenshot");
    res.hint = "Screenshots need the Developer Disk Image mounted (Xcode/ideviceimagemounter); iOS 17+ uses a different developer-services path that some libimobiledevice builds lack.";
    return res;
  }
  return { ok: true, file: outFile, command: r.argv };
}

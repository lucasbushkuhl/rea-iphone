// Safe external-process execution: argv arrays only (never a shell), hard
// timeouts, bounded output, and tool discovery from PATH or an explicit
// directory (REA_IPHONE_TOOLS_DIR).

import { spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, join } from "node:path";

export function findTool(name, env = process.env) {
  const dirs = [];
  if (env.REA_IPHONE_TOOLS_DIR) dirs.push(env.REA_IPHONE_TOOLS_DIR);
  dirs.push(...(env.PATH ?? "").split(delimiter).filter(Boolean));
  for (const d of dirs) {
    const p = join(d, name);
    try {
      accessSync(p, constants.X_OK);
      return p;
    } catch { /* keep looking */ }
  }
  return null;
}

/**
 * Run a tool. Resolves (never rejects) with
 * { ok, code, signal, stdout, stderr, timedOut, truncated, argv, durationMs }.
 * `timeoutIsSuccess` treats hitting the time limit as a normal end (streams
 * such as syslog capture run until stopped).
 */
export function run(tool, args, { timeoutMs = 30000, maxBytes = 8 * 1024 * 1024, timeoutIsSuccess = false, env = process.env, onLine } = {}) {
  const path = tool.includes("/") ? tool : findTool(tool, env);
  const argv = [path ?? tool, ...args];
  if (!path) {
    return Promise.resolve({ ok: false, code: null, signal: null, stdout: "", stderr: `${tool}: not found (install it or set REA_IPHONE_TOOLS_DIR)`, timedOut: false, truncated: false, argv, durationMs: 0, missing: true });
  }
  const started = Date.now();
  return new Promise((resolve) => {
    // Own process group, so a timeout stops the tool *and* any helpers it
    // spawned (grandchildren holding our pipes open would otherwise hang us).
    const child = spawn(path, args, { env, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
    track(child);
    let stdout = "";
    let stderr = "";
    let truncated = false;
    let timedOut = false;
    let pending = "";
    let settled = false;
    const take = (cur, chunk) => {
      if (cur.length >= maxBytes) { truncated = true; return cur; }
      const s = chunk.toString("utf8");
      if (cur.length + s.length > maxBytes) { truncated = true; return cur + s.slice(0, maxBytes - cur.length); }
      return cur + s;
    };
    child.stdout.on("data", (c) => {
      stdout = take(stdout, c);
      if (onLine) {
        pending += c.toString("utf8");
        const lines = pending.split("\n");
        pending = lines.pop();
        for (const l of lines) onLine(l);
      }
    });
    child.stderr.on("data", (c) => { stderr = take(stderr, c); });
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child, "SIGTERM");
      setTimeout(() => killTree(child, "SIGKILL"), 2000).unref();
    }, timeoutMs);
    const finish = (code, signal, extraErr) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      untrack(child);
      if (onLine && pending) onLine(pending);
      const ok = (code === 0 && !timedOut) || (timedOut && timeoutIsSuccess);
      resolve({ ok, code, signal, stdout, stderr: extraErr ? `${stderr}${extraErr}` : stderr, timedOut, truncated, argv, durationMs: Date.now() - started });
    };
    child.on("error", (err) => finish(null, null, err.message));
    child.on("close", (code, signal) => finish(code, signal));
    // If the process exited but a straggler keeps a pipe open, stop waiting.
    child.on("exit", (code, signal) => {
      setTimeout(() => {
        if (settled) return;
        killTree(child, "SIGKILL");
        child.stdout.destroy();
        child.stderr.destroy();
        finish(code, signal);
      }, 300).unref();
    });
  });
}

// ---- process-group bookkeeping

const active = new Set();
let handlersInstalled = false;

function killTree(child, sig) {
  try {
    if (process.platform !== "win32" && child.pid) process.kill(-child.pid, sig);
    else child.kill(sig);
  } catch { /* already gone */ }
}

function track(child) {
  active.add(child);
  if (handlersInstalled) return;
  handlersInstalled = true;
  process.on("exit", () => { for (const c of active) killTree(c, "SIGKILL"); });
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => {
      for (const c of active) killTree(c, "SIGKILL");
      process.exit(sig === "SIGINT" ? 130 : 143);
    });
  }
}

function untrack(child) {
  active.delete(child);
}

// Background worker: keeps analysis of large binaries off the UI thread.
import * as engine from "./engine.js";

self.onmessage = async ({ data }) => {
  const { id, op, args } = data;
  const progress = (message) => self.postMessage({ id, progress: message });
  try {
    let result;
    if (op === "open") result = await engine.openFile(args.file, args.name, progress);
    else if (op === "binary") result = await engine.analyzeBinary(args.path, args.arch, progress);
    else if (op === "frida") result = engine.fridaScript(args.mode, args.options);
    else if (op === "demangle") result = engine.demangle(args.symbols);
    else if (op === "ping") result = "pong";
    else throw new Error(`unknown operation ${op}`);
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: err?.message ?? String(err) });
  }
};

self.postMessage({ ready: true });

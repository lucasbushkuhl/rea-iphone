// Node entry point: analyze a path on disk. The environment-independent
// orchestrator is analyzeSource() in analyzeSource.js.

import { openSource } from "./target.js";
import { analyzeSource } from "./analyzeSource.js";

export { analyzeSource };

export function analyze(path, options = {}) {
  return analyzeSource(openSource(path), typeof path === "string" ? path : options.name ?? "target", options);
}

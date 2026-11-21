// Evidence records in REA's spirit: every reported fact carries what it is,
// how it was derived, and the limitation behind the conclusion. Nothing here
// executes the target; all facts are static.

import { createHash } from "node:crypto";

let counter = 0;

export function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export function evidence({ kind, path, facts, method, limitations = [] }) {
  counter += 1;
  return {
    evidence_id: `ios-ev-${counter.toString().padStart(4, "0")}`,
    kind,
    path: path ?? null,
    method, // how this was derived, e.g. "static Mach-O load-command parse"
    facts,
    limitations,
  };
}

export function resetEvidenceCounter() {
  counter = 0;
}

// Runtime-family hints from bundle paths. These are inventory-derived
// hypotheses (path conventions), never observed loading — matching REA's
// honesty about Apple framework hints.
const FAMILY_RULES = [
  { family: "Flutter", test: (p) => p.includes("/Flutter.framework/") },
  { family: "React Native", test: (p) => p.includes("/React.framework/") || /\/main\.jsbundle$/.test(p) },
  { family: "React Native (Hermes)", test: (p) => p.includes("/hermes.framework/") },
  { family: "Unity", test: (p) => p.includes("/UnityFramework.framework/") },
  { family: "Capacitor/Cordova", test: (p) => /\/www\/.+\.(js|html)$/.test(p) || p.includes("/Capacitor") },
  { family: ".NET / Xamarin / MAUI", test: (p) => /\.dll$/.test(p) || p.includes("libmonosgen") || p.includes("libxamarin") },
  { family: "KMP / Kotlin Native", test: (p) => p.includes("/shared.framework/") },
];

export function detectRuntimeFamilies(paths) {
  const found = new Map();
  for (const p of paths) {
    const norm = p.replace(/\\/g, "/");
    for (const rule of FAMILY_RULES) {
      if (rule.test(norm)) {
        if (!found.has(rule.family)) found.set(rule.family, []);
        found.get(rule.family).push(norm);
      }
    }
  }
  return [...found.entries()].map(([family, basis]) => ({
    family,
    basis: "path-convention",
    evidence_paths: basis.slice(0, 5),
    note: "Inventory-derived hint, not observed runtime loading.",
  }));
}

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

// Third-party SDK detection for privacy / supply-chain auditing. Each rule
// matches embedded framework names, Objective-C class names, or linked dylib
// paths. Matches are hints with their basis, not proof of runtime behavior.
const SDK_RULES = [
  { sdk: "Firebase", category: "analytics", frameworks: [/^Firebase\w*\.framework$/], classes: [/^FIR[A-Z]/] },
  { sdk: "Firebase Crashlytics", category: "crash-reporting", frameworks: [/^FirebaseCrashlytics\.framework$/], classes: [/^FIRCrashlytics/] },
  { sdk: "Google Mobile Ads", category: "advertising", frameworks: [/^GoogleMobileAds\.framework$/], classes: [/^GAD[A-Z]/] },
  { sdk: "Google Analytics", category: "analytics", frameworks: [/^GoogleAnalytics\.framework$/], classes: [/^GAI[A-Z]/] },
  { sdk: "Facebook SDK", category: "analytics", frameworks: [/^FBSDK\w*\.framework$/, /^FBAudienceNetwork\.framework$/], classes: [/^FBSDK/] },
  { sdk: "Adjust", category: "attribution", frameworks: [/^Adjust(Sdk)?\.framework$/], classes: [/^ADJ[A-Z]/] },
  { sdk: "AppsFlyer", category: "attribution", frameworks: [/^AppsFlyerLib\.framework$/], classes: [/^AppsFlyer/] },
  { sdk: "Branch", category: "attribution", frameworks: [/^Branch(SDK)?\.framework$/], classes: [/^BNC[A-Z]/] },
  { sdk: "Amplitude", category: "analytics", frameworks: [/^Amplitude\w*\.framework$/], classes: [/^Amplitude/] },
  { sdk: "Mixpanel", category: "analytics", frameworks: [/^Mixpanel\.framework$/], classes: [/^Mixpanel/] },
  { sdk: "Segment", category: "analytics", frameworks: [/^Segment\.framework$/], classes: [/^SEG[A-Z]/] },
  { sdk: "Braze", category: "engagement", frameworks: [/^(BrazeKit|Appboy\w*)\.framework$/], classes: [/^ABK[A-Z]/] },
  { sdk: "OneSignal", category: "push", frameworks: [/^OneSignal\w*\.framework$/], classes: [/^OneSignal/] },
  { sdk: "Sentry", category: "crash-reporting", frameworks: [/^Sentry\.framework$/], classes: [/^Sentry[A-Z]/] },
  { sdk: "Bugsnag", category: "crash-reporting", frameworks: [/^Bugsnag\.framework$/], classes: [/^Bugsnag/] },
  { sdk: "Datadog", category: "observability", frameworks: [/^Datadog\w*\.framework$/], classes: [/^DD[A-Z]\w*Datadog/] },
  { sdk: "Stripe", category: "payments", frameworks: [/^Stripe\w*\.framework$/], classes: [/^STP[A-Z]/] },
  { sdk: "RevenueCat", category: "payments", frameworks: [/^RevenueCat\.framework$/] },
  { sdk: "Alamofire", category: "networking", frameworks: [/^Alamofire\.framework$/] },
  { sdk: "AFNetworking", category: "networking", frameworks: [/^AFNetworking\.framework$/], classes: [/^AF(HTTP|URL)Session/] },
  { sdk: "Realm", category: "persistence", frameworks: [/^Realm(Swift)?\.framework$/], classes: [/^RLM[A-Z]/] },
  { sdk: "SDWebImage", category: "ui", frameworks: [/^SDWebImage\.framework$/], classes: [/^SDWebImage/] },
  { sdk: "Lottie", category: "ui", frameworks: [/^Lottie\.framework$/] },
  { sdk: "OpenSSL", category: "crypto", frameworks: [/^(OpenSSL|openssl)\.framework$/], dylibs: [/libssl/, /libcrypto/] },
];

export function detectThirdPartySdks({ frameworks = [], classNames = [], dylibs = [] }) {
  const out = [];
  for (const rule of SDK_RULES) {
    const basis = [];
    for (const f of frameworks) if (rule.frameworks?.some((r) => r.test(f))) basis.push(`framework:${f}`);
    const cls = classNames.filter((c) => c && rule.classes?.some((r) => r.test(c)));
    if (cls.length) basis.push(`objc-classes:${cls.slice(0, 3).join(",")}${cls.length > 3 ? `,+${cls.length - 3}` : ""}`);
    for (const d of dylibs) if (rule.dylibs?.some((r) => r.test(d))) basis.push(`dylib:${d}`);
    if (basis.length) out.push({ sdk: rule.sdk, category: rule.category, basis, note: "Static hint; presence does not prove the SDK is initialized or collecting data." });
  }
  return out;
}

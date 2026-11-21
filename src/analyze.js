// Orchestrator. Given an .ipa, an unpacked .app, or a bare Mach-O, produce an
// evidence-based iPhone application report. Execution-free throughout.
// With { deep: true } the main executable also gets the full static stack:
// Objective-C class-dump, Swift metadata, symbols and classified strings.

import { basename } from "node:path";
import { parsePlist } from "./plist.js";
import { openMachO, isMachO, selectImage } from "./macho.js";
import { parseProvisioningProfile, extractEntitlements } from "./provisioning.js";
import { sha256, evidence, detectRuntimeFamilies, detectThirdPartySdks, resetEvidenceCounter } from "./evidence.js";
import { openSource, findAppRoots, listBinaries, escapeRe } from "./target.js";
import { deepAnalyze, summarizeDeep } from "./deep.js";

export function analyze(path, options = {}) {
  resetEvidenceCounter();
  const src = openSource(path);
  const entries = src.list();
  const allPaths = entries.map((e) => e.path);
  const report = {
    tool: "rea-iphone",
    target: path,
    container: src.container,
    generated: new Date().toISOString(),
    execution_free: true,
    apps: [],
    binaries: listBinaries(src).map((b) => ({ role: b.role, path: b.path })),
    runtime_families: detectRuntimeFamilies(allPaths),
    third_party_sdks: [],
    evidence: [],
    limitations: [],
  };
  const push = (rec) => { report.evidence.push(rec); return rec; };

  if (src.container === "macho") {
    const buf = src.read(allPaths[0]);
    const exe = analyzeExecutable(buf, allPaths[0], push);
    const app = { root: null, bundle: {}, executable: exe.summary, entitlements: exe.entitlements, provisioning: null, embedded_frameworks: [] };
    if (options.deep) attachDeep(app, buf, options, report);
    report.apps.push(app);
    finalize(report, push, entries, []);
    return report;
  }

  const roots = findAppRoots(allPaths);
  if (roots.length === 0) report.limitations.push("No Payload/<Name>.app application root found; target may not be an iOS app bundle.");

  for (const root of roots) {
    const app = { root, bundle: {}, executable: null, entitlements: null, provisioning: null, embedded_frameworks: [], app_extensions: [] };

    // ---- Info.plist
    const infoPath = `${root}/Info.plist`;
    if (src.has(infoPath)) {
      try {
        const info = parsePlist(src.read(infoPath));
        app.bundle = {
          identifier: info.CFBundleIdentifier ?? null,
          name: info.CFBundleName ?? info.CFBundleDisplayName ?? null,
          displayName: info.CFBundleDisplayName ?? null,
          executable: info.CFBundleExecutable ?? null,
          shortVersion: info.CFBundleShortVersionString ?? null,
          version: info.CFBundleVersion ?? null,
          minimumOS: info.MinimumOSVersion ?? null,
          platforms: info.CFBundleSupportedPlatforms ?? null,
          requiredCapabilities: info.UIRequiredDeviceCapabilities ?? null,
          urlSchemes: extractUrlSchemes(info),
          queriedSchemes: Array.isArray(info.LSApplicationQueriesSchemes) ? info.LSApplicationQueriesSchemes : null,
          atsAllowsArbitraryLoads: info.NSAppTransportSecurity?.NSAllowsArbitraryLoads ?? null,
          atsExceptionDomains: info.NSAppTransportSecurity?.NSExceptionDomains ? Object.keys(info.NSAppTransportSecurity.NSExceptionDomains) : null,
          backgroundModes: Array.isArray(info.UIBackgroundModes) ? info.UIBackgroundModes : null,
          privacyUsageDescriptions: extractUsageDescriptions(info),
        };
        push(evidence({
          kind: "info_plist",
          path: infoPath,
          method: "static plist parse (binary/XML)",
          facts: app.bundle,
          limitations: ["Declared values; not cross-checked against the signed executable."],
        }));
      } catch (err) {
        report.limitations.push(`Info.plist parse failed for ${root}: ${err.message}`);
      }
    } else {
      report.limitations.push(`No Info.plist at ${infoPath}.`);
    }

    // ---- Main executable
    const exeName = app.bundle.executable ?? basename(root).replace(/\.app$/, "");
    const exePath = `${root}/${exeName}`;
    if (src.has(exePath)) {
      try {
        const buf = src.read(exePath);
        if (isMachO(buf)) {
          const exe = analyzeExecutable(buf, exePath, push);
          app.executable = exe.summary;
          app.entitlements = exe.entitlements;
          if (options.deep) attachDeep(app, buf, options, report);
        } else {
          report.limitations.push(`Executable ${exePath} is not Mach-O.`);
        }
      } catch (err) {
        report.limitations.push(`Executable parse failed for ${exePath}: ${err.message}`);
      }
    } else {
      report.limitations.push(`Declared executable not found at ${exePath}.`);
    }

    // ---- Provisioning profile
    const provPath = `${root}/embedded.mobileprovision`;
    if (src.has(provPath)) {
      try {
        const prov = parseProvisioningProfile(src.read(provPath));
        app.provisioning = prov;
        push(evidence({
          kind: "provisioning_profile",
          path: provPath,
          method: "embedded XML plist extraction from CMS container",
          facts: prov.parsed
            ? {
              name: prov.name, team: prov.teamName, team_identifier: prov.teamIdentifier,
              distribution: prov.distribution, get_task_allow: prov.getTaskAllow,
              expiration: prov.expirationDate, expired: prov.expired,
              provisioned_devices: prov.provisionedDeviceCount, aps_environment: prov.apsEnvironment,
            }
            : { parsed: false },
          limitations: ["CMS signature chain not validated; facts taken from the embedded plist."],
        }));
      } catch (err) {
        report.limitations.push(`Provisioning profile parse failed: ${err.message}`);
      }
    }

    // ---- Embedded frameworks and app extensions
    const fwRe = new RegExp(`^${escapeRe(root)}/Frameworks/([^/]+)`);
    const exRe = new RegExp(`^${escapeRe(root)}/PlugIns/([^/]+\\.appex)/`);
    const fw = new Set();
    const ex = new Set();
    for (const p of allPaths) {
      const m = p.match(fwRe);
      if (m) fw.add(m[1]);
      const e = p.match(exRe);
      if (e) ex.add(e[1]);
    }
    app.embedded_frameworks = [...fw].sort();
    app.app_extensions = [...ex].sort();
    report.apps.push(app);
  }

  finalize(report, push, entries, roots);
  return report;
}

function analyzeExecutable(buf, exePath, push) {
  const macho = openMachO(buf);
  const slices = macho.images.map((im) => summarizeImage(im.summary()));
  const summary = { path: exePath, sha256: sha256(buf), size: buf.length, kind: macho.kind, slices };
  const encrypted = macho.images.some((im) => im.encryption.encrypted);
  const first = macho.images[0];
  push(evidence({
    kind: "macho_executable",
    path: exePath,
    method: "static Mach-O header + load-command parse",
    facts: {
      kind: macho.kind,
      architectures: macho.images.map((im) => im.arch),
      fairplay_encrypted: encrypted,
      platform: first?.platform ?? null,
      minimum_os: first?.minOS ?? null,
      languages: [...new Set(slices.flatMap((s) => s.languages))],
      dylib_count: first?.dylibs.length ?? 0,
      fixup_format: slices[0]?.fixup_format ?? null,
    },
    limitations: [
      encrypted
        ? "LC_ENCRYPTION_INFO cryptid != 0: __TEXT is FairPlay-encrypted. Strings/decompilation require a decrypted copy obtained from a device you own."
        : "cryptid == 0 (or absent): not App Store FairPlay-encrypted (dev build or already decrypted).",
      "Language hints come from section names, not a full symbol/type decode.",
    ],
  }));

  let entitlements = null;
  const ent = extractEntitlements(buf);
  if (ent) {
    entitlements = ent;
    push(evidence({
      kind: "entitlements",
      path: exePath,
      method: "scan of code-signature blob for embedded entitlements plist",
      facts: summarizeEntitlements(ent),
      limitations: ["Extracted from the signature blob by pattern scan; signature validity not verified."],
    }));
  }
  return { summary, entitlements };
}

function attachDeep(app, buf, options, report) {
  const { images } = openMachO(buf);
  const image = selectImage(images, options.arch);
  if (!image) {
    report.limitations.push(`Requested architecture ${options.arch} not present.`);
    return;
  }
  const d = deepAnalyze(image, options);
  app.deep = { arch: image.arch, ...summarizeDeep(d) };
  app._deepFull = d; // full detail for callers (not serialized by default)
  report.limitations.push(...d.limitations.map((l) => `[deep ${image.arch}] ${l}`));
  report.evidence.push(evidence({
    kind: "deep_static_analysis",
    path: app.executable?.path ?? null,
    method: `Objective-C class-dump + Swift 5 metadata + symbols + strings via ${d.fixups.mode} fixups (${image.arch})`,
    facts: app.deep,
    limitations: d.limitations,
  }));
}

function finalize(report, push, entries, roots) {
  const frameworks = report.apps.flatMap((a) => a.embedded_frameworks);
  const classNames = report.apps.flatMap((a) => a._deepFull?.objc.classes.map((c) => c.name) ?? []);
  const dylibs = report.apps.flatMap((a) => a.executable?.slices[0]?.linked_dylibs ?? []);
  report.third_party_sdks = detectThirdPartySdks({ frameworks, classNames, dylibs });
  push(evidence({
    kind: "inventory",
    method: "container enumeration (zip central directory / directory walk)",
    facts: {
      total_files: entries.length,
      app_roots: roots,
      binaries: report.binaries.length,
      runtime_families: report.runtime_families.map((f) => f.family),
      third_party_sdks: report.third_party_sdks.map((s) => s.sdk),
    },
    limitations: ["Hashes computed for main executables only."],
  }));
  // Keep the serialized report bounded: full deep data stays non-enumerable.
  for (const app of report.apps) {
    if (app._deepFull) Object.defineProperty(app, "_deepFull", { enumerable: false, value: app._deepFull });
  }
}

function summarizeImage(im) {
  return {
    arch: im.arch,
    bits: im.bits,
    filetype: im.filetype,
    platform: im.platform,
    minimum_os: im.minOS,
    sdk: im.sdk,
    uuid: im.uuid,
    fairplay_encrypted: im.encryption.encrypted,
    crypt_id: im.encryption.cryptId,
    code_signature: im.codeSignature,
    fixup_format: im.fixupFormat,
    languages: im.languageHints,
    linked_dylibs: im.dylibs,
    rpaths: im.rpaths,
    install_name: im.installName ?? null,
  };
}

function summarizeEntitlements(ent) {
  return {
    application_identifier: ent["application-identifier"] ?? null,
    team_identifier: ent["com.apple.developer.team-identifier"] ?? null,
    get_task_allow: ent["get-task-allow"] ?? null,
    aps_environment: ent["aps-environment"] ?? null,
    app_groups: ent["com.apple.security.application-groups"] ?? null,
    keychain_access_groups: ent["keychain-access-groups"] ?? null,
    associated_domains: ent["com.apple.developer.associated-domains"] ?? null,
    all_keys: Object.keys(ent),
  };
}

function extractUrlSchemes(info) {
  const types = info.CFBundleURLTypes;
  if (!Array.isArray(types)) return null;
  const schemes = [];
  for (const t of types) if (Array.isArray(t.CFBundleURLSchemes)) schemes.push(...t.CFBundleURLSchemes);
  return schemes.length ? schemes : null;
}

function extractUsageDescriptions(info) {
  const out = {};
  for (const [k, v] of Object.entries(info)) if (/^NS\w+UsageDescription$/.test(k)) out[k] = v;
  return Object.keys(out).length ? out : null;
}

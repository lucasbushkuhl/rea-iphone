// Orchestrator. Given an .ipa file or an unpacked .app directory, produce an
// evidence-based iPhone application analysis report. Execution-free throughout.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename, relative, sep } from "node:path";
import { readZip } from "./zip.js";
import { parsePlist } from "./plist.js";
import { parseMachO, isMachO } from "./macho.js";
import { parseProvisioningProfile, extractEntitlements } from "./provisioning.js";
import { sha256, evidence, detectRuntimeFamilies, resetEvidenceCounter } from "./evidence.js";

// A uniform file source: list(), read(name) -> Buffer. Backed by an IPA zip or
// a directory tree, so the rest of the analyzer doesn't care which it got.
function ipaSource(buf) {
  const zip = readZip(buf);
  const files = zip.entries.filter((e) => !e.isDir);
  return {
    container: "ipa",
    list: () => files.map((e) => ({ path: e.name, size: e.uncompSize, encrypted: false })),
    read: (name) => zip.extract(files.find((e) => e.name === name)),
  };
}

function dirSource(root) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const full = join(d, name);
      const st = statSync(full);
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) out.push({ full, rel: relative(root, full).split(sep).join("/"), size: st.size });
    }
  };
  walk(root);
  const base = basename(root);
  // Normalize to IPA-like Payload/<App>.app/ paths for consistent reporting.
  const prefix = base.endsWith(".app") ? `Payload/${base}` : base;
  return {
    container: "app-directory",
    list: () => out.map((e) => ({ path: `${prefix}/${e.rel}`, size: e.size, encrypted: false })),
    read: (name) => {
      const rel = name.startsWith(`${prefix}/`) ? name.slice(prefix.length + 1) : name;
      return readFileSync(join(root, rel.split("/").join(sep)));
    },
  };
}

function openSource(path) {
  const st = statSync(path);
  if (st.isDirectory()) {
    if (!path.endsWith(".app")) throw new Error(`directory target must be a .app bundle: ${path}`);
    return dirSource(path);
  }
  const buf = readFileSync(path);
  if (buf.toString("ascii", 0, 2) === "PK") return ipaSource(buf);
  throw new Error(`unrecognized target (expected .ipa archive or .app directory): ${path}`);
}

// Find each Payload/<Name>.app root and its Info.plist executable.
function findAppRoots(entries) {
  const roots = new Set();
  for (const e of entries) {
    const m = e.path.match(/^(Payload\/[^/]+\.app)\//);
    if (m) roots.add(m[1]);
  }
  return [...roots];
}

export function analyze(path) {
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
    runtime_families: detectRuntimeFamilies(allPaths),
    evidence: [],
    limitations: [],
  };

  const push = (rec) => { report.evidence.push(rec); return rec; };

  const roots = findAppRoots(entries);
  if (roots.length === 0 && src.container === "app-directory") {
    // dirSource prefixes with Payload/<name>.app already; recompute.
    const inferred = allPaths[0]?.match(/^(Payload\/[^/]+\.app)\//);
    if (inferred) roots.push(inferred[1]);
  }
  if (roots.length === 0) {
    report.limitations.push("No Payload/<Name>.app application root found; target may not be an iOS app bundle.");
  }

  for (const root of roots) {
    const app = { root, bundle: {}, executable: null, entitlements: null, provisioning: null, embedded_frameworks: [] };

    // ---- Info.plist ----
    const infoPath = `${root}/Info.plist`;
    let info = null;
    if (allPaths.includes(infoPath)) {
      try {
        info = parsePlist(src.read(infoPath));
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
          atsAllowsArbitraryLoads: info.NSAppTransportSecurity?.NSAllowsArbitraryLoads ?? null,
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

    // ---- Main executable (Mach-O) ----
    const exeName = app.bundle.executable ?? basename(root).replace(/\.app$/, "");
    const exePath = `${root}/${exeName}`;
    if (allPaths.includes(exePath)) {
      try {
        const exeBuf = src.read(exePath);
        if (isMachO(exeBuf)) {
          const macho = parseMachO(exeBuf);
          app.executable = {
            path: exePath,
            sha256: sha256(exeBuf),
            size: exeBuf.length,
            kind: macho.kind,
            slices: macho.images.map(summarizeImage),
          };
          const encrypted = macho.images.some((im) => im.encryption.encrypted);
          push(evidence({
            kind: "macho_executable",
            path: exePath,
            method: "static Mach-O header + load-command parse",
            facts: {
              kind: macho.kind,
              architectures: macho.images.map((im) => im.arch),
              fairplay_encrypted: encrypted,
              platform: macho.images[0]?.platform ?? null,
              minimum_os: macho.images[0]?.minOS ?? null,
              languages: [...new Set(macho.images.flatMap((im) => im.languageHints))],
              dylib_count: macho.images[0]?.dylibs.length ?? 0,
            },
            limitations: [
              encrypted
                ? "LC_ENCRYPTION_INFO cryptid != 0: __TEXT is FairPlay-encrypted. Strings/decompilation require a decrypted copy obtained from a device you own."
                : "cryptid == 0: not App Store FairPlay-encrypted (dev build or already decrypted).",
              "Language hints come from section names, not a full symbol/type decode.",
            ],
          }));

          // Entitlements embedded in the code signature.
          const ent = extractEntitlements(exeBuf);
          if (ent) {
            app.entitlements = ent;
            push(evidence({
              kind: "entitlements",
              path: exePath,
              method: "scan of code-signature blob for embedded entitlements plist",
              facts: summarizeEntitlements(ent),
              limitations: ["Extracted from the signature blob by pattern scan; signature validity not verified."],
            }));
          }
        } else {
          report.limitations.push(`Executable ${exePath} is not Mach-O.`);
        }
      } catch (err) {
        report.limitations.push(`Executable parse failed for ${exePath}: ${err.message}`);
      }
    } else {
      report.limitations.push(`Declared executable not found at ${exePath}.`);
    }

    // ---- Embedded provisioning profile ----
    const provPath = `${root}/embedded.mobileprovision`;
    if (allPaths.includes(provPath)) {
      try {
        const prov = parseProvisioningProfile(src.read(provPath));
        app.provisioning = prov;
        push(evidence({
          kind: "provisioning_profile",
          path: provPath,
          method: "embedded XML plist extraction from CMS container",
          facts: prov.parsed
            ? {
              name: prov.name,
              team: prov.teamName,
              team_identifier: prov.teamIdentifier,
              distribution: prov.distribution,
              get_task_allow: prov.getTaskAllow,
              expiration: prov.expirationDate,
              expired: prov.expired,
              provisioned_devices: prov.provisionedDeviceCount,
              aps_environment: prov.apsEnvironment,
            }
            : { parsed: false },
          limitations: ["CMS signature chain not validated; facts taken from the embedded plist."],
        }));
      } catch (err) {
        report.limitations.push(`Provisioning profile parse failed: ${err.message}`);
      }
    }

    // ---- Embedded frameworks / dylibs inventory ----
    const fwRe = new RegExp(`^${escapeRe(root)}/Frameworks/([^/]+)`);
    const fwSet = new Set();
    for (const p of allPaths) {
      const m = p.match(fwRe);
      if (m) fwSet.add(m[1]);
    }
    app.embedded_frameworks = [...fwSet].sort();

    report.apps.push(app);
  }

  // Top-level inventory evidence (hashes for the key binaries only, to stay bounded).
  push(evidence({
    kind: "inventory",
    method: "container enumeration (zip central directory / directory walk)",
    facts: {
      total_files: entries.length,
      app_roots: roots,
      runtime_families: report.runtime_families.map((f) => f.family),
    },
    limitations: ["Hashes computed for main executables only; full per-file hashing available on request."],
  }));

  return report;
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
    languages: im.languageHints,
    linked_dylibs: im.dylibs,
    rpaths: im.rpaths,
    install_name: im.installName ?? null,
  };
}

function summarizeEntitlements(ent) {
  const keys = Object.keys(ent);
  return {
    application_identifier: ent["application-identifier"] ?? null,
    team_identifier: ent["com.apple.developer.team-identifier"] ?? null,
    get_task_allow: ent["get-task-allow"] ?? null,
    aps_environment: ent["aps-environment"] ?? null,
    app_groups: ent["com.apple.security.application-groups"] ?? null,
    keychain_access_groups: ent["keychain-access-groups"] ?? null,
    associated_domains: ent["com.apple.developer.associated-domains"] ?? null,
    all_keys: keys,
  };
}

function extractUrlSchemes(info) {
  const types = info.CFBundleURLTypes;
  if (!Array.isArray(types)) return null;
  const schemes = [];
  for (const t of types) {
    if (Array.isArray(t.CFBundleURLSchemes)) schemes.push(...t.CFBundleURLSchemes);
  }
  return schemes.length ? schemes : null;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

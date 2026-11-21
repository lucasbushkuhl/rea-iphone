// Render an analysis report as readable text (default CLI output).

export function renderText(r) {
  const L = [];
  L.push(`REA-iPhone — iOS application analysis`);
  L.push(`Target:    ${r.target}`);
  L.push(`Container: ${r.container}   Execution-free: ${r.execution_free}`);
  L.push(`Generated: ${r.generated}`);
  L.push("");

  for (const app of r.apps) {
    L.push(`App: ${app.root ?? "(bare Mach-O)"}`);
    const b = app.bundle || {};
    L.push(`  Bundle ID:     ${b.identifier ?? "(unknown)"}`);
    L.push(`  Name:          ${b.displayName ?? b.name ?? "(unknown)"}`);
    L.push(`  Version:       ${b.shortVersion ?? "?"} (build ${b.version ?? "?"})`);
    L.push(`  Minimum iOS:   ${b.minimumOS ?? "?"}`);
    if (b.urlSchemes) L.push(`  URL schemes:   ${b.urlSchemes.join(", ")}`);
    if (b.atsAllowsArbitraryLoads === true) L.push(`  ATS:           NSAllowsArbitraryLoads = true (cleartext HTTP permitted)`);

    if (app.executable) {
      const e = app.executable;
      L.push(`  Executable:    ${e.path}`);
      L.push(`    sha256: ${e.sha256}`);
      L.push(`    Mach-O: ${e.kind}, slices: ${e.slices.map((s) => s.arch).join(", ")}`);
      for (const s of e.slices) {
        L.push(`    • ${s.arch} ${s.filetype} — platform ${s.platform ?? "?"} min ${s.minimum_os ?? "?"} sdk ${s.sdk ?? "?"}`);
        const fp = s.crypt_id == null ? "n/a (no LC_ENCRYPTION_INFO)" : `${fmtBool(s.fairplay_encrypted)} (cryptid ${s.crypt_id})`;
        L.push(`        FairPlay encrypted: ${fp}   signed: ${fmtBool(s.code_signature)}${s.fixup_format ? `   fixups: ${s.fixup_format}` : ""}`);
        if (s.languages.length) L.push(`        Languages: ${s.languages.join(", ")}`);
        if (s.uuid) L.push(`        UUID: ${s.uuid}`);
        if (s.linked_dylibs.length) {
          L.push(`        Linked dylibs (${s.linked_dylibs.length}):`);
          for (const d of s.linked_dylibs.slice(0, 20)) L.push(`          - ${d}`);
          if (s.linked_dylibs.length > 20) L.push(`          … +${s.linked_dylibs.length - 20} more`);
        }
      }
    } else {
      L.push(`  Executable:    (not parsed)`);
    }

    if (app.entitlements) {
      const keys = Object.keys(app.entitlements);
      L.push(`  Entitlements:  ${keys.length} key(s)`);
      for (const k of keys.slice(0, 15)) L.push(`    - ${k}: ${fmtVal(app.entitlements[k])}`);
    }

    if (app.provisioning?.parsed) {
      const p = app.provisioning;
      L.push(`  Provisioning:  ${p.name ?? "?"}`);
      L.push(`    Team: ${p.teamName ?? "?"} ${p.teamIdentifier ? `(${p.teamIdentifier.join(",")})` : ""}`);
      L.push(`    Distribution: ${p.distribution}   get-task-allow: ${fmtBool(p.getTaskAllow)}`);
      L.push(`    Expires: ${p.expirationDate ?? "?"} ${p.expired === true ? "(EXPIRED)" : ""}`);
      if (p.provisionedDeviceCount != null) L.push(`    Provisioned devices: ${p.provisionedDeviceCount}`);
    }

    if (app.embedded_frameworks.length) {
      L.push(`  Embedded frameworks (${app.embedded_frameworks.length}):`);
      for (const f of app.embedded_frameworks.slice(0, 30)) L.push(`    - ${f}`);
    }
    if (app.app_extensions?.length) L.push(`  App extensions: ${app.app_extensions.join(", ")}`);
    if (b.privacyUsageDescriptions) {
      L.push(`  Privacy usage descriptions:`);
      for (const [k, v] of Object.entries(b.privacyUsageDescriptions)) L.push(`    - ${k}: ${v}`);
    }
    if (b.queriedSchemes) L.push(`  Queried URL schemes: ${b.queriedSchemes.join(", ")}`);
    if (b.atsExceptionDomains) L.push(`  ATS exception domains: ${b.atsExceptionDomains.join(", ")}`);

    if (app.deep) {
      const d = app.deep;
      L.push(`  Deep static analysis (${d.arch}, ${d.fixups.mode} fixups${d.fixups.formats.length ? `: ${d.fixups.formats.join(", ")}` : ""}):`);
      L.push(`    Objective-C: ${d.objc.classes} classes, ${d.objc.categories} categories, ${d.objc.protocols} protocols, ${d.objc.methods} methods`);
      if (d.objc.class_names.length) L.push(`      classes: ${d.objc.class_names.join(", ")}`);
      if (d.objc.external_classes.length) L.push(`      uses external classes: ${d.objc.external_classes.join(", ")}`);
      L.push(`    Swift: ${d.swift.types} types, ${d.swift.protocols} protocols, ${d.swift.conformances} conformances; symbols demangled ${d.swift.demangled_symbols}`);
      if (d.swift.type_names.length) L.push(`      types: ${d.swift.type_names.join(", ")}`);
      L.push(`    Symbols: ${d.symbols.total} (${d.symbols.stripped ? "stripped" : "not stripped"}), ${d.symbols.exports} exports`);
      for (const g of d.symbols.imports_by_library) L.push(`      imports from ${g.library}: ${g.count}`);
      const cats = Object.entries(d.strings.findings);
      if (cats.length) {
        L.push(`    String findings:`);
        for (const [cat, vals] of cats) L.push(`      ${cat}: ${vals.join(" | ")}`);
      }
    }
    L.push("");
  }

  if (r.binaries?.length > 1) {
    L.push(`Binaries (${r.binaries.length}):`);
    for (const bin of r.binaries) L.push(`  - [${bin.role}] ${bin.path}`);
    L.push("");
  }
  if (r.third_party_sdks?.length) {
    L.push(`Third-party SDKs (static hints):`);
    for (const s of r.third_party_sdks) L.push(`  - ${s.sdk} (${s.category})  [${s.basis.join("; ")}]`);
    L.push("");
  }

  if (r.runtime_families.length) {
    L.push(`Runtime families (path-convention hints):`);
    for (const f of r.runtime_families) L.push(`  - ${f.family}  [${f.evidence_paths[0]}]`);
    L.push("");
  }

  if (r.limitations.length) {
    L.push(`Limitations:`);
    for (const lim of r.limitations) L.push(`  ! ${lim}`);
    L.push("");
  }

  L.push(`${r.evidence.length} evidence record(s). Use --json for the full evidence-linked report.`);
  return L.join("\n");
}

function fmtBool(v) {
  if (v === true) return "yes";
  if (v === false) return "no";
  return "unknown";
}
function fmtVal(v) {
  if (Array.isArray(v)) return `[${v.join(", ")}]`;
  if (v && typeof v === "object") return JSON.stringify(v);
  return String(v);
}

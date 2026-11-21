// Render an analysis report as readable text (default CLI output).

export function renderText(r) {
  const L = [];
  L.push(`REA-iPhone — iOS application analysis`);
  L.push(`Target:    ${r.target}`);
  L.push(`Container: ${r.container}   Execution-free: ${r.execution_free}`);
  L.push(`Generated: ${r.generated}`);
  L.push("");

  for (const app of r.apps) {
    L.push(`App: ${app.root}`);
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
        L.push(`        FairPlay encrypted: ${fmtBool(s.fairplay_encrypted)} (cryptid ${s.crypt_id})   signed: ${fmtBool(s.code_signature)}`);
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

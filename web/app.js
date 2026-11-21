// REA iPhone web app: UI. Analysis runs in engine.js (in a worker when
// available). Nothing leaves the device.

const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const hex = (n) => (n == null ? "" : `0x${Number(n).toString(16)}`);
const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const standalone = (() => { try { return window.self === window.top; } catch { return false; } })();
const store = {
  get(k) { try { return localStorage.getItem(`rea:${k}`); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(`rea:${k}`, v); } catch { /* storage unavailable */ } },
};

const TABS = [
  ["overview", "Overview"],
  ["classes", "Classes"],
  ["swift", "Swift"],
  ["strings", "Strings"],
  ["symbols", "Symbols"],
  ["frida", "Frida"],
  ["demangle", "Demangle"],
];

const FINDING_LABELS = {
  credential_candidates: ["Possible embedded keys", "crit"],
  urls: ["Web addresses", "info"],
  custom_url_schemes: ["Custom URL schemes", "info"],
  emails: ["Email addresses", "info"],
  ip_addresses: ["IP addresses", "info"],
  integrity_checks: ["Jailbreak and tamper checks", "warn"],
  tls_pinning: ["Certificate pinning", "info"],
  high_entropy: ["High-entropy tokens", "warn"],
};

const S = { data: null, deep: null, tab: store.get("tab") ?? "overview", sample: false, name: "", binary: null };

// ---------------------------------------------------------------- engine

let worker = null;
let local = null;
let seq = 0;
const pending = new Map();

const workerReady = new Promise((resolve) => {
  let w;
  try {
    w = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  } catch {
    resolve(null);
    return;
  }
  const timer = setTimeout(() => { w.terminate(); resolve(null); }, 6000);
  w.onmessage = ({ data }) => {
    if (!data.ready) return;
    clearTimeout(timer);
    worker = w;
    w.onmessage = ({ data: m }) => {
      const p = pending.get(m.id);
      if (!p) return;
      if (m.progress) return p.progress?.(m.progress);
      pending.delete(m.id);
      m.ok ? p.resolve(m.result) : p.reject(new Error(m.error));
    };
    resolve(w);
  };
  w.onerror = (e) => {
    clearTimeout(timer);
    e.preventDefault?.();
    if (!worker) return resolve(null);
    // A crash mid-analysis (usually memory): fail pending work and fall back.
    for (const p of pending.values()) p.reject(new Error("The analysis stopped unexpectedly, most likely out of memory. Try a smaller binary, such as one framework from the app."));
    pending.clear();
    worker = null;
  };
});

async function call(op, args, progress) {
  const w = await workerReady;
  if (w && worker) {
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, progress });
      w.postMessage({ id, op, args });
    });
  }
  local ??= await import("./engine.js");
  if (op === "open") return local.openFile(args.file, args.name, progress);
  if (op === "binary") return local.analyzeBinary(args.path, args.arch, progress);
  if (op === "frida") return local.fridaScript(args.mode, args.options);
  if (op === "demangle") return local.demangle(args.symbols);
  throw new Error(`unknown operation ${op}`);
}

// ---------------------------------------------------------------- status

function busy(text) {
  const st = $("#status");
  if (text == null) { st.hidden = true; return; }
  $("#status-text").textContent = text;
  st.hidden = false;
}

function showError(msg) {
  const el = $("#error");
  el.textContent = msg ?? "";
  el.hidden = !msg;
}

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2200);
}

async function copy(text, sourceEl) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    if (sourceEl) {
      const r = document.createRange();
      r.selectNodeContents(sourceEl);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
      toast("Selected. Use Copy from the menu.");
    } else {
      toast("Copying isn't allowed here");
    }
  }
}

function save(name, text, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const actionButtons = (items) => `<div class="toolbar">${items.filter(Boolean).join("")}</div>`;
const copyBtn = (id, label = "Copy") => `<button class="btn small" type="button" data-copy="${id}">${esc(label)}</button>`;
const saveBtn = (id, label) => (standalone ? `<button class="btn small" type="button" data-save="${id}">${esc(label)}</button>` : "");

// Copy and save sources, registered per render.
const blobs = new Map();
function register(id, text, file) { blobs.set(id, { text, file }); return id; }

document.addEventListener("click", (e) => {
  const c = e.target.closest("[data-copy]");
  if (c) {
    const b = blobs.get(c.dataset.copy);
    if (b) copy(b.text, document.getElementById(`${c.dataset.copy}-src`));
    return;
  }
  const s = e.target.closest("[data-save]");
  if (s) {
    const b = blobs.get(s.dataset.save);
    if (b) save(b.file, b.text, b.file.endsWith(".json") ? "application/json" : "text/plain");
    return;
  }
  const v = e.target.closest("[data-copy-value]");
  if (v) copy(v.dataset.copyValue);
  const go = e.target.closest("[data-goto]");
  if (go) selectTab(go.dataset.goto);
});

// ---------------------------------------------------------------- highlighting

function hlObjC(src) {
  return esc(src).replace(/(\/\/[^\n]*)|(@(?:interface|end|property|protocol|optional|required|class|implementation))\b/g, (m, c, k) => {
    if (c) return `<span class="c">${c.replace(/(0x[0-9a-f]+)/g, '<span class="a">$1</span>')}</span>`;
    return `<span class="k">${k}</span>`;
  });
}

function hlSwift(src) {
  return esc(src).replace(/(\/\/[^\n]*)|\b(struct|class|enum|protocol|extension|case|let|var|indirect|associatedtype)\b/g, (m, c, k) => (c ? `<span class="c">${c}</span>` : `<span class="k">${k}</span>`));
}

// ---------------------------------------------------------------- lists

/** Render items into a container, `page` at a time, with a Show more button. */
function paged(container, items, render, page = 150) {
  let shown = 0;
  const list = document.createElement("div");
  list.className = "list";
  container.replaceChildren(list);
  const more = document.createElement("button");
  more.className = "btn small more";
  more.type = "button";
  const step = () => {
    const next = items.slice(shown, shown + page);
    list.insertAdjacentHTML("beforeend", next.map(render).join(""));
    shown += next.length;
    more.textContent = `Show ${Math.min(page, items.length - shown).toLocaleString()} more of ${(items.length - shown).toLocaleString()}`;
    more.hidden = shown >= items.length;
  };
  more.addEventListener("click", step);
  container.append(more);
  if (items.length === 0) list.insertAdjacentHTML("beforeend", '<p class="muted" style="padding:10px 2px;margin:0">Nothing here.</p>');
  step();
}

function filterInput(id, placeholder, onInput) {
  setTimeout(() => {
    const el = document.getElementById(id);
    if (!el) return;
    let t;
    el.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => onInput(el.value.trim()), 120); });
  });
  return `<input id="${id}" class="field" type="search" placeholder="${esc(placeholder)}" autocomplete="off" autocapitalize="off" spellcheck="false">`;
}

const matcher = (q) => {
  if (!q) return () => true;
  let re;
  try { re = new RegExp(q, "i"); } catch { re = null; }
  const lower = q.toLowerCase();
  return (...vals) => vals.some((v) => v != null && (re ? re.test(String(v)) : String(v).toLowerCase().includes(lower)));
};

// ---------------------------------------------------------------- tabs

function renderTabs() {
  const d = S.deep;
  const counts = {
    classes: d ? d.objc.classes.length + d.objc.categories.length + d.objc.protocols.length : 0,
    swift: d ? d.swift.types.length + d.swift.protocols.length : 0,
    strings: d ? Object.values(d.strings.findings).reduce((n, v) => n + v.length, 0) : 0,
    symbols: d ? d.symbols.importsByLibrary.reduce((n, g) => n + g.count, 0) : 0,
  };
  const nav = $("#tabs");
  nav.innerHTML = TABS.map(([id, label]) => `<button class="tab" role="tab" type="button" id="tab-${id}" aria-controls="panel-${id}" aria-selected="${S.tab === id}" data-tab="${id}">${label}${counts[id] ? `<span class="n">${counts[id].toLocaleString()}</span>` : ""}</button>`).join("");
  nav.hidden = false;
}

function selectTab(id) {
  S.tab = id;
  store.set("tab", id);
  for (const b of document.querySelectorAll(".tab")) b.setAttribute("aria-selected", String(b.dataset.tab === id));
  for (const p of document.querySelectorAll(".panel")) p.hidden = p.dataset.panel !== id;
  $(`#tab-${id}`)?.scrollIntoView({ block: "nearest", inline: "nearest" });
  window.scrollTo({ top: 0 });
}

$("#tabs").addEventListener("click", (e) => {
  const t = e.target.closest("[data-tab]");
  if (t) selectTab(t.dataset.tab);
});

// ---------------------------------------------------------------- file bar

function renderFileBar() {
  const fb = $("#filebar");
  const bins = S.data.binaries;
  const slices = S.deep.slices.filter((s) => s.is64);
  fb.innerHTML = `
    <span class="name">${esc(S.name)}</span>
    ${S.sample ? '<span class="tag">Sample</span>' : ""}
    ${bins.length > 1 ? `<label class="vh" for="binary">Binary</label><select id="binary" class="field">${bins.map((b) => `<option value="${esc(b.path)}" ${b.path === S.deep.path ? "selected" : ""}>${esc(roleLabel(b.role))}: ${esc(b.path.split("/").pop())}</option>`).join("")}</select>` : ""}
    ${slices.length > 1 ? `<label class="vh" for="arch">Architecture</label><select id="arch" class="field">${slices.map((s) => `<option ${s.arch === S.deep.arch ? "selected" : ""}>${esc(s.arch)}</option>`).join("")}</select>` : ""}`;
  fb.hidden = false;
  $("#binary")?.addEventListener("change", (e) => switchBinary(e.target.value, null));
  $("#arch")?.addEventListener("change", (e) => switchBinary(S.deep.path, e.target.value));
}

const roleLabel = (r) => ({ main: "App", framework: "Framework", extension: "Extension", dylib: "Library", file: "Binary" })[r] ?? r;

async function switchBinary(path, arch) {
  showError(null);
  busy("Loading binary");
  try {
    S.deep = await call("binary", { path, arch }, busy);
    renderAll();
  } catch (err) {
    showError(err.message);
  } finally {
    busy(null);
  }
}

// ---------------------------------------------------------------- overview

function attention(app, d) {
  const out = [];
  const b = app.bundle ?? {};
  if (d.image.encrypted) out.push(["warn", "Encrypted App Store binary", "Text, selectors and Swift details stored in __TEXT can't be read. Class structure is still shown. For full detail, use your own build or a decrypted copy from a device you own."]);
  const creds = d.strings.findings.credential_candidates ?? [];
  if (creds.length) out.push(["crit", plural(creds.length, "possible embedded key"), `${creds.slice(0, 3).map((f) => f.rule).join(", ")}. See Strings.`, "strings"]);
  if (b.atsAllowsArbitraryLoads === true) out.push(["warn", "Allows unencrypted HTTP", "NSAppTransportSecurity › NSAllowsArbitraryLoads is on."]);
  if (app.provisioning?.expired) out.push(["warn", "Provisioning profile has expired", `Expired ${app.provisioning.expirationDate}.`]);
  if (app.provisioning?.getTaskAllow || app.entitlements?.["get-task-allow"] === true) out.push(["info", "Debuggable build", "get-task-allow is set: a development build that debuggers and Frida can attach to."]);
  if ((d.strings.findings.integrity_checks ?? []).length) out.push(["info", "Contains jailbreak or tamper checks", "Strings that apps use to detect jailbreaks or instrumentation. See Strings.", "strings"]);
  if ((d.strings.findings.tls_pinning ?? []).length) out.push(["info", "Uses certificate pinning", "See Strings.", "strings"]);
  if (!out.length) out.push(["ok", "Nothing flagged", "No embedded keys, cleartext HTTP exceptions or encryption found."]);
  return out;
}

function kv(rows) {
  const r = rows.filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length));
  if (!r.length) return "";
  return `<dl class="kv">${r.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join("")}</dl>`;
}
const chips = (arr) => `<div class="chips">${arr.map((x) => `<span class="chip">${esc(x)}</span>`).join("")}</div>`;

function renderOverview(el) {
  const r = S.data.report;
  const app = r.apps[0] ?? { bundle: {} };
  const b = app.bundle ?? {};
  const d = S.deep;
  const objcCount = d.objc.classes.length;
  const swiftCount = d.swift.types.length;
  const libs = d.symbols.importsByLibrary.length;
  const findings = Object.values(d.strings.findings).reduce((n, v) => n + v.length, 0);
  const fix = d.fixups.mode === "chained" ? `chained (${d.fixups.formats.join(", ").replace(/DYLD_CHAINED_PTR_/g, "")})` : d.fixups.mode === "dyld-info" ? "classic bind/rebase" : "none";
  const reportId = register("report", S.data.text, `${(b.identifier ?? "report")}.txt`);
  const jsonId = register("json", JSON.stringify({ report: r, deep: d }, null, 2), `${(b.identifier ?? "report")}.json`);
  const title = b.displayName ?? b.name ?? d.path.split("/").pop();

  el.innerHTML = `
  <div class="ident">
    <div><h1 class="wrapall">${esc(title)}</h1>${b.identifier ? `<div class="bid">${esc(b.identifier)}</div>` : ""}</div>
    <dl class="spec">
      <div><dt>Version</dt><dd>${esc(b.shortVersion ?? "—")}${b.version ? ` (${esc(b.version)})` : ""}</dd></div>
      <div><dt>Minimum iOS</dt><dd>${esc(b.minimumOS ?? d.image.minOS ?? "—")}</dd></div>
      <div><dt>Architecture</dt><dd>${esc(d.slices.map((s) => s.arch).join(" + "))}</dd></div>
      <div><dt>Platform</dt><dd>${esc(d.image.platform ?? "—")}${d.image.sdk ? ` · SDK ${esc(d.image.sdk)}` : ""}</dd></div>
      <div><dt>FairPlay</dt><dd>${d.image.cryptId == null ? "n/a" : d.image.encrypted ? `encrypted (cryptid ${d.image.cryptId})` : "not encrypted"}</dd></div>
      <div><dt>Pointer fixups</dt><dd>${esc(fix)}</dd></div>
      <div><dt>Languages</dt><dd>${esc([swiftCount || d.symbols.swift.total ? "Swift" : null, objcCount ? "Objective-C" : null].filter(Boolean).join(", ") || "—")}</dd></div>
      <div><dt>Signed</dt><dd>${d.image.signed ? "yes" : "no"}</dd></div>
    </dl>
    ${actionButtons([copyBtn(reportId, "Copy report"), saveBtn(jsonId, "Save JSON")])}
  </div>

  <div class="stats">
    <button class="stat" type="button" data-goto="classes"><b>${objcCount.toLocaleString()}</b><span>Objective-C classes</span></button>
    <button class="stat" type="button" data-goto="swift"><b>${swiftCount.toLocaleString()}</b><span>Swift types</span></button>
    <button class="stat" type="button" data-goto="strings"><b>${findings.toLocaleString()}</b><span>String findings</span></button>
    <button class="stat" type="button" data-goto="symbols"><b>${libs.toLocaleString()}</b><span>Linked libraries</span></button>
  </div>

  <section class="section"><h2>Attention</h2><ul class="attn">${attention(app, d).map(([sev, t, desc, go]) => `<li><span class="sev ${sev}">${{ crit: "High", warn: "Check", info: "Note", ok: "OK" }[sev]}</span><div><strong>${esc(t)}</strong><div class="muted">${esc(desc)}${go ? ` <button class="btn small" type="button" data-goto="${go}">Open</button>` : ""}</div></div></li>`).join("")}</ul></section>

  ${r.apps.length && r.apps[0].root ? `<section class="section"><h2>App bundle</h2>${kv([
    ["URL schemes", b.urlSchemes ? chips(b.urlSchemes) : null],
    ["Queries other apps", b.queriedSchemes ? chips(b.queriedSchemes) : null],
    ["Privacy prompts", b.privacyUsageDescriptions ? Object.entries(b.privacyUsageDescriptions).map(([k, v]) => `<div><span class="mono">${esc(k)}</span><div class="muted">${esc(v)}</div></div>`).join("") : null],
    ["ATS exceptions", b.atsExceptionDomains ? chips(b.atsExceptionDomains) : null],
    ["Background modes", b.backgroundModes ? chips(b.backgroundModes) : null],
    ["Required capabilities", Array.isArray(b.requiredCapabilities) ? chips(b.requiredCapabilities) : null],
    ["Frameworks", app.embedded_frameworks?.length ? chips(app.embedded_frameworks) : null],
    ["App extensions", app.app_extensions?.length ? chips(app.app_extensions) : null],
    ["Third-party SDKs", r.third_party_sdks?.length ? r.third_party_sdks.map((s) => `<div><strong>${esc(s.sdk)}</strong> <span class="muted">${esc(s.category)}</span></div>`).join("") : null],
    ["Runtime", r.runtime_families?.length ? chips(r.runtime_families.map((f) => f.family)) : null],
  ])}</section>` : ""}

  ${app.entitlements ? `<section class="section"><h2>Entitlements</h2>${kv(Object.entries(app.entitlements).map(([k, v]) => [k, `<span class="mono">${esc(typeof v === "object" ? JSON.stringify(v) : String(v))}</span>`]))}</section>` : ""}

  ${app.provisioning?.parsed ? `<section class="section"><h2>Provisioning profile</h2>${kv([
    ["Name", esc(app.provisioning.name)],
    ["Team", `${esc(app.provisioning.teamName ?? "")} <span class="mono muted">${esc((app.provisioning.teamIdentifier ?? []).join(", "))}</span>`],
    ["Distribution", esc(app.provisioning.distribution)],
    ["Expires", `${esc(app.provisioning.expirationDate ?? "")}${app.provisioning.expired ? ' <span class="sev warn">Expired</span>' : ""}`],
    ["Devices", app.provisioning.provisionedDeviceCount != null ? esc(app.provisioning.provisionedDeviceCount) : null],
    ["Push", app.provisioning.apsEnvironment ? esc(app.provisioning.apsEnvironment) : null],
  ])}</section>` : ""}

  <section class="section"><h2>Binary · ${esc(d.path.split("/").pop())}</h2>
    ${kv([
      ["Path", `<span class="mono">${esc(d.path)}</span>`],
      ["UUID", d.image.uuid ? `<span class="mono">${esc(d.image.uuid)}</span>` : null],
      ["Type", `<span class="mono">${esc(d.image.filetype)}</span>`],
      ["Linked libraries", d.image.dylibs.length ? `<div class="chips">${d.image.dylibs.map((x) => `<span class="chip">${esc(x)}</span>`).join("")}</div>` : null],
    ])}
    <div class="tablewrap"><table><thead><tr><th>Segment</th><th>VM address</th><th>VM size</th><th>Sections</th></tr></thead><tbody>
      ${d.image.segments.map((s) => `<tr><td class="num">${esc(s.name)}</td><td class="num">${hex(s.vmaddr)}</td><td class="num">${hex(s.vmsize)}</td><td class="num">${s.sections}</td></tr>`).join("")}
    </tbody></table></div>
  </section>

  ${[...r.limitations, ...d.limitations].length ? `<section class="section"><h2>Limitations</h2><ul class="prose muted" style="padding-left:1.2em;margin:0">${[...new Set([...r.limitations, ...d.limitations])].slice(0, 40).map((l) => `<li>${esc(l)}</li>`).join("")}</ul></section>` : ""}`;
}

// ---------------------------------------------------------------- classes

function renderClasses(el) {
  const o = S.deep.objc;
  const all = [
    ...o.classes.map((c) => ({ kind: "class", name: c.swiftName ?? c.name, raw: c.name, sup: c.superclass, n: c.instanceMethods.length + c.classMethods.length, swift: c.isSwift, header: c.header, protocols: c.protocols })),
    ...o.categories.map((c) => ({ kind: "category", name: `${c.class ?? "?"} (${c.name})`, raw: c.name, sup: null, n: c.instanceMethods.length + c.classMethods.length, header: c.header, protocols: c.protocols })),
    ...o.protocols.map((p) => ({ kind: "protocol", name: p.name, raw: p.name, sup: null, n: p.instanceMethods.length + p.classMethods.length + p.optionalInstanceMethods.length + p.optionalClassMethods.length, header: p.header, protocols: p.protocols })),
  ];
  const hid = register("objc-h", o.header, `${S.deep.path.split("/").pop()}.h`);
  el.innerHTML = `
  <section class="section">
    <p class="prose muted">${plural(o.classes.length, "class", "classes")}, ${plural(o.categories.length, "category", "categories")}, ${plural(o.protocols.length, "protocol")}, recovered from Objective-C runtime metadata${o.methodListFormats.length ? ` (${esc(o.methodListFormats.join(" and "))} method lists)` : ""}. Tap one to see its interface.</p>
    <div class="toolbar"><div class="grow">${filterInput("q-classes", "Filter by name, superclass or protocol", (q) => draw(q))}</div>${copyBtn(hid, "Copy header")}${saveBtn(hid, "Save .h")}</div>
    ${o.externalClassRefs.length ? `<div class="muted" style="font-size:14px">Uses system classes: <span class="mono">${esc(o.externalClassRefs.slice(0, 30).map((c) => c.name).join(", "))}${o.externalClassRefs.length > 30 ? ` +${o.externalClassRefs.length - 30}` : ""}</span></div>` : ""}
    <div id="classes-list"></div>
  </section>`;
  const draw = (q) => {
    const m = matcher(q);
    const items = all.filter((x) => m(x.name, x.raw, x.sup, ...(x.protocols ?? [])));
    paged($("#classes-list"), items, (x) => `
      <details class="item"><summary><span class="title">${esc(x.name)}</span>${x.sup ? `<span class="meta">: ${esc(x.sup)}</span>` : ""}${x.kind !== "class" ? `<span class="tag">${x.kind}</span>` : ""}${x.swift ? '<span class="tag">Swift</span>' : ""}<span class="meta">${plural(x.n, "method")}</span></summary>
      <div class="body"><pre class="code">${hlObjC(x.header)}</pre></div></details>`);
  };
  draw("");
}

// ---------------------------------------------------------------- swift

function renderSwift(el) {
  const s = S.deep.swift;
  const sid = register("swift-i", s.interface, `${S.deep.path.split("/").pop()}.swift`);
  const items = [
    ...s.types.map((t) => ({ name: t.fullName, kind: t.kind, sup: t.superclass, t })),
    ...s.protocols.map((p) => ({ name: p.fullName, kind: "protocol", sup: null, p })),
  ];
  el.innerHTML = `
  <section class="section">
    <p class="prose muted">${plural(s.types.length, "type")}, ${plural(s.protocols.length, "protocol")} and ${plural(s.conformances.length, "conformance")} from Swift reflection metadata. ${S.deep.symbols.swift.total ? `${S.deep.symbols.swift.demangled.toLocaleString()} of ${S.deep.symbols.swift.total.toLocaleString()} Swift symbols demangled (see Symbols).` : ""}</p>
    <div class="toolbar"><div class="grow">${filterInput("q-swift", "Filter types", (q) => draw(q))}</div>${copyBtn(sid, "Copy interface")}${saveBtn(sid, "Save .swift")}</div>
    <div id="swift-list"></div>
  </section>
  ${s.conformances.length ? `<section class="section"><h2>Protocol conformances</h2><div class="list">${s.conformances.map((c) => `<div class="row"><div class="v">${esc(c.type ?? "?")} : ${esc(c.protocol ?? "?")}</div><div class="d">${c.typeReference.includes("objc") ? "Objective-C class" : c.protocolExternal ? "external protocol" : ""}</div></div>`).join("")}</div></section>` : ""}`;
  const draw = (q) => {
    const m = matcher(q);
    paged($("#swift-list"), items.filter((x) => m(x.name, x.sup)), (x) => {
      let body;
      if (x.p) body = `<p class="muted" style="margin:0">${plural(x.p.requirementCount, "requirement")}${x.p.associatedTypes.length ? ` · associated types: <span class="mono">${esc(x.p.associatedTypes.join(", "))}</span>` : ""}</p>`;
      else if (x.t.kind === "enum") body = `<div class="list">${x.t.cases.map((c) => `<div class="row"><div class="v">case ${esc(c.name)}${c.payload ? `(${esc(c.payload.replace(/^\((.*)\)$/, "$1"))})` : ""}</div><div class="d">${c.indirect ? "indirect" : ""}</div></div>`).join("") || '<p class="muted" style="margin:0">No cases recorded.</p>'}</div>`;
      else body = `<div class="list">${(x.t.fields ?? []).map((f) => `<div class="row"><div class="v">${f.isVar ? "var" : "let"} ${esc(f.name)}: ${esc(f.type ?? "?")}</div></div>`).join("") || '<p class="muted" style="margin:0">No stored properties recorded.</p>'}</div>`;
      const n = x.t ? (x.t.kind === "enum" ? plural(x.t.cases.length, "case") : plural((x.t.fields ?? []).length, "field")) : "";
      return `<details class="item"><summary><span class="title">${esc(x.name)}</span>${x.sup ? `<span class="meta">: ${esc(x.sup)}</span>` : ""}<span class="tag">${esc(x.kind)}</span>${x.t?.generic ? '<span class="tag">generic</span>' : ""}<span class="meta">${n}</span></summary><div class="body">${body}</div></details>`;
    });
  };
  draw("");
}

// ---------------------------------------------------------------- strings

function renderStrings(el) {
  const st = S.deep.strings;
  const cats = Object.keys(FINDING_LABELS).filter((k) => st.findings[k]?.length);
  const sources = Object.keys(st.counts);
  el.innerHTML = `
  <section class="section">
    <p class="prose muted">${st.total.toLocaleString()} strings from C literals, NSString literals, selectors and Swift metadata. Findings are matched by pattern; check each one before relying on it.</p>
    ${cats.length ? cats.map((k) => {
      const [label, sev] = FINDING_LABELS[k];
      return `<div class="section"><h2><span class="sev ${sev}" style="margin-right:8px">${st.findings[k].length}</span>${esc(label)}</h2><div class="list">${st.findings[k].map((f) => `<div class="row"><div><div class="v">${esc(f.value)}</div><div class="d">${esc(f.rule)} · ${esc(f.source)} <span class="addr">${esc(f.address)}</span></div></div><button class="btn small" type="button" data-copy-value="${esc(f.value)}">Copy</button></div>`).join("")}</div></div>`;
    }).join("") : '<p class="muted">No findings.</p>'}
  </section>
  <section class="section"><h2>All strings</h2>
    <div class="toolbar"><div class="grow">${filterInput("q-strings", "Search strings", (q) => draw(q))}</div>
      <label class="vh" for="src-filter">Source</label><select id="src-filter" class="field"><option value="">All sources</option>${sources.map((s) => `<option value="${esc(s)}">${esc(s)} (${st.counts[s].toLocaleString()})</option>`).join("")}</select></div>
    ${st.truncated ? `<p class="muted" style="margin:0">Showing the first ${st.strings.length.toLocaleString()} strings.</p>` : ""}
    <div id="strings-list"></div>
  </section>`;
  let q = "";
  const draw = (nq = q) => {
    q = nq;
    const m = matcher(q);
    const src = $("#src-filter").value;
    paged($("#strings-list"), st.strings.filter((s) => (!src || s.s === src) && m(s.v)), (s) => `<div class="row"><div class="v">${esc(s.v)}</div><div class="addr">${hex(s.a)}</div></div>`, 200);
  };
  $("#src-filter").addEventListener("change", () => draw());
  draw("");
}

// ---------------------------------------------------------------- symbols

function renderSymbols(el) {
  const sy = S.deep.symbols;
  const sym = (s) => `<div class="row"><div><div class="v">${esc(s.demangled ?? s.name)}</div>${s.demangled ? `<div class="d mono">${esc(s.name)}</div>` : ""}</div>${s.address != null ? `<div class="addr">${hex(s.address)}</div>` : "<div></div>"}</div>`;
  el.innerHTML = `
  <section class="section">
    <p class="prose muted">${sy.total.toLocaleString()} symbols${sy.stripped ? " (local symbols stripped)" : ""}. Fixups: ${esc(S.deep.fixups.mode)}${S.deep.fixups.formats.length ? ` · ${esc(S.deep.fixups.formats.join(", "))}` : ""}.</p>
    <h2>Imports by library</h2>
    <div class="list">${sy.importsByLibrary.map((g) => `<details class="item"><summary><span class="title">${esc(g.library)}</span><span class="meta">${plural(g.count, "symbol")}</span></summary><div class="body"><div class="list">${g.symbols.map(sym).join("")}</div></div></details>`).join("") || '<p class="muted">No imports.</p>'}</div>
  </section>
  <section class="section"><h2>Exports</h2>
    ${filterInput("q-exports", "Filter exports", (q) => drawEx(q))}
    <div id="exports-list"></div>
  </section>
  ${sy.swift.total ? `<section class="section"><h2>Swift symbols</h2>${filterInput("q-swiftsym", "Filter Swift symbols", (q) => drawSw(q))}<div id="swiftsym-list"></div></section>` : ""}`;
  const drawEx = (q) => { const m = matcher(q); paged($("#exports-list"), sy.exports.filter((e) => m(e.name, e.demangled)), sym); };
  const drawSw = (q) => { const m = matcher(q); paged($("#swiftsym-list"), sy.swift.symbols.filter((e) => m(e.name, e.demangled)), sym); };
  drawEx("");
  if (sy.swift.total) drawSw("");
}

// ---------------------------------------------------------------- frida

const FRIDA_MODES = [
  ["objc-trace", "Trace Objective-C methods", "Log calls, arguments and return values of methods matching your patterns."],
  ["network", "Watch network requests", "Log HTTP requests made through NSURLSession and WebKit, plus DNS lookups. Authorization headers are hidden unless you turn that off."],
  ["classes", "List runtime classes", "List the app's classes as they exist in memory. Works even when the file on disk is encrypted."],
  ["native-trace", "Trace C functions", "Log calls to exported functions matching patterns like exports:*!SecItem*."],
  ["modules", "List loaded libraries", "List every library loaded into the app."],
];

function renderFrida(el) {
  const bid = S.data.report.apps[0]?.bundle?.identifier ?? "com.example.app";
  const suggestions = S.deep.objc.classes.filter((c) => !c.isSwift).slice(0, 6).map((c) => `-[${c.name} *]`);
  el.innerHTML = `
  <section class="section">
    <p class="prose">Build a script that watches this app while it runs. You run it from a computer with <code>frida-tools</code>, against a device you control with <code>frida-server</code> installed. iPhones can't run Frida from Safari, so this page writes the script and the command for you.</p>
    <div class="section">
      <label for="f-mode"><h2>What to observe</h2></label>
      <select id="f-mode" class="field">${FRIDA_MODES.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select>
      <p id="f-desc" class="muted" style="margin:0"></p>
    </div>
    <div class="section" id="f-pat-wrap">
      <label for="f-patterns"><h2>Patterns, one per line</h2></label>
      <textarea id="f-patterns" class="field" spellcheck="false" autocapitalize="off">${esc(suggestions.slice(0, 2).join("\n") || "-[NSURLSession *]")}</textarea>
      ${suggestions.length ? `<div class="chips">${suggestions.map((s) => `<button class="btn small" type="button" data-pattern="${esc(s)}">${esc(s)}</button>`).join("")}</div>` : ""}
    </div>
    <div class="toolbar">
      <label class="check"><input id="f-bt" type="checkbox"> Include call stacks</label>
      <label class="check"><input id="f-redact" type="checkbox" checked> Hide credential headers</label>
      <label class="check">Seconds <input id="f-secs" class="field" type="number" min="1" max="600" value="30" style="width:6em"></label>
    </div>
    <div class="toolbar"><button id="f-gen" class="btn primary" type="button">Build script</button></div>
    <div id="f-out" class="section" hidden></div>
  </section>`;
  const mode = $("#f-mode");
  const sync = () => {
    const m = FRIDA_MODES.find(([v]) => v === mode.value);
    $("#f-desc").textContent = m[2];
    $("#f-pat-wrap").hidden = !(m[0] === "objc-trace" || m[0] === "native-trace");
    if (m[0] === "native-trace" && /^[-+]\[/.test($("#f-patterns").value)) $("#f-patterns").value = "exports:*!SecItem*";
    if (m[0] === "objc-trace" && /^exports:/.test($("#f-patterns").value)) $("#f-patterns").value = suggestions[0] ?? "-[NSURLSession *]";
  };
  mode.addEventListener("change", sync);
  sync();
  el.addEventListener("click", (e) => {
    const p = e.target.closest("[data-pattern]");
    if (!p) return;
    const ta = $("#f-patterns");
    ta.value = [...new Set([...ta.value.split("\n").map((x) => x.trim()).filter(Boolean), p.dataset.pattern])].join("\n");
  });
  $("#f-gen").addEventListener("click", async () => {
    const out = $("#f-out");
    const secs = Math.min(600, Math.max(1, Number($("#f-secs").value) || 30));
    try {
      const patterns = $("#f-patterns").value.split("\n").map((x) => x.trim()).filter(Boolean);
      const script = await call("frida", { mode: mode.value, options: { patterns, backtrace: $("#f-bt").checked, redact: $("#f-redact").checked } });
      const cmd = `frida -U -f ${bid} -l rea-agent.js -q -t ${secs}`;
      const sId = register("frida-js", script, "rea-agent.js");
      const cId = register("frida-cmd", cmd, "command.txt");
      out.innerHTML = `
        <h2>1 · Save the script as rea-agent.js</h2>
        ${actionButtons([copyBtn(sId, "Copy script"), saveBtn(sId, "Save rea-agent.js")])}
        <pre class="code" id="frida-js-src">${esc(script)}</pre>
        <h2>2 · Run it on your computer</h2>
        <pre class="code tall wrap" id="frida-cmd-src">${esc(cmd)}</pre>
        ${actionButtons([copyBtn(cId, "Copy command")])}
        <p class="muted" style="margin:0">Events print as lines starting with <span class="cmd">REA_EVT</span>, one JSON object each. Use <span class="cmd">-N ${esc(bid)}</span> instead of <span class="cmd">-f</span> to attach to the app while it's already running.</p>`;
      out.hidden = false;
      out.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      out.innerHTML = `<div class="error">${esc(err.message)}</div>`;
      out.hidden = false;
    }
  });
}

// ---------------------------------------------------------------- demangle

function renderDemangle(el) {
  const seed = S.deep.symbols.swift.symbols.slice(0, 4).map((s) => s.name);
  el.innerHTML = `
  <section class="section">
    <p class="prose muted">Paste Swift symbols, one per line or separated by spaces, to turn them into readable names.</p>
    <label class="vh" for="dm-in">Symbols</label>
    <textarea id="dm-in" class="field" spellcheck="false" autocapitalize="off">${esc((seed.length ? seed : ["$s9WalletKit7AccountV7balanceSdvg", "_$sSHMp"]).join("\n"))}</textarea>
    <div class="toolbar"><button id="dm-go" class="btn primary" type="button">Demangle</button></div>
    <div id="dm-out" class="list"></div>
  </section>`;
  const go = async () => {
    const syms = $("#dm-in").value.split(/\s+/).filter(Boolean).slice(0, 5000);
    const res = await call("demangle", { symbols: syms });
    $("#dm-out").innerHTML = res.map((r) => `<div class="row"><div><div class="v">${esc(r.demangled ?? "Not recognized as a supported Swift symbol")}</div><div class="d mono">${esc(r.symbol)}</div></div><div></div></div>`).join("");
  };
  $("#dm-go").addEventListener("click", go);
  go();
}

// ---------------------------------------------------------------- render

function renderAll() {
  renderFileBar();
  renderTabs();
  const panels = $("#panels");
  panels.innerHTML = TABS.map(([id]) => `<div class="panel" id="panel-${id}" role="tabpanel" aria-labelledby="tab-${id}" data-panel="${id}" hidden></div>`).join("");
  const renderers = { overview: renderOverview, classes: renderClasses, swift: renderSwift, strings: renderStrings, symbols: renderSymbols, frida: renderFrida, demangle: renderDemangle };
  for (const [id] of TABS) {
    try {
      renderers[id](document.getElementById(`panel-${id}`));
    } catch (err) {
      document.getElementById(`panel-${id}`).innerHTML = `<div class="error">This section couldn't be shown: ${esc(err.message)}</div>`;
    }
  }
  if (!TABS.some(([id]) => id === S.tab)) S.tab = "overview";
  selectTab(S.tab);
}

async function open(file, name, { sample = false } = {}) {
  showError(null);
  busy(`Opening ${name}`);
  try {
    const result = await call("open", { file, name }, busy);
    S.data = result;
    S.deep = result.deep;
    S.name = name;
    S.sample = sample;
    const notice = $("#notice");
    if (sample) {
      notice.innerHTML = `<span>This is a sample app built for testing this tool. Open your own <span class="mono">.ipa</span>, zipped <span class="mono">.app</span>, or binary to analyze it.</span><label class="btn small" for="file">Open app</label>`;
      notice.hidden = false;
    } else {
      notice.hidden = true;
    }
    renderAll();
  } catch (err) {
    showError(`${name}: ${err.message}`);
  } finally {
    busy(null);
  }
}

$("#file").addEventListener("change", (e) => {
  const f = e.target.files?.[0];
  if (f) open(f, f.name);
  e.target.value = "";
});

// Drag and drop (desktop).
let dragDepth = 0;
addEventListener("dragenter", (e) => { if (e.dataTransfer?.types?.includes("Files")) { dragDepth++; $("#drop").hidden = false; e.preventDefault(); } });
addEventListener("dragover", (e) => { if (e.dataTransfer?.types?.includes("Files")) e.preventDefault(); });
addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $("#drop").hidden = true; });
addEventListener("drop", (e) => {
  e.preventDefault();
  dragDepth = 0;
  $("#drop").hidden = true;
  const f = e.dataTransfer?.files?.[0];
  if (f) open(f, f.name);
});

// Offline support when hosted as a standalone site.
if (standalone && "serviceWorker" in navigator && document.querySelector('link[rel="manifest"]') && location.protocol !== "file:") {
  navigator.serviceWorker.register("sw.js").catch(() => { /* offline mode unavailable */ });
}

// Start with the sample so the first screen shows what the tool does.
(async () => {
  busy("Loading the sample app");
  try {
    const res = await fetch(new URL("sample/Demo.ipa.b64.txt", document.baseURI));
    if (!res.ok) throw new Error(`sample unavailable (${res.status})`);
    const b64 = (await res.text()).trim();
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    await open(new Blob([bytes]), "Demo.ipa", { sample: true });
  } catch (err) {
    busy(null);
    $("#notice").innerHTML = '<span>Open an <span class="mono">.ipa</span>, a zipped <span class="mono">.app</span>, or a Mach-O binary to analyze it.</span><label class="btn small" for="file">Open app</label>';
    $("#notice").hidden = false;
  }
})();

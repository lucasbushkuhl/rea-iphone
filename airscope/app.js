// Airscope UI. Passive: listens to Bluetooth advertisements, never connects.
import { bluetoothSupport, startScan, explainBluetoothError } from "../scanner/ble.js";
import { CATEGORIES, classifySsid } from "./signatures.js";
import { Session } from "./session.js";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const store = {
  get(k, d) { try { const v = localStorage.getItem(`airscope:${k}`); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`airscope:${k}`, JSON.stringify(v)); } catch { /* unavailable */ } },
};
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
const uid = () => Math.random().toString(36).slice(2, 10);

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}

// ---------------------------------------------------------------- state

let watch = store.get("watch", []);
let mute = store.get("mute", []);
let session = new Session({ watch, mute });
let scan = null;
let geo = null;
let geoWatch = null;
let catFilter = null;
let audio = null;

function saveRules() {
  store.set("watch", watch);
  store.set("mute", mute);
  session.setRules(watch, mute);
  renderRules();
}

// ---------------------------------------------------------------- views

function showView(name) {
  for (const v of document.querySelectorAll(".view")) v.hidden = v.dataset.name !== name;
  for (const b of document.querySelectorAll("nav.tabs button")) b.setAttribute("aria-selected", String(b.dataset.view === name));
  store.set("view", name);
  if (name === "log") renderLog();
  window.scrollTo({ top: 0 });
}
document.querySelector("nav.tabs").addEventListener("click", (e) => {
  const b = e.target.closest("[data-view]");
  if (b) showView(b.dataset.view);
});

// ---------------------------------------------------------------- scanning

function renderSupport() {
  const el = $("#support");
  const level = bluetoothSupport().level;
  if (scan) {
    el.innerHTML = `<button class="btn block" type="button" id="stop">Stop scan</button>`;
    $("#stop").onclick = stop;
  } else if (level === "scan") {
    el.innerHTML = `<button class="btn primary block" type="button" id="start">Start scan</button>`;
    $("#start").onclick = start;
  } else if (isIOS) {
    el.innerHTML = `<div class="note warn"><strong>Open Airscope in Bluefy to scan</strong><p>Safari on iPhone has no Bluetooth access. Install <strong>Bluefy – Web BLE Browser</strong> (free) from the App Store and open this page in it. Watchlist, log and exports work here too.</p><button class="btn block" type="button" id="copy-link">Copy link for Bluefy</button></div>`;
    $("#copy-link").onclick = async () => {
      try { await navigator.clipboard.writeText(location.href); toast("Link copied. Paste it into Bluefy."); } catch { toast(location.href); }
    };
  } else {
    el.innerHTML = `<div class="note warn"><strong>This browser can't scan Bluetooth</strong><p>Use Chrome or Edge on Android or a computer with <span class="mono">chrome://flags</span> › Experimental Web Platform features turned on, over https.</p></div>`;
  }
}

async function start() {
  try { audio ??= new (window.AudioContext || window.webkitAudioContext)(); audio.resume(); } catch { audio = null; }
  try {
    scan = await startScan(onAdvert);
  } catch (err) {
    toast(explainBluetoothError(err));
    return;
  }
  if ($("#geo-tag").checked) startGeo();
  renderSupport();
  tick();
}

function stop() {
  scan?.stop();
  scan = null;
  stopGeo();
  renderSupport();
  tick();
}

function onAdvert(ad) {
  const { alerts } = session.ingest(ad, Date.now(), geo);
  if (alerts.length) raise(alerts[alerts.length - 1]);
}

// ---------------------------------------------------------------- alerts

let lastAlertDevice = null;
function raise(a) {
  lastAlertDevice = a.deviceId;
  $("#alert-title").textContent = a.kind === "reappeared" ? "Back in range" : "Watchlist match";
  $("#alert-text").textContent = `${a.label}${a.name && a.name !== a.label ? ` (${a.name})` : ""} · rule: ${a.rule}`;
  $("#alertbar").hidden = false;
  if (a.sound && audio) {
    for (const [i, f] of [880, 1320].entries()) {
      const o = audio.createOscillator();
      const g = audio.createGain();
      const t0 = audio.currentTime + i * 0.16;
      o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(0.3, t0 + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.13);
      o.connect(g).connect(audio.destination);
      o.start(t0);
      o.stop(t0 + 0.14);
    }
  }
  navigator.vibrate?.([120, 60, 120]);
  renderAlertLog();
}
$("#alert-open").onclick = () => {
  if (lastAlertDevice) openDevice(lastAlertDevice);
  $("#alertbar").hidden = true;
};

// ---------------------------------------------------------------- location

function startGeo() {
  if (!navigator.geolocation || geoWatch != null) return;
  geoWatch = navigator.geolocation.watchPosition(
    (p) => { geo = { latitude: p.coords.latitude, longitude: p.coords.longitude }; },
    () => { toast("Location isn't available. Observations won't be location-tagged."); $("#geo-tag").checked = false; store.set("geo", false); stopGeo(); },
    { enableHighAccuracy: true, maximumAge: 10000 },
  );
}
function stopGeo() {
  if (geoWatch != null) navigator.geolocation.clearWatch(geoWatch);
  geoWatch = null;
  geo = null;
}
$("#geo-tag").checked = store.get("geo", false);
$("#geo-tag").addEventListener("change", (e) => {
  store.set("geo", e.target.checked);
  if (e.target.checked && scan) startGeo();
  if (!e.target.checked) stopGeo();
});

// ---------------------------------------------------------------- radar

const radar = $("#radar");
let sweep = 0;
const hashAngle = (id) => {
  let h = 2166136261;
  for (const ch of String(id)) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  return ((h >>> 0) / 4294967296) * Math.PI * 2;
};

function drawRadar() {
  const size = radar.clientWidth;
  if (size < 40) return; // hidden (another tab is open) or not laid out yet
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  if (radar.width !== size * dpr) { radar.width = size * dpr; radar.height = size * dpr; }
  const ctx = radar.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const c = size / 2;
  const R = c - 6;
  ctx.clearRect(0, 0, size, size);
  ctx.strokeStyle = "#16324a";
  ctx.lineWidth = 1;
  for (const f of [0.25, 0.5, 0.75, 1]) { ctx.beginPath(); ctx.arc(c, c, R * f, 0, Math.PI * 2); ctx.stroke(); }
  ctx.beginPath(); ctx.moveTo(c - R, c); ctx.lineTo(c + R, c); ctx.moveTo(c, c - R); ctx.lineTo(c, c + R); ctx.stroke();
  ctx.fillStyle = "#4f6378";
  ctx.font = "600 10px ui-monospace, SF Mono, Menlo, monospace";
  for (const [f, label] of [[0.25, "-50"], [0.5, "-65"], [0.75, "-80"], [1, "-95 dBm"]]) ctx.fillText(label, c + 4, c - R * f + 11);
  if (scan) {
    sweep = (sweep + 0.035) % (Math.PI * 2);
    const g = ctx.createConicGradient ? ctx.createConicGradient(sweep - 0.9, c, c) : null;
    if (g) {
      g.addColorStop(0, "rgba(57,199,232,0)");
      g.addColorStop(0.14, "rgba(57,199,232,0.22)");
      g.addColorStop(0.1401, "rgba(57,199,232,0)");
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(c, c, R, 0, Math.PI * 2); ctx.fill();
    }
  }
  const now = Date.now();
  for (const d of session.list(now, 30000)) {
    if (catFilter && d.category !== catFilter) continue;
    const rssi = d.rssi ?? -100;
    const r = Math.min(1, Math.max(0.06, (-rssi - 35) / 60)) * R;
    const a = hashAngle(d.id);
    const x = c + Math.cos(a) * r;
    const y = c + Math.sin(a) * r;
    const fade = Math.max(0.35, 1 - (now - d.lastSeen) / 30000);
    const color = CATEGORIES[d.category]?.color ?? "#8fa19b";
    ctx.globalAlpha = fade;
    ctx.fillStyle = color;
    ctx.beginPath(); ctx.arc(x, y, d.category === "unknown" ? 3 : 5, 0, Math.PI * 2); ctx.fill();
    if (d.watched.length) {
      ctx.strokeStyle = "#ff6b5a";
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(x, y, 9 + 3 * Math.sin(now / 200), 0, Math.PI * 2); ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}

// ---------------------------------------------------------------- list & counters

function renderCounters() {
  const counts = session.counts(Date.now(), 60000);
  const keys = Object.keys(CATEGORIES).filter((k) => counts[k]);
  $("#counters").innerHTML = keys.length ? keys.map((k) => `<button class="counter" type="button" data-cat="${k}" aria-pressed="${catFilter === k}"><b>${counts[k]}</b><span><i class="dot" style="background:${CATEGORIES[k].color}"></i>${esc(CATEGORIES[k].label)}</span></button>`).join("") : "";
}
$("#counters").addEventListener("click", (e) => {
  const b = e.target.closest("[data-cat]");
  if (!b) return;
  catFilter = catFilter === b.dataset.cat ? null : b.dataset.cat;
  tick();
});

function renderList() {
  const now = Date.now();
  const hide = $("#hide-common").checked;
  const list = session.list(now, 60000).filter((d) => (!catFilter || d.category === catFilter) && (!hide || (d.category !== "phone" && d.category !== "audio")));
  $("#list-title").textContent = catFilter ? `${CATEGORIES[catFilter].label} nearby` : "Nearby now";
  $("#devs").innerHTML = list.length ? list.slice(0, 200).map((d) => {
    const ago = Math.round((now - d.lastSeen) / 1000);
    return `<button class="dev ${d.watched.length ? "watched" : ""}" type="button" data-dev="${esc(d.id)}">
      <span class="bar" style="background:${CATEGORIES[d.category]?.color}"></span>
      <span><span class="t">${esc(d.label)}</span> ${d.watched.length ? '<span class="badge watch">Watched</span>' : ""}<span class="badge">${esc(d.confidence)}</span>
        <span class="s" style="display:block">${esc([CATEGORIES[d.category]?.label, d.name && d.name !== d.label ? d.name : null, d.vendor, d.proximity?.band].filter(Boolean).join(" · "))}</span></span>
      <span class="r">${d.rssi == null ? "—" : Math.round(d.rssi)}<span class="muted" style="display:block;font-size:11px">${ago < 3 ? "now" : `${ago}s ago`}</span></span></button>`;
  }).join("") : `<p class="muted">${scan ? "Listening. Devices appear as they broadcast." : "Start a scan to see Bluetooth activity around you."}</p>`;
}
$("#hide-common").checked = store.get("hideCommon", false);
$("#hide-common").addEventListener("change", (e) => { store.set("hideCommon", e.target.checked); tick(); });
$("#devs").addEventListener("click", (e) => {
  const b = e.target.closest("[data-dev]");
  if (b) openDevice(b.dataset.dev);
});

// ---------------------------------------------------------------- device sheet

function openDevice(id) {
  const d = session.devices.get(id);
  if (!d) return;
  const dt = (k, v) => (v == null || v === "" ? "" : `<dt>${esc(k)}</dt><dd>${v}</dd>`);
  const drone = d.drone ? `<h2>Remote ID</h2><dl class="kv">
    ${dt("Serial / ID", esc(d.drone.uasId))}${dt("ID type", esc(d.drone.idType))}${dt("Aircraft", esc(d.drone.uaType))}${dt("Status", esc(d.drone.status))}
    ${dt("Position", d.drone.latitude != null ? `${d.drone.latitude.toFixed(6)}, ${d.drone.longitude.toFixed(6)} <a href="https://www.openstreetmap.org/?mlat=${d.drone.latitude}&mlon=${d.drone.longitude}#map=17/${d.drone.latitude}/${d.drone.longitude}" target="_blank" rel="noopener">Map</a>` : null)}
    ${dt("Altitude", d.drone.altitudeGeo != null ? `${d.drone.altitudeGeo} m` : d.drone.altitudeBaro != null ? `${d.drone.altitudeBaro} m (pressure)` : null)}
    ${dt("Height", d.drone.height != null ? `${d.drone.height} m ${esc(d.drone.heightRef ?? "")}` : null)}
    ${dt("Speed", d.drone.speed != null ? `${d.drone.speed.toFixed(1)} m/s` : null)}${dt("Heading", d.drone.heading != null ? `${d.drone.heading}°` : null)}
    ${dt("Operator ID", esc(d.drone.operatorId))}${dt("Operator position", d.drone.operatorLatitude != null ? `${d.drone.operatorLatitude.toFixed(6)}, ${d.drone.operatorLongitude.toFixed(6)}` : null)}
    ${dt("Description", esc(d.drone.description))}</dl>` : "";
  $("#sheet-body").innerHTML = `
    <div class="row" style="justify-content:space-between;align-items:start"><div style="min-width:0"><div style="font-weight:700;font-size:18px;overflow-wrap:anywhere">${esc(d.label)}</div><div class="muted">${esc(CATEGORIES[d.category]?.label)} · ${esc(d.confidence)} match</div></div><button class="btn small" type="button" id="sheet-close">Done</button></div>
    <p>${esc(d.reason)}</p>
    <dl class="kv">
      ${dt("Name", esc(d.name))}${dt("Vendor", esc(d.vendor))}${dt("Signal", d.rssi == null ? null : `${Math.round(d.rssi)} dBm (strongest ${d.rssiMax}) · ${esc(d.proximity?.band)}`)}
      ${dt("First seen", new Date(d.firstSeen).toLocaleTimeString())}${dt("Last seen", new Date(d.lastSeen).toLocaleTimeString())}
      ${dt("Broadcasts", d.count)}${dt("Places", d.places.size ? d.places.size : null)}
      ${dt("Company IDs", d.companies.length ? esc(d.companies.map((c) => `0x${c.toString(16).padStart(4, "0")}`).join(", ")) : null)}
      ${dt("Services", d.services.length ? esc(d.services.join(", ")) : null)}${dt("Beacon URL", esc(d.eddystone?.url))}
      ${dt("Device ID", esc(d.id))}
    </dl>
    ${drone}
    <div class="row">
      <button class="btn primary" type="button" id="sheet-watch">${d.watched.length ? "Watched" : "Watch this device"}</button>
      <button class="btn" type="button" id="sheet-mute">${d.muted ? "Unmute" : "Mute"}</button>
    </div>
    <p class="muted" style="font-size:13px">Browsers give each device a private ID. Many phones also change their Bluetooth address every few minutes, so watching one specific phone often won't last; watching a name, drone serial or company ID does.</p>`;
  $("#sheet").hidden = false;
  $("#sheet-close").onclick = () => { $("#sheet").hidden = true; };
  $("#sheet-watch").onclick = () => {
    if (d.watched.length) return;
    watch.push({ id: uid(), kind: d.drone?.uasId ? "keyword" : "device", value: d.drone?.uasId ?? d.id, label: d.label, sound: true });
    saveRules();
    openDevice(id);
    toast("Added to watchlist");
  };
  $("#sheet-mute").onclick = () => {
    if (d.muted) mute = mute.filter((r) => !(r.kind === "device" && r.value === d.id));
    else mute.push({ id: uid(), kind: "device", value: d.id, label: d.label });
    saveRules();
    openDevice(id);
    tick();
  };
}
$("#sheet").addEventListener("click", (e) => { if (e.target.id === "sheet") $("#sheet").hidden = true; });

// ---------------------------------------------------------------- rules UI

$("#watch-category").innerHTML = Object.entries(CATEGORIES).map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join("");
$("#watch-kind").addEventListener("change", (e) => {
  const cat = e.target.value === "category";
  $("#watch-category").hidden = !cat;
  $("#watch-value").hidden = cat;
  $("#watch-value").placeholder = { keyword: "e.g. geotab, Tesla, /^1581F5/", company: "e.g. 004C", service: "e.g. FFFA", device: "Device ID from a detail sheet" }[e.target.value] ?? "";
});
$("#watch-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const kind = $("#watch-kind").value;
  const value = kind === "category" ? $("#watch-category").value : $("#watch-value").value.trim();
  if (!value) return toast("Enter something to watch for.");
  watch.push({ id: uid(), kind, value, label: kind === "category" ? CATEGORIES[value].label : value, sound: $("#watch-sound").checked });
  $("#watch-value").value = "";
  saveRules();
  toast("Added to watchlist");
});
$("#mute-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const value = $("#mute-value").value.trim();
  if (!value) return;
  mute.push({ id: uid(), kind: "keyword", value, label: value });
  $("#mute-value").value = "";
  saveRules();
});

function renderRules() {
  const kindLabel = { keyword: "Keyword", category: "Category", company: "Company", service: "Service", device: "Device" };
  $("#watch-rules").innerHTML = watch.length ? watch.map((r) => `<div class="rule"><div><span class="badge">${kindLabel[r.kind]}</span> <span class="v">${esc(r.label ?? r.value)}</span>${r.sound === false ? ' <span class="muted" style="font-size:12px">silent</span>' : ""}</div><button class="btn small" type="button" data-del-watch="${r.id}">Remove</button></div>`).join("") : '<p class="muted">No rules yet.</p>';
  $("#mute-rules").innerHTML = mute.length ? mute.map((r) => `<div class="rule"><div><span class="badge">${kindLabel[r.kind]}</span> <span class="v">${esc(r.label ?? r.value)}</span></div><button class="btn small" type="button" data-del-mute="${r.id}">Unmute</button></div>`).join("") : '<p class="muted">Nothing muted.</p>';
}
document.addEventListener("click", (e) => {
  const w = e.target.closest("[data-del-watch]");
  if (w) { watch = watch.filter((r) => r.id !== w.dataset.delWatch); saveRules(); }
  const m = e.target.closest("[data-del-mute]");
  if (m) { mute = mute.filter((r) => r.id !== m.dataset.delMute); saveRules(); tick(); }
});

function renderAlertLog() {
  const items = session.alerts.slice(-30).reverse();
  $("#alert-log").innerHTML = items.length ? items.map((a) => `<div class="rule"><div><div>${esc(a.label)}</div><div class="muted" style="font-size:12.5px">${new Date(a.t).toLocaleTimeString()} · ${a.kind === "reappeared" ? "back in range" : "appeared"} · ${esc(a.rule)}</div></div><button class="btn small" type="button" data-dev-open="${esc(a.deviceId)}">View</button></div>`).join("") : '<p class="muted">None yet.</p>';
}
$("#alert-log").addEventListener("click", (e) => {
  const b = e.target.closest("[data-dev-open]");
  if (b) openDevice(b.dataset.devOpen);
});

// ---------------------------------------------------------------- log & export

function renderLog() {
  const n = session.devices.size;
  const mins = Math.round((Date.now() - session.startedAt) / 60000);
  $("#session-stats").textContent = n ? `${n} device${n === 1 ? "" : "s"} observed over ${mins} min · ${session.alerts.length} alert${session.alerts.length === 1 ? "" : "s"}` : "No devices observed yet.";
}

async function deliver(filename, text, type) {
  const file = new File([text], filename, { type });
  try {
    if (navigator.canShare?.({ files: [file] })) {
      await navigator.share({ files: [file], title: filename });
      return;
    }
  } catch (err) {
    if (err?.name === "AbortError") return;
  }
  const url = URL.createObjectURL(file);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 3000);
}
const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
$("#export-csv").onclick = () => (session.devices.size ? deliver(`airscope-${stamp()}.csv`, session.toCSV(), "text/csv") : toast("Nothing to export yet."));
$("#export-json").onclick = () => (session.devices.size ? deliver(`airscope-${stamp()}.json`, JSON.stringify(session.toJSON(), null, 2), "application/json") : toast("Nothing to export yet."));
let clearArmed = false;
$("#clear-session").onclick = (e) => {
  if (!clearArmed) {
    clearArmed = true;
    e.currentTarget.textContent = "Tap again to clear";
    setTimeout(() => { clearArmed = false; e.currentTarget.textContent = "Clear session"; }, 3000);
    return;
  }
  clearArmed = false;
  e.currentTarget.textContent = "Clear session";
  session = new Session({ watch, mute });
  $("#debrief").hidden = true;
  $("#debrief-copy").hidden = true;
  renderLog();
  renderAlertLog();
  tick();
  toast("Session cleared");
};
$("#debrief-make").onclick = () => {
  $("#debrief").textContent = session.debrief();
  $("#debrief").hidden = false;
  $("#debrief-copy").hidden = false;
};
$("#debrief-copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("#debrief").textContent); toast("Copied. Paste it into your AI assistant."); } catch {
    const r = document.createRange();
    r.selectNodeContents($("#debrief"));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
    toast("Selected. Use Copy from the menu.");
  }
};

function renderSsids() {
  store.set("ssids", $("#ssids").value);
  const res = $("#ssids").value.split("\n").map(classifySsid).filter(Boolean);
  $("#ssid-out").innerHTML = res.map((r) => `<div class="rule"><div class="v">${esc(r.ssid)}</div>${r.category === "unknown" ? '<span class="muted" style="font-size:13px">No match</span>' : `<span class="badge" style="color:${CATEGORIES[r.category].color}">${esc(r.label)}</span>`}</div>`).join("");
}
$("#ssids").value = store.get("ssids", "");
$("#ssids").addEventListener("input", renderSsids);

// ---------------------------------------------------------------- loop

let lastList = 0;
function tick() {
  const st = $("#status");
  if (scan) {
    const s = Math.floor((Date.now() - session.startedAt) / 1000);
    st.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} · ${session.list(Date.now(), 60000).length}`;
    st.className = "status live";
  } else {
    st.textContent = "Idle";
    st.className = "status";
  }
  renderCounters();
  renderList();
  lastList = Date.now();
}
function frame() {
  // Schedule first: one failed frame must never stop live updates.
  requestAnimationFrame(frame);
  try {
    drawRadar();
  } catch { /* skip this frame's drawing */ }
  if (scan && Date.now() - lastList > 800) tick();
}

renderSupport();
renderRules();
renderAlertLog();
renderSsids();
tick();
showView(store.get("view", "live"));
requestAnimationFrame(frame);
if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});

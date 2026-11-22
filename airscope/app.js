// Airscope UI. Passive: listens to Bluetooth advertisements, never connects.
import { bluetoothSupport, startScan, pickAndWatch, explainBluetoothError } from "../scanner/ble.js";
import { CATEGORIES, classifySsid, setCustomSignatures, isRandomizedMac } from "./signatures.js";
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
let custom = store.get("custom", []);
let mute = store.get("mute", []);
let session = new Session({ watch, mute });
let scan = null;
let followers = []; // devices picked one at a time (browsers without a full scan)

// Inside the Android app, a native core scans Bluetooth and Wi-Fi and calls
// window.__airscopeEvents with batches of events.
const native = typeof window.AirscopeNative === "object" && window.AirscopeNative ? window.AirscopeNative : null;
let nativeState = { scanning: false };
const WINDOW = native ? 90000 : 60000; // Wi-Fi scans arrive every ~30 s
const hexToBytes = (h) => Uint8Array.from((String(h ?? "").match(/[0-9a-f]{2}/gi) ?? []).map((b) => parseInt(b, 16)));
const mapHex = (o) => Object.fromEntries(Object.entries(o ?? {}).map(([k, v]) => [k, hexToBytes(v)]));
window.__airscopeEvents = (events) => {
  for (const e of events) {
    try { handleNative(e); } catch { /* one bad event never stops the stream */ }
  }
};
function handleNative(e) {
  if (e.type === "ble") {
    onAdvert({ id: e.id, mac: e.mac, name: e.name, rssi: e.rssi, txPower: e.txPower, manufacturerData: mapHex(e.manufacturerData), serviceData: mapHex(e.serviceData), uuids: e.uuids ?? [] });
  } else if (e.type === "wifi") {
    let last = null;
    for (const n of e.networks ?? []) {
      const { alerts } = session.ingestWifi(n, Date.now(), geo);
      if (alerts.length) last = alerts[alerts.length - 1];
    }
    nativeState.wifiAt = Date.now();
    nativeState.wifiCount = (e.networks ?? []).length;
    renderSupport();
    if (last) raise(last);
  } else if (e.type === "location") {
    if ($("#geo-tag").checked) geo = { latitude: e.latitude, longitude: e.longitude };
  } else if (e.type === "state") {
    const was = nativeState.scanning;
    nativeState = { ...nativeState, ...e };
    if (e.message) toast(e.message);
    if (nativeState.scanning && !was) scan = { stop: () => native.stop() };
    if (!nativeState.scanning && was) scan = null;
    renderSupport();
    tick();
  }
}
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

function diagnostics() {
  const bt = navigator.bluetooth;
  const has = (f) => (bt && typeof bt[f] === "function" ? "yes" : "no");
  return `Bluetooth API: ${bt ? "yes" : "no"} · scan: ${has("requestLEScan")} · pick: ${has("requestDevice")}`;
}

let lastLevel = null;
function renderSupport() {
  const el = $("#support");
  if (native) {
    const warn = (nativeState.warnings ?? []).map((w) => `<p style="color:var(--warn)">${esc(w)}</p>`).join("");
    if (nativeState.scanning) {
      const wifi = nativeState.wifiAt ? `Wi-Fi: ${nativeState.wifiCount} networks, updated ${Math.max(0, Math.round((Date.now() - nativeState.wifiAt) / 1000))}s ago` : "Wi-Fi: waiting for the first scan";
      el.innerHTML = `<div class="row"><button class="btn block" type="button" id="stop">Stop scan</button></div><p class="muted mono" style="font-size:11.5px;margin-top:6px">Bluetooth: ${nativeState.bluetooth ? "scanning" : "off"} · ${esc(wifi)}</p>${warn}`;
      $("#stop").onclick = stop;
    } else {
      el.innerHTML = `<button class="btn primary block" type="button" id="start">Start scan</button>${warn}`;
      $("#start").onclick = start;
    }
    return;
  }
  const level = bluetoothSupport().level;
  lastLevel = level;
  if (scan) {
    el.innerHTML = `<button class="btn block" type="button" id="stop">Stop scan</button>`;
    $("#stop").onclick = stop;
  } else if (level === "scan") {
    el.innerHTML = `<button class="btn primary block" type="button" id="start">Start scan</button>`;
    $("#start").onclick = start;
  } else if (level === "pick") {
    const n = followers.length;
    const noLive = followers.filter((f) => !f.live).length;
    el.innerHTML = `<div class="note"><strong>${n ? `Following ${n} device${n === 1 ? "" : "s"}` : "Pick the devices to follow"}</strong><p>This browser can't scan everything at once. Tap <em>Add a device</em>, pick one from its list, and repeat for as many as you like. Airscope follows them all together.</p>${noLive ? `<p style="color:var(--warn)">This browser didn't send live signal strength for ${noLive === n ? "these devices" : `${noLive} of them`}, so their signal won't update.</p>` : ""}<div class="row"><button class="btn primary" type="button" id="pick" style="flex:1">${n ? "Add another device" : "Add a device"}</button>${n ? '<button class="btn" type="button" id="stop-all">Stop all</button>' : ""}</div><p class="muted mono" style="font-size:11px">${esc(diagnostics())}</p></div>`;
    $("#pick").onclick = pick;
    if (n) $("#stop-all").onclick = stop;
  } else if (isIOS) {
    el.innerHTML = `<div class="note warn"><strong>Waiting for Bluetooth</strong><p>If this page is open in <strong>Bluefy</strong>, wait a second or pull down to reload. Safari on iPhone has no Bluetooth access, so for scanning, open this page in Bluefy (free on the App Store). Watchlist, log and exports work anywhere.</p><div class="row"><button class="btn" type="button" id="recheck">Check again</button><button class="btn" type="button" id="copy-link">Copy link</button></div><p class="muted mono" style="font-size:11px">${esc(diagnostics())}</p></div>`;
    $("#recheck").onclick = () => { renderSupport(); if (lastLevel === "none") toast("Still no Bluetooth in this browser."); };
    $("#copy-link").onclick = async () => {
      try { await navigator.clipboard.writeText(location.href); toast("Link copied."); } catch { toast(location.href); }
    };
  } else {
    el.innerHTML = `<div class="note warn"><strong>This browser can't scan Bluetooth</strong><p>Use Chrome or Edge on Android or a computer with <span class="mono">chrome://flags</span> › Experimental Web Platform features turned on, over https.</p><p class="muted mono" style="font-size:11px">${esc(diagnostics())}</p></div>`;
  }
}

// Some browsers (Bluefy) add Bluetooth to the page shortly after it loads:
// keep checking for a while, and again when the app comes back to front.
function watchForBluetooth(ms = 15000) {
  const until = Date.now() + ms;
  const timer = setInterval(() => {
    if (bluetoothSupport().level !== lastLevel && !scan) renderSupport();
    if (lastLevel !== "none" || Date.now() > until) clearInterval(timer);
  }, 300);
}
document.addEventListener("visibilitychange", () => { if (!document.hidden && !scan) { renderSupport(); watchForBluetooth(5000); } });

async function pick() {
  try { audio ??= new (window.AudioContext || window.webkitAudioContext)(); audio.resume(); } catch { audio = null; }
  let f;
  try {
    f = await pickAndWatch(onAdvert);
  } catch (err) {
    toast(explainBluetoothError(err));
    return;
  }
  if (followers.some((x) => x.device.id === f.device.id)) {
    toast("Already following that device.");
  } else {
    followers.push(f);
    toast(`Following ${f.device.name || "device"}`);
  }
  if ($("#geo-tag").checked) startGeo();
  renderSupport();
  tick();
}

async function start() {
  try { audio ??= new (window.AudioContext || window.webkitAudioContext)(); audio.resume(); } catch { audio = null; }
  if (native) {
    native.start(); // permissions are requested natively; state arrives as events
    return;
  }
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
  if (native) {
    native.stop();
    return;
  }
  scan?.stop();
  scan = null;
  for (const f of followers) f.stop();
  followers = [];
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
  if (native) native.vibrate(300);
  else navigator.vibrate?.([120, 60, 120]);
  renderAlertLog();
}
$("#alert-open").onclick = () => {
  if (lastAlertDevice) openDevice(lastAlertDevice);
  $("#alertbar").hidden = true;
};

// ---------------------------------------------------------------- location

function startGeo() {
  if (native) return; // the app sends location events while scanning
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
  for (const d of session.list(now, followers.length ? null : WINDOW)) {
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
  const counts = session.counts(Date.now(), followers.length ? null : WINDOW);
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
  const list = session.list(now, followers.length ? null : WINDOW).filter((d) => (!catFilter || d.category === catFilter) && (!hide || !["phone", "audio", "network"].includes(d.category)));
  $("#list-title").textContent = catFilter ? `${CATEGORIES[catFilter].label} nearby` : "Nearby now";
  $("#devs").innerHTML = list.length ? list.slice(0, 200).map((d) => {
    const ago = Math.round((now - d.lastSeen) / 1000);
    return `<button class="dev ${d.watched.length ? "watched" : ""}" type="button" data-dev="${esc(d.id)}">
      <span class="bar" style="background:${CATEGORIES[d.category]?.color}"></span>
      <span><span class="t">${esc(d.label)}</span> ${d.watched.length ? '<span class="badge watch">Watched</span>' : ""}${d.radio === "wifi" ? `<span class="badge">Wi-Fi${d.band ? ` ${esc(d.band)}` : ""}</span>` : ""}<span class="badge">${esc(d.confidence)}</span>
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
      ${dt("Radio", d.radio === "wifi" ? `Wi-Fi${d.band ? ` · ${esc(d.band)}` : ""}${d.frequency ? ` · ${d.frequency} MHz` : ""}` : "Bluetooth")}
      ${dt("Address", d.mac ? `${esc(d.mac)}${isRandomizedMac(d.mac) ? ' <span class="muted">(randomized: doesn\'t identify the maker)</span>' : ""}` : null)}
      ${dt("Security", esc(d.security))}
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
  $("#watch-value").placeholder = { keyword: "e.g. geotab, Tesla, /^1581F5/", company: "e.g. 004C", service: "e.g. FFFA", device: "Device ID from a detail sheet", mac: "Address or prefix, e.g. 00:30:44" }[e.target.value] ?? "";
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

function renderCustom() {
  const el = $("#custom-rules");
  if (!el) return;
  el.innerHTML = custom.length ? custom.map((r) => `<div class="rule"><div><span class="badge">${r.kind === "mac" ? "Address" : "Name"}</span> <span class="v">${esc(r.value)}</span> → <span style="color:${CATEGORIES[r.category]?.color}">${esc(r.label || CATEGORIES[r.category]?.label)}</span></div><button class="btn small" type="button" data-del-custom="${r.id}">Remove</button></div>`).join("") : '<p class="muted">None yet.</p>';
}
function saveCustom() {
  store.set("custom", custom);
  setCustomSignatures(custom);
  renderCustom();
}
$("#custom-category").innerHTML = Object.entries(CATEGORIES).filter(([k]) => k !== "unknown").map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join("");
$("#custom-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const value = $("#custom-value").value.trim();
  if (!value) return toast("Enter an address prefix or a name.");
  custom.push({ id: uid(), kind: $("#custom-kind").value, value, category: $("#custom-category").value, label: $("#custom-label").value.trim() });
  $("#custom-value").value = "";
  $("#custom-label").value = "";
  saveCustom();
  toast("Signature added. It applies to devices seen from now on.");
});
document.addEventListener("click", (e) => {
  const c = e.target.closest("[data-del-custom]");
  if (c) { custom = custom.filter((r) => r.id !== c.dataset.delCustom); saveCustom(); }
});

function renderRules() {
  const kindLabel = { keyword: "Keyword", category: "Category", company: "Company", service: "Service", device: "Device", mac: "Address" };
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
  if (native) {
    native.saveFile(filename, type, text);
    return;
  }
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
  if (native) {
    native.copy($("#debrief").textContent);
    toast("Copied. Paste it into your AI assistant.");
    return;
  }
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
  if (scan || followers.length) {
    const s = Math.floor((Date.now() - session.startedAt) / 1000);
    st.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} · ${followers.length ? `${followers.length} followed` : session.list(Date.now(), WINDOW).length}`;
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
  if ((scan || followers.length) && Date.now() - lastList > 800) tick();
}

renderSupport();
if (!native) watchForBluetooth();
setCustomSignatures(custom);
renderCustom();
renderRules();
renderAlertLog();
renderSsids();
tick();
showView(store.get("view", "live"));
requestAnimationFrame(frame);
if (!native && "serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});

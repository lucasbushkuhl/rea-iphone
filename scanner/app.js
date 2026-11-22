// Signal Sweep UI. Everything runs on the device.
import { DeviceRegistry, bluetoothSupport, startScan, pickAndWatch, explainBluetoothError } from "./ble.js";
import { checkNetworkName } from "./trackers.js";
import { findSpots, SpotTracker } from "./lens.js";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const store = {
  get(k, d) { try { const v = localStorage.getItem(`sweep:${k}`); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(`sweep:${k}`, JSON.stringify(v)); } catch { /* unavailable */ } },
};
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);

let toastTimer;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}

// ---------------------------------------------------------------- views

const cameras = {};
function showView(name) {
  for (const v of document.querySelectorAll(".view")) v.hidden = v.dataset.name !== name;
  for (const b of document.querySelectorAll("nav.tabs button")) b.setAttribute("aria-selected", String(b.dataset.view === name));
  for (const [k, cam] of Object.entries(cameras)) if (k !== name) cam.stop();
  store.set("view", name);
  window.scrollTo({ top: 0 });
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-view]");
  if (b) showView(b.dataset.view);
});

// ---------------------------------------------------------------- bluetooth

const registry = new DeviceRegistry();
let session = null;
let startedAt = 0;
let renderTimer = null;
let finderId = null;

function renderSupport() {
  const el = $("#bt-support");
  const level = bluetoothSupport().level;
  if (session) {
    el.innerHTML = `<div class="row-actions"><button class="btn block" type="button" id="bt-stop">Stop scanning</button></div>`;
    $("#bt-stop").onclick = stopBluetooth;
    return;
  }
  if (level === "scan") {
    el.innerHTML = `<button class="btn primary block" type="button" id="bt-start">Start Bluetooth scan</button>`;
    $("#bt-start").onclick = startBluetooth;
  } else if (level === "pick") {
    el.innerHTML = `<div class="note info"><strong>This browser can follow one device at a time</strong><p>It will show its own list of nearby devices. Pick one to track its signal. For a full live scan, use Bluefy on iPhone or Chrome on Android.</p></div><button class="btn primary block" type="button" id="bt-pick">Choose a device</button>`;
    $("#bt-pick").onclick = pickOne;
  } else if (isIOS) {
    el.innerHTML = `<div class="note warn"><strong>Safari can't use Bluetooth</strong><p>Apple doesn't give Safari Bluetooth access. Install <strong>Bluefy – Web BLE Browser</strong> (free) from the App Store, open this page in it, and tap Start. The camera, Wi-Fi and checklist tools work here in Safari.</p></div><button class="btn block" type="button" id="bt-copy">Copy this page's link for Bluefy</button>`;
    $("#bt-copy").onclick = async () => {
      try { await navigator.clipboard.writeText(location.href); toast("Link copied. Paste it into Bluefy."); } catch { toast(location.href); }
    };
  } else {
    el.innerHTML = `<div class="note warn"><strong>Bluetooth isn't available in this browser</strong><p>Use Chrome or Edge on Android or a computer. For the live scan, open <span class="mono">chrome://flags</span>, enable <em>Experimental Web Platform features</em>, and restart the browser. The page must be opened over https.</p></div>`;
  }
}

async function startBluetooth() {
  try {
    registry.clear();
    session = await startScan((ad) => registry.ingest(ad));
    startedAt = Date.now();
    $("#live").hidden = false;
    $("#live").className = "pill live";
    $("#bt-stats").hidden = false;
    $("#bt-filter-wrap").hidden = false;
    renderSupport();
    renderTimer = setInterval(renderDevices, 700);
    renderDevices();
  } catch (err) {
    toast(explainBluetoothError(err));
  }
}

async function pickOne() {
  try {
    const s = await pickAndWatch((ad) => registry.ingest(ad));
    session = s;
    startedAt = Date.now();
    $("#live").hidden = false;
    $("#live").className = "pill live";
    renderSupport();
    renderTimer = setInterval(renderDevices, 700);
    openFinder(s.device.id);
  } catch (err) {
    toast(explainBluetoothError(err));
  }
}

function stopBluetooth() {
  session?.stop();
  session = null;
  clearInterval(renderTimer);
  $("#live").hidden = true;
  renderSupport();
  renderDevices();
}

function bars(rssi) {
  const n = rssi == null ? 0 : rssi >= -55 ? 4 : rssi >= -67 ? 3 : rssi >= -80 ? 2 : 1;
  return `<span class="bars" aria-hidden="true">${[6, 9, 12, 14].map((h, i) => `<i class="${i < n ? "on" : ""}" style="height:${h}px"></i>`).join("")}</span>`;
}

function renderDevices() {
  const now = Date.now();
  const list = registry.list(now);
  const trackers = list.filter((d) => d.category === "tracker" && d.concern !== "low").length;
  const cams = list.filter((d) => d.category === "camera").length;
  $("#st-trackers b").textContent = trackers;
  $("#st-trackers").classList.toggle("alert", trackers > 0);
  $("#st-cams b").textContent = cams;
  $("#st-all").textContent = list.length;
  if (session) $("#live").textContent = `${Math.floor((now - startedAt) / 60000)}:${String(Math.floor(((now - startedAt) / 1000) % 60)).padStart(2, "0")}`;
  const onlyRisky = $("#bt-filter").checked;
  const shown = onlyRisky ? list.filter((d) => d.category === "tracker" || d.category === "camera") : list;
  $("#devices").innerHTML = shown.length ? shown.map((d) => {
    const lingering = d.minutesAround >= 10 && (d.category === "tracker" || d.category === "unknown");
    const tag = d.concern === "high" ? '<span class="tag high">Check now</span>' : d.concern === "medium" ? '<span class="tag medium">Check</span>' : "";
    return `<div class="dev ${esc(d.concern)}"><span class="stripe"></span>
      <div><div class="t">${esc(d.label)} ${tag}</div>
        <div class="s">${esc([...new Set([d.name && !d.label.startsWith(d.name) ? d.name : null, d.vendor && !d.label.startsWith(d.vendor) ? d.vendor : null, d.proximity?.band, d.minutesAround ? `around ${d.minutesAround} min` : "just seen"].filter(Boolean))].join(" · "))}</div>
        ${lingering ? '<div class="s" style="color:var(--high)">Has stayed near you a while. If you\'ve moved around in that time, find it.</div>' : ""}</div>
      <div class="sig">${bars(d.rssi)}<span>${d.rssi == null ? "—" : `${Math.round(d.rssi)} dBm`}</span><button class="btn small" type="button" data-find="${esc(d.id)}">Find</button></div></div>`;
  }).join("") : `<p class="muted">${session ? "Listening… devices appear as they advertise. Trackers can take up to a minute to show." : "Start a scan to list nearby Bluetooth devices."}</p>`;
  if (finderId) updateFinder();
}
$("#bt-filter").addEventListener("change", renderDevices);
$("#devices").addEventListener("click", (e) => {
  const b = e.target.closest("[data-find]");
  if (b) openFinder(b.dataset.find);
});

// ---- hot/cold finder with an audio tone

let audio = null;
let toneOn = false;
let beepTimer = null;

function openFinder(id) {
  finderId = id;
  $("#finder").hidden = false;
  updateFinder();
}
function closeFinder() {
  finderId = null;
  $("#finder").hidden = true;
  setTone(false);
}
$("#f-close").onclick = closeFinder;
$("#f-tone").onclick = () => setTone(!toneOn);

function setTone(on) {
  toneOn = on;
  $("#f-tone").textContent = on ? "Sound off" : "Sound on";
  clearTimeout(beepTimer);
  if (!on) return;
  try { audio ??= new (window.AudioContext || window.webkitAudioContext)(); audio.resume(); } catch { toast("Sound isn't available here."); toneOn = false; return; }
  const beep = () => {
    if (!toneOn) return;
    const d = registry.devices.get(finderId);
    const rssi = d?.rssi ?? -100;
    const k = Math.min(1, Math.max(0, (rssi + 95) / 55)); // -95 dBm .. -40 dBm
    const osc = audio.createOscillator();
    const gain = audio.createGain();
    osc.frequency.value = 440 + k * 880;
    gain.gain.setValueAtTime(0.0001, audio.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.25, audio.currentTime + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, audio.currentTime + 0.09);
    osc.connect(gain).connect(audio.destination);
    osc.start();
    osc.stop(audio.currentTime + 0.1);
    beepTimer = setTimeout(beep, 1100 - k * 980);
  };
  beep();
}

function updateFinder() {
  const d = registry.devices.get(finderId);
  if (!d) return;
  $("#f-title").textContent = d.label;
  $("#f-sub").textContent = [d.name, d.vendor].filter(Boolean).join(" · ");
  const stale = Date.now() - d.lastSeen > 8000;
  const rssi = d.rssi;
  const k = rssi == null ? 0 : Math.min(1, Math.max(0, (rssi + 100) / 60));
  $("#f-arc").setAttribute("stroke-dasharray", `${(k * 540).toFixed(1)} 541`);
  $("#f-arc").setAttribute("stroke", d.concern === "high" ? "var(--high)" : "var(--accent)");
  $("#f-dbm").textContent = rssi == null ? "—" : Math.round(rssi);
  $("#f-band").textContent = stale ? "Signal lost" : d.proximity?.band ? d.proximity.band[0].toUpperCase() + d.proximity.band.slice(1) : "Waiting for signal";
  const t = $("#f-trend");
  t.className = `trend ${d.trend > 2 ? "up" : d.trend < -2 ? "down" : ""}`;
  t.textContent = stale ? "Move back toward where it was strongest" : d.trend > 2 ? "↑ Warmer" : d.trend < -2 ? "↓ Colder" : "Steady";
  $("#f-meta").textContent = `Strongest so far ${d.rssiMax == null ? "—" : `${d.rssiMax} dBm`} · ${d.reason}`;
}

// ---------------------------------------------------------------- cameras

function camera(rootSel, { facing = "environment", detect = {} } = {}) {
  const root = $(rootSel);
  const video = $("video", root);
  const canvas = $("canvas", root);
  const count = $(".count", root);
  const idle = $(".idle", root);
  const view = root.closest(".view");
  const work = document.createElement("canvas");
  const tracker = new SpotTracker({ minFrames: 4, radius: 22 });
  let stream = null;
  let raf = 0;
  let last = 0;
  let torch = false;
  const state = { facing, sensitivity: 3 };

  const loop = (ts) => {
    raf = requestAnimationFrame(loop);
    if (ts - last < 80 || video.readyState < 2) return; // ~12 frames per second
    last = ts;
    const vw = video.videoWidth;
    const vh = video.videoHeight;
    if (!vw) return;
    const W = 320;
    const H = Math.round((vh / vw) * W);
    work.width = W;
    work.height = H;
    const wctx = work.getContext("2d", { willReadFrequently: true });
    wctx.drawImage(video, 0, 0, W, H);
    const frame = wctx.getImageData(0, 0, W, H);
    const s = state.sensitivity;
    const spots = findSpots(frame, { minLevel: (detect.minLevel ?? 205) - (s - 3) * 12, sigma: (detect.sigma ?? 3.5) - (s - 3) * 0.4, minContrast: (detect.minContrast ?? 60) - (s - 3) * 10 });
    const tracks = tracker.update(spots).filter((t) => t.steady);
    // Overlay, mapped from the work frame to the displayed (object-fit: cover) video.
    const cw = canvas.clientWidth;
    const ch = canvas.clientHeight;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = cw * dpr;
    canvas.height = ch * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, cw, ch);
    const scale = Math.max(cw / W, ch / H);
    const ox = (cw - W * scale) / 2;
    const oy = (ch - H * scale) / 2;
    for (const t of tracks) {
      const x = ox + t.x * scale;
      const y = oy + t.y * scale;
      const r = Math.max(14, t.r * scale * 2.2);
      ctx.lineWidth = 3;
      ctx.strokeStyle = t.purple || t.blinks > 1 ? "#ff7ad9" : "#ff4f3d";
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.stroke();
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(x - r - 8, y); ctx.lineTo(x - r + 4, y); ctx.moveTo(x + r - 4, y); ctx.lineTo(x + r + 8, y); ctx.stroke();
    }
    count.hidden = false;
    count.textContent = tracks.length ? `${tracks.length} bright point${tracks.length > 1 ? "s" : ""} marked` : "Nothing marked";
  };

  async function start() {
    stop();
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: state.facing }, width: { ideal: 1280 }, height: { ideal: 960 } }, audio: false });
    } catch (err) {
      const msg = err?.name === "NotAllowedError" ? "Camera permission was denied. Allow camera access for this site in Settings, then try again."
        : err?.name === "NotFoundError" ? "No camera was found." : !window.isSecureContext ? "The camera needs this page to be opened over https." : `The camera couldn't start: ${err?.message ?? err}`;
      toast(msg);
      return;
    }
    video.srcObject = stream;
    await video.play().catch(() => {});
    idle.hidden = true;
    $("[data-stop]", view).hidden = false;
    const track = stream.getVideoTracks()[0];
    const caps = track.getCapabilities?.() ?? {};
    const tb = $("[data-torch]", view);
    if (tb) tb.hidden = !caps.torch;
    tracker.reset();
    raf = requestAnimationFrame(loop);
  }

  function stop() {
    cancelAnimationFrame(raf);
    if (stream) for (const t of stream.getTracks()) t.stop();
    stream = null;
    torch = false;
    video.srcObject = null;
    idle.hidden = false;
    count.hidden = true;
    canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
    const sb = $("[data-stop]", view);
    if (sb) sb.hidden = true;
  }

  async function toggleTorch() {
    const track = stream?.getVideoTracks()[0];
    if (!track) return;
    torch = !torch;
    try { await track.applyConstraints({ advanced: [{ torch }] }); } catch { toast("This phone doesn't allow the flashlight here."); }
  }

  $("[data-start]", root).onclick = start;
  $("[data-stop]", view).onclick = stop;
  $("[data-torch]", view)?.addEventListener("click", toggleTorch);
  $("[data-red]", view)?.addEventListener("click", (e) => {
    root.classList.toggle("redfilter");
    e.currentTarget.setAttribute("aria-pressed", String(root.classList.contains("redfilter")));
  });
  return { start, stop, state };
}

cameras.lens = camera("#lens-cam", { facing: "environment" });
cameras.ir = camera("#ir-cam", { facing: "user", detect: { minLevel: 185, sigma: 3, minContrast: 45 } });
$("#lens-sens").addEventListener("input", (e) => { cameras.lens.state.sensitivity = Number(e.target.value); });
for (const b of document.querySelectorAll("[data-facing]")) {
  b.addEventListener("click", () => {
    for (const x of document.querySelectorAll("[data-facing]")) x.setAttribute("aria-pressed", String(x === b));
    cameras.ir.state.facing = b.dataset.facing;
    if (!$("#ir-cam .idle").hidden) return;
    cameras.ir.start();
  });
}
document.addEventListener("visibilitychange", () => { if (document.hidden) for (const c of Object.values(cameras)) c.stop(); });

// ---------------------------------------------------------------- Wi-Fi names

function renderWifi() {
  const names = $("#wifi-in").value.split("\n").map((s) => s.trim()).filter(Boolean);
  store.set("wifi", $("#wifi-in").value);
  const res = names.map(checkNetworkName).filter(Boolean);
  $("#wifi-out").innerHTML = res.map((r) => `<div class="li"><div><div class="v">${esc(r.ssid)}</div>${r.suspicious ? `<div class="muted" style="font-size:13.5px">${esc(r.why)}</div>` : ""}</div>${r.suspicious ? `<span class="tag ${r.strength === "strong" ? "high" : "medium"}">${r.strength === "strong" ? "Looks like a camera" : "Possible"}</span>` : '<span class="muted" style="font-size:13px">No match</span>'}</div>`).join("");
}
$("#wifi-in").value = store.get("wifi", "");
$("#wifi-in").addEventListener("input", renderWifi);
renderWifi();

// ---------------------------------------------------------------- checklist

const CHECKLISTS = {
  room: ["Hotel or rental room", [
    ["Smoke and carbon-monoxide detectors", "Look for a small hole or glass dot facing the bed or shower."],
    ["Alarm clocks, radios and speakers", "Especially ones aimed at the bed."],
    ["USB chargers, power strips and adapters", "Spy chargers have a pinhole in the front face."],
    ["TV, set-top box and router", "Check the front bezels and status lights."],
    ["Picture frames, mirrors and wall art", "Fingertip test on mirrors: a gap between finger and reflection means normal glass."],
    ["Air vents, ceiling fixtures and sprinklers", "Use the lens finder with the room dark."],
    ["Shelves, books, plants and decor", "Anything with a clear view of the bed, shower or sofa."],
    ["Bathroom: shower head, towel hooks, outlets", "Cameras in bathrooms and bedrooms are illegal in most places."],
    ["Wi-Fi network names", "Check them on the Wi-Fi tab."],
    ["Bluetooth scan of the room", "Use the Bluetooth tab and look for anything you can't account for."],
  ]],
  car: ["Car", [
    ["OBD-II port under the dashboard", "Plug-in GPS trackers sit here and draw power from the car."],
    ["Under the front and rear bumpers", "Magnetic trackers stick to metal behind the bumper."],
    ["Wheel wells", "Feel along the top of each wheel arch."],
    ["Under the seats and in seat pockets", ""],
    ["Glove box, center console and trunk spare-tire well", ""],
    ["Phone holders, USB adapters and dash cams you didn't install", ""],
    ["Bluetooth scan while driving and after parking", "A tracker that stays with you across places is the strongest signal."],
  ]],
  bag: ["Bag, coat and belongings", [
    ["Every pocket, including zipped inner pockets", ""],
    ["Bag lining and seams", "Trackers get slipped under loose lining."],
    ["Coat pockets and hood", ""],
    ["Gifts or items you didn't buy", "Plush toys, key chains, wallets and phone cases have been used."],
    ["Bluetooth scan after you've moved locations", "If the same tracker is still nearby after a move, it's traveling with you."],
    ["iPhone tracker alerts", "Settings › Privacy & Security › Safety Check, and the Find My app's alerts."],
  ]],
};

let place = store.get("place", "room");
function renderChecklist() {
  const ticks = store.get(`ck:${place}`, {});
  const [, items] = CHECKLISTS[place];
  $("#ck-places").innerHTML = Object.entries(CHECKLISTS).map(([k, [label]]) => `<button type="button" data-place="${k}" aria-pressed="${k === place}">${esc({ room: "Room", car: "Car", bag: "Bag" }[k] ?? label)}</button>`).join("");
  $("#ck-list").innerHTML = items.map(([t, d], i) => `<label><input type="checkbox" data-i="${i}" ${ticks[i] ? "checked" : ""}><span>${esc(t)}${d ? `<small>${esc(d)}</small>` : ""}</span></label>`).join("");
  const done = items.filter((_, i) => ticks[i]).length;
  $("#ck-bar").style.width = `${(done / items.length) * 100}%`;
  $("#ck-count").textContent = `${CHECKLISTS[place][0]}: ${done} of ${items.length} checked`;
}
$("#ck-places").addEventListener("click", (e) => {
  const b = e.target.closest("[data-place]");
  if (!b) return;
  place = b.dataset.place;
  store.set("place", place);
  renderChecklist();
});
$("#ck-list").addEventListener("change", (e) => {
  const i = e.target.dataset.i;
  const ticks = store.get(`ck:${place}`, {});
  ticks[i] = e.target.checked;
  store.set(`ck:${place}`, ticks);
  renderChecklist();
});
$("#ck-reset").onclick = () => { store.set(`ck:${place}`, {}); renderChecklist(); };
renderChecklist();

// ---------------------------------------------------------------- start

renderSupport();
// Some browsers (Bluefy) add Bluetooth to the page shortly after it loads.
{
  let level = bluetoothSupport().level;
  const recheck = (ms) => {
    const until = Date.now() + ms;
    const timer = setInterval(() => {
      const now = bluetoothSupport().level;
      if (now !== level && !session) { level = now; renderSupport(); }
      if (level !== "none" || Date.now() > until) clearInterval(timer);
    }, 300);
  };
  recheck(15000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !session) recheck(5000); });
}
renderDevices();
showView(store.get("view", "bluetooth"));
if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(() => {});

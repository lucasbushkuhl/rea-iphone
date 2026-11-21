// Camera-based detection of hidden camera lenses and infrared LEDs.
//
// A camera lens hit by light returns a small, very bright, sharply bounded
// reflection ("glint") toward the light source. Infrared night-vision LEDs
// show up on cameras that can see near-IR as small bright spots, often
// purple-white. Both look like small bright blobs that are much brighter
// than their surroundings. This module finds such blobs in a frame and keeps
// only those that persist across frames. Pure: frames are { data, width,
// height } in RGBA like ImageData, so it runs in tests without a browser.

/**
 * Brightness (0..255) of an RGBA frame, downsampled by `step`: the brightest
 * channel (HSV value), so saturated purple or red IR spots count at full
 * strength alongside white glints.
 */
export function luminance(frame, step = 1) {
  const w = Math.floor(frame.width / step);
  const h = Math.floor(frame.height / step);
  const out = new Float32Array(w * h);
  const d = frame.data;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = ((y * step) * frame.width + x * step) * 4;
      const r = d[i], g = d[i + 1], b = d[i + 2];
      out[y * w + x] = r > g ? (r > b ? r : b) : (g > b ? g : b);
    }
  }
  return { lum: out, w, h };
}

/**
 * Find small bright spots.
 * options: { minLevel = 200, sigma = 3.5, maxAreaFrac = 0.004, minContrast = 60 }
 * Returns blobs { x, y, r, area, peak, contrast, purple } in frame pixels.
 */
export function findSpots(frame, options = {}) {
  const step = options.step ?? 1;
  const { lum, w, h } = luminance(frame, step);
  const n = w * h;
  let sum = 0;
  let sq = 0;
  for (let i = 0; i < n; i++) { sum += lum[i]; sq += lum[i] * lum[i]; }
  const mean = sum / n;
  const std = Math.sqrt(Math.max(0, sq / n - mean * mean));
  const threshold = Math.max(options.minLevel ?? 200, mean + (options.sigma ?? 3.5) * std);
  const maxArea = Math.max(4, Math.floor(n * (options.maxAreaFrac ?? 0.004)));
  const minContrast = options.minContrast ?? 60;

  const label = new Int32Array(n).fill(-1);
  const blobs = [];
  const stack = [];
  for (let start = 0; start < n; start++) {
    if (label[start] !== -1 || lum[start] < threshold) continue;
    // Flood fill (4-connected).
    let area = 0, sx = 0, sy = 0, peak = 0, minX = w, maxX = 0, minY = h, maxY = 0, r = 0, g = 0, b = 0;
    const id = blobs.length;
    label[start] = id;
    stack.push(start);
    while (stack.length) {
      const p = stack.pop();
      const x = p % w;
      const y = (p - x) / w;
      area++; sx += x; sy += y;
      if (lum[p] > peak) peak = lum[p];
      if (x < minX) minX = x; if (x > maxX) maxX = x; if (y < minY) minY = y; if (y > maxY) maxY = y;
      const i = ((y * step) * frame.width + x * step) * 4;
      r += frame.data[i]; g += frame.data[i + 1]; b += frame.data[i + 2];
      if (area > maxArea * 4) continue; // stop growing huge regions
      for (const q of [p - 1, p + 1, p - w, p + w]) {
        if (q < 0 || q >= n) continue;
        if ((q === p - 1 && x === 0) || (q === p + 1 && x === w - 1)) continue;
        if (label[q] === -1 && lum[q] >= threshold) { label[q] = id; stack.push(q); }
      }
    }
    blobs.push({ area, cx: sx / area, cy: sy / area, peak, minX, maxX, minY, maxY, r: r / area, g: g / area, b: b / area });
  }

  const out = [];
  for (const bl of blobs) {
    if (bl.area > maxArea) continue; // windows, lamps, screens
    const bw = bl.maxX - bl.minX + 1;
    const bh = bl.maxY - bl.minY + 1;
    if (Math.max(bw, bh) / Math.min(bw, bh) > 3) continue; // lines and edges, not points
    // Contrast against a ring around the blob.
    const rad = Math.max(bw, bh) / 2 + 3;
    let ringSum = 0, ringN = 0;
    for (let k = 0; k < 16; k++) {
      const ang = (k / 16) * Math.PI * 2;
      const x = Math.round(bl.cx + Math.cos(ang) * rad);
      const y = Math.round(bl.cy + Math.sin(ang) * rad);
      if (x < 0 || y < 0 || x >= w || y >= h) continue;
      ringSum += lum[y * w + x];
      ringN++;
    }
    const ring = ringN ? ringSum / ringN : mean;
    const contrast = bl.peak - ring;
    if (contrast < minContrast) continue;
    out.push({
      x: (bl.cx + 0.5) * step,
      y: (bl.cy + 0.5) * step,
      r: Math.max(2, (Math.max(bw, bh) / 2) * step),
      area: bl.area * step * step,
      peak: Math.round(bl.peak),
      contrast: Math.round(contrast),
      // Near-IR on phone sensors often reads as purple / magenta-white.
      purple: bl.b > bl.g + 15 && bl.r > bl.g + 10,
    });
  }
  return out.sort((a, b) => b.contrast - a.contrast).slice(0, options.max ?? 12);
}

/**
 * Keep spots that persist. Each call takes the spots of one frame; returns
 * tracked spots with `frames` (consecutive frames seen) and `steady` (seen
 * long enough to show). Matching is nearest-neighbor within `radius` px.
 */
export class SpotTracker {
  constructor({ radius = 24, minFrames = 4, maxMissed = 3 } = {}) {
    Object.assign(this, { radius, minFrames, maxMissed });
    this.tracks = [];
    this.nextId = 1;
  }

  update(spots) {
    const used = new Set();
    for (const t of this.tracks) {
      let best = null;
      let bestD = this.radius;
      spots.forEach((s, i) => {
        if (used.has(i)) return;
        const d = Math.hypot(s.x - t.x, s.y - t.y);
        if (d < bestD) { bestD = d; best = i; }
      });
      if (best == null) {
        t.missed++;
      } else {
        used.add(best);
        const s = spots[best];
        Object.assign(t, { x: t.x * 0.5 + s.x * 0.5, y: t.y * 0.5 + s.y * 0.5, r: s.r, contrast: s.contrast, purple: s.purple, missed: 0 });
        t.frames++;
        // Blinking (IR LEDs, recording lights): count gaps that ended.
        if (t.wasMissed) t.blinks++;
        t.wasMissed = false;
      }
      if (t.missed > 0) t.wasMissed = true;
    }
    spots.forEach((s, i) => {
      if (!used.has(i)) this.tracks.push({ id: this.nextId++, ...s, frames: 1, missed: 0, blinks: 0, wasMissed: false });
    });
    this.tracks = this.tracks.filter((t) => t.missed <= this.maxMissed);
    return this.tracks.map((t) => ({ ...t, steady: t.frames >= this.minFrames }));
  }

  reset() {
    this.tracks = [];
  }
}

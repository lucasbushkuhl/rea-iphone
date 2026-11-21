#!/usr/bin/env node
// Generate the app icons as PNGs (zero dependencies): a magnifier over three
// lines of code on a cobalt field. 4x4 supersampling for clean edges.
import { writeFileSync, mkdirSync } from "node:fs";
import { deflateSync, crc32 } from "node:zlib";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "web", "icons");
mkdirSync(OUT, { recursive: true });

const BG_TOP = [0x2f, 0x5b, 0xe0];
const BG_BOT = [0x1b, 0x37, 0xa6];
const WHITE = [0xff, 0xff, 0xff];
const LINE = [0xb9, 0xcb, 0xff];

function png(w, h, rgb) {
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 3 + 1)] = 0;
    rgb.copy(raw, y * (w * 3 + 1) + 1, y * w * 3, (y + 1) * w * 3);
  }
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}

// Shapes in unit coordinates (0..1), scaled by `k` around the center.
function shade(u, v, k) {
  const x = (u - 0.5) / k + 0.5;
  const y = (v - 0.5) / k + 0.5;
  const cx = 0.44, cy = 0.42, r = 0.235, ring = 0.062;
  const d = Math.hypot(x - cx, y - cy);
  if (Math.abs(d - r) <= ring / 2) return WHITE; // lens ring
  // Handle: a thick segment from the ring toward the lower right.
  const ax = cx + (r + ring / 2) * Math.SQRT1_2, ay = cy + (r + ring / 2) * Math.SQRT1_2;
  const bx = 0.80, by = 0.78;
  const t = Math.max(0, Math.min(1, ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)));
  if (Math.hypot(x - (ax + t * (bx - ax)), y - (ay + t * (by - ay))) <= 0.052) return WHITE;
  // Three code lines inside the lens.
  const lines = [[0.335, 0.37, 0.135], [0.335, 0.42, 0.205], [0.335, 0.47, 0.100]];
  for (const [lx, ly, len] of lines) {
    if (d < r - ring / 2 && x >= lx && x <= lx + len && Math.abs(y - ly) <= 0.014) return LINE;
  }
  return null;
}

function render(size, k) {
  const rgb = Buffer.alloc(size * size * 3);
  const S = 4;
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const u = (px + (sx + 0.5) / S) / size;
          const v = (py + (sy + 0.5) / S) / size;
          const c = shade(u, v, k) ?? BG_TOP.map((t, i) => t + (BG_BOT[i] - t) * v);
          r += c[0]; g += c[1]; b += c[2];
        }
      }
      const o = (py * size + px) * 3;
      rgb[o] = Math.round(r / (S * S));
      rgb[o + 1] = Math.round(g / (S * S));
      rgb[o + 2] = Math.round(b / (S * S));
    }
  }
  return png(size, size, rgb);
}

for (const [name, size, k] of [["icon-180.png", 180, 1], ["icon-192.png", 192, 1], ["icon-512.png", 512, 1], ["icon-maskable-512.png", 512, 0.78]]) {
  writeFileSync(join(OUT, name), render(size, k));
}
console.log(`icons written to ${OUT}`);

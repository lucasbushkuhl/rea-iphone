// The subset of Node's Buffer API that rea-iphone's analysis core uses,
// implemented on Uint8Array for browsers. Out-of-range reads throw RangeError
// exactly like Node, which the core's malformed-input handling relies on.
// Importing this module installs it as globalThis.Buffer when none exists.

const utf8 = new TextDecoder("utf-8");
const enc = new TextEncoder();

function latin1(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return s;
}

export class BrowserBuffer extends Uint8Array {
  static from(value, encoding) {
    if (typeof value === "string") {
      if (encoding === "latin1" || encoding === "binary" || encoding === "ascii") {
        const b = new BrowserBuffer(value.length);
        for (let i = 0; i < value.length; i++) b[i] = value.charCodeAt(i) & 0xff;
        return b;
      }
      if (encoding === "hex") {
        const b = new BrowserBuffer(value.length >> 1);
        for (let i = 0; i < b.length; i++) b[i] = parseInt(value.substr(i * 2, 2), 16);
        return b;
      }
      const u = enc.encode(value);
      return new BrowserBuffer(u.buffer, u.byteOffset, u.byteLength);
    }
    if (value instanceof ArrayBuffer) return new BrowserBuffer(value, encoding ?? 0, arguments[2]);
    if (ArrayBuffer.isView(value)) {
      const copy = new BrowserBuffer(value.byteLength);
      copy.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
      return copy;
    }
    if (Array.isArray(value)) return new BrowserBuffer(value);
    throw new TypeError("unsupported Buffer.from input");
  }

  static alloc(n, fill = 0) {
    const b = new BrowserBuffer(n);
    if (fill) b.fill(fill);
    return b;
  }

  static concat(list, total) {
    const len = total ?? list.reduce((n, b) => n + b.length, 0);
    const out = new BrowserBuffer(len);
    let o = 0;
    for (const b of list) { out.set(b.subarray(0, Math.min(b.length, len - o)), o); o += b.length; if (o >= len) break; }
    return out;
  }

  static isBuffer(x) { return x instanceof BrowserBuffer; }

  /** Wrap existing bytes without copying. */
  static wrap(u8) { return new BrowserBuffer(u8.buffer, u8.byteOffset, u8.byteLength); }

  get dv() {
    // Cached per view; subarray() returns a new BrowserBuffer with its own view.
    return this._dv ?? (this._dv = new DataView(this.buffer, this.byteOffset, this.byteLength));
  }

  readUInt8(o) { return this.dv.getUint8(o); }
  readUInt16LE(o) { return this.dv.getUint16(o, true); }
  readUInt16BE(o) { return this.dv.getUint16(o, false); }
  readUInt32LE(o) { return this.dv.getUint32(o, true); }
  readUInt32BE(o) { return this.dv.getUint32(o, false); }
  readInt32LE(o) { return this.dv.getInt32(o, true); }
  readInt32BE(o) { return this.dv.getInt32(o, false); }
  readBigUInt64LE(o) { return this.dv.getBigUint64(o, true); }
  readBigUInt64BE(o) { return this.dv.getBigUint64(o, false); }
  readFloatBE(o) { return this.dv.getFloat32(o, false); }
  readDoubleBE(o) { return this.dv.getFloat64(o, false); }
  writeUInt32LE(v, o) { this.dv.setUint32(o, v >>> 0, true); return o + 4; }
  writeUInt16LE(v, o) { this.dv.setUint16(o, v, true); return o + 2; }

  toString(encoding = "utf8", start = 0, end = this.length) {
    const s = Math.max(0, start);
    const e = Math.min(this.length, end);
    if (e <= s) return "";
    const view = Uint8Array.prototype.subarray.call(this, s, e);
    switch (encoding) {
      case "latin1": case "binary": return latin1(view);
      case "ascii": return latin1(view.map((b) => b & 0x7f));
      case "utf16le": case "ucs2": {
        // Code units verbatim (lone surrogates kept), exactly like Node.
        const units = new Uint16Array(view.length >> 1);
        for (let i = 0; i < units.length; i++) units[i] = view[i * 2] | (view[i * 2 + 1] << 8);
        let out = "";
        for (let i = 0; i < units.length; i += 0x8000) out += String.fromCharCode.apply(null, units.subarray(i, i + 0x8000));
        return out;
      }
      case "hex": return Array.from(view, (b) => b.toString(16).padStart(2, "0")).join("");
      default: return utf8.decode(view);
    }
  }
}

if (typeof globalThis.Buffer === "undefined") globalThis.Buffer = BrowserBuffer;

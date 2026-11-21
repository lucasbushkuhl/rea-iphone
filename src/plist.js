// Property-list parser. Handles both Apple binary plists (bplist00), which is
// what a compiled Info.plist usually is, and the XML form used by entitlements
// and provisioning profiles. Pure, static, no execution.

export function parsePlist(buf) {
  if (buf.length >= 8 && buf.toString("ascii", 0, 6) === "bplist") {
    return parseBinaryPlist(buf);
  }
  const text = buf.toString("utf8").replace(/^﻿/, "");
  return parseXmlPlist(text);
}

// ---------- Binary plist (bplist00) ----------

function parseBinaryPlist(buf) {
  const trailerOff = buf.length - 32;
  const offsetSize = buf[trailerOff + 6];
  const refSize = buf[trailerOff + 7];
  const numObjects = Number(buf.readBigUInt64BE(trailerOff + 8));
  const topObject = Number(buf.readBigUInt64BE(trailerOff + 16));
  const offsetTableOffset = Number(buf.readBigUInt64BE(trailerOff + 24));

  const readSized = (off, size) => {
    let v = 0;
    for (let i = 0; i < size; i++) v = v * 256 + buf[off + i];
    return v;
  };

  const offsets = [];
  for (let i = 0; i < numObjects; i++) {
    offsets.push(readSized(offsetTableOffset + i * offsetSize, offsetSize));
  }

  const parseObject = (index) => {
    let off = offsets[index];
    const marker = buf[off];
    const type = marker & 0xf0;
    const nibble = marker & 0x0f;
    off += 1;

    const readCount = () => {
      if (nibble !== 0xf) return nibble;
      const intMarker = buf[off];
      const intLen = 1 << (intMarker & 0x0f);
      off += 1;
      const n = readSized(off, intLen);
      off += intLen;
      return n;
    };

    switch (type) {
      case 0x00: // singletons
        if (marker === 0x00) return null;
        if (marker === 0x08) return false;
        if (marker === 0x09) return true;
        return null;
      case 0x10: {
        // int
        const len = 1 << nibble;
        return readSized(off, len);
      }
      case 0x20: {
        // real
        const len = 1 << nibble;
        return len === 8 ? buf.readDoubleBE(off) : buf.readFloatBE(off);
      }
      case 0x30: // date (seconds since 2001-01-01)
        return new Date(Date.UTC(2001, 0, 1) + buf.readDoubleBE(off) * 1000).toISOString();
      case 0x40: {
        // data
        const n = readCount();
        return buf.subarray(off, off + n);
      }
      case 0x50: {
        // ASCII string
        const n = readCount();
        return buf.toString("latin1", off, off + n);
      }
      case 0x60: {
        // UTF-16BE string
        const n = readCount();
        return buf.toString("utf16le", off, off + n * 2)
          .split("")
          .length === 0
          ? ""
          : utf16beToString(buf, off, n);
      }
      case 0x80: {
        // uid
        const len = nibble + 1;
        return { CF$UID: readSized(off, len) };
      }
      case 0xa0:
      case 0xc0: {
        // array / set
        const n = readCount();
        const arr = [];
        for (let i = 0; i < n; i++) arr.push(parseObject(readSized(off + i * refSize, refSize)));
        return arr;
      }
      case 0xd0: {
        // dict
        const n = readCount();
        const obj = {};
        for (let i = 0; i < n; i++) {
          const key = parseObject(readSized(off + i * refSize, refSize));
          const val = parseObject(readSized(off + (n + i) * refSize, refSize));
          obj[key] = val;
        }
        return obj;
      }
      default:
        return null;
    }
  };

  return parseObject(topObject);
}

function utf16beToString(buf, off, n) {
  let s = "";
  for (let i = 0; i < n; i++) s += String.fromCharCode(buf.readUInt16BE(off + i * 2));
  return s;
}

// ---------- XML plist ----------

function parseXmlPlist(text) {
  // Strip declaration / doctype / comments.
  let s = text.replace(/<\?xml[^>]*\?>/g, "").replace(/<!DOCTYPE[^>]*>/g, "").replace(/<!--[\s\S]*?-->/g, "");
  const plistMatch = s.match(/<plist[^>]*>([\s\S]*)<\/plist>/);
  if (plistMatch) s = plistMatch[1];
  const tokens = tokenize(s);
  let pos = 0;

  const parseValue = () => {
    const tok = tokens[pos];
    if (!tok) return null;
    switch (tok.name) {
      case "dict": {
        pos++;
        const obj = {};
        while (tokens[pos] && tokens[pos].name !== "/dict") {
          const keyTok = tokens[pos];
          if (keyTok.name !== "key") { pos++; continue; }
          pos++;
          const key = decodeEntities(tokens[pos] && tokens[pos].text ? tokens[pos].text : "");
          pos++; // text
          if (tokens[pos] && tokens[pos].name === "/key") pos++;
          obj[key] = parseValue();
        }
        pos++; // /dict
        return obj;
      }
      case "array": {
        pos++;
        const arr = [];
        while (tokens[pos] && tokens[pos].name !== "/array") arr.push(parseValue());
        pos++;
        return arr;
      }
      case "true": pos++; return true;
      case "false": pos++; return false;
      case "string": case "integer": case "real": case "date": case "data": {
        const name = tok.name;
        pos++;
        let text2 = "";
        if (tokens[pos] && tokens[pos].text !== undefined) { text2 = tokens[pos].text; pos++; }
        if (tokens[pos] && tokens[pos].name === `/${name}`) pos++;
        if (name === "integer") return parseInt(text2.trim(), 10);
        if (name === "real") return parseFloat(text2.trim());
        return decodeEntities(text2);
      }
      case "true/": pos++; return true;
      case "false/": pos++; return false;
      default:
        pos++;
        return null;
    }
  };

  // Skip to first real element.
  while (tokens[pos] && tokens[pos].text !== undefined && tokens[pos].name === undefined) pos++;
  return parseValue();
}

function tokenize(s) {
  const tokens = [];
  const re = /<(\/?[a-zA-Z]+)\s*\/?>|([^<]+)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    if (m[1] !== undefined) {
      const selfClose = m[0].endsWith("/>") && !m[1].startsWith("/");
      tokens.push({ name: selfClose ? `${m[1]}/` : m[1] });
    } else if (m[2] !== undefined) {
      if (m[2].trim() === "") continue;
      tokens.push({ text: m[2] });
    }
  }
  return tokens;
}

function decodeEntities(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&amp;/g, "&");
}

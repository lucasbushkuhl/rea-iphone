// Minimal ZIP reader, enough to inventory and extract members of an IPA
// (which is a ZIP). Reads the central directory, supports STORE and DEFLATE,
// and handles the common Zip64 case (0xffffffff local-header offset carried in
// the extra field). No shelling out, no dependencies.

import { inflateRawSync } from "node:zlib";

const EOCD_SIG = 0x06054b50;
const EOCD64_LOC_SIG = 0x07064b50;
const EOCD64_SIG = 0x06064b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

export function readZip(buf) {
  const eocd = findEOCD(buf);
  let { entryCount, cdOffset } = eocd;

  // Zip64 upgrade if the classic record is saturated.
  if (entryCount === 0xffff || cdOffset === 0xffffffff) {
    const loc = eocd.pos - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === EOCD64_LOC_SIG) {
      const eocd64Off = Number(buf.readBigUInt64LE(loc + 8));
      if (buf.readUInt32LE(eocd64Off) === EOCD64_SIG) {
        entryCount = Number(buf.readBigUInt64LE(eocd64Off + 32));
        cdOffset = Number(buf.readBigUInt64LE(eocd64Off + 48));
      }
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount && p + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(p) !== CEN_SIG) break;
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    let uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);

    // Walk the extra field for a Zip64 record if any size/offset is saturated.
    if (compSize === 0xffffffff || uncompSize === 0xffffffff || localOffset === 0xffffffff) {
      const exStart = p + 46 + nameLen;
      let e = exStart;
      const exEnd = exStart + extraLen;
      while (e + 4 <= exEnd) {
        const id = buf.readUInt16LE(e);
        const sz = buf.readUInt16LE(e + 2);
        let q = e + 4;
        if (id === 0x0001) {
          if (uncompSize === 0xffffffff) { uncompSize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (compSize === 0xffffffff) { compSize = Number(buf.readBigUInt64LE(q)); q += 8; }
          if (localOffset === 0xffffffff) { localOffset = Number(buf.readBigUInt64LE(q)); q += 8; }
          break;
        }
        e += 4 + sz;
      }
    }

    entries.push({ name, method, compSize, uncompSize, localOffset, isDir: name.endsWith("/") });
    p += 46 + nameLen + extraLen + commentLen;
  }

  const extract = (entry) => {
    if (entry.isDir) return Buffer.alloc(0);
    const lo = entry.localOffset;
    if (buf.readUInt32LE(lo) !== LOC_SIG) throw new Error(`bad local header for ${entry.name}`);
    const lnameLen = buf.readUInt16LE(lo + 26);
    const lextraLen = buf.readUInt16LE(lo + 28);
    const dataStart = lo + 30 + lnameLen + lextraLen;
    const raw = buf.subarray(dataStart, dataStart + entry.compSize);
    if (entry.method === 0) return Buffer.from(raw);
    if (entry.method === 8) return inflateRawSync(raw);
    throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
  };

  return { entries, extract };
}

function findEOCD(buf) {
  const minPos = Math.max(0, buf.length - 65557); // max comment 65535 + 22
  for (let pos = buf.length - 22; pos >= minPos; pos--) {
    if (buf.readUInt32LE(pos) === EOCD_SIG) {
      return {
        pos,
        entryCount: buf.readUInt16LE(pos + 10),
        cdOffset: buf.readUInt32LE(pos + 16),
      };
    }
  }
  throw new Error("not a ZIP/IPA: end-of-central-directory not found");
}

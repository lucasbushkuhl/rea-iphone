// Minimal ZIP reader, enough to inventory and extract members of an IPA.
// Pure: no Node imports. Decompression is injected (Node passes
// zlib.inflateRawSync; the browser inflates asynchronously with
// DecompressionStream and only needs the parsers exported here).

const EOCD_SIG = 0x06054b50;
const EOCD64_LOC_SIG = 0x07064b50;
const EOCD64_SIG = 0x06064b50;
const CEN_SIG = 0x02014b50;
export const LOC_SIG = 0x04034b50;

/**
 * Locate the end-of-central-directory record in `tail`, the last bytes of the
 * archive starting at absolute offset `tailOffset`. Returns the classic record
 * plus, when present, the absolute offset of the Zip64 end record.
 */
export function findEOCD(tail, tailOffset = 0) {
  const minPos = Math.max(0, tail.length - 65557); // max comment 65535 + 22
  for (let pos = tail.length - 22; pos >= minPos; pos--) {
    if (tail.readUInt32LE(pos) === EOCD_SIG) {
      const rec = {
        pos: tailOffset + pos,
        entryCount: tail.readUInt16LE(pos + 10),
        cdSize: tail.readUInt32LE(pos + 12),
        cdOffset: tail.readUInt32LE(pos + 16),
        zip64EndOffset: null,
      };
      const loc = pos - 20;
      if (loc >= 0 && tail.readUInt32LE(loc) === EOCD64_LOC_SIG) rec.zip64EndOffset = Number(tail.readBigUInt64LE(loc + 8));
      return rec;
    }
  }
  throw new Error("not a ZIP/IPA: end-of-central-directory not found");
}

/** Apply a Zip64 end-of-central-directory record (56+ bytes) to an EOCD. */
export function applyZip64End(eocd, rec64) {
  if (rec64.readUInt32LE(0) !== EOCD64_SIG) return eocd;
  return {
    ...eocd,
    entryCount: Number(rec64.readBigUInt64LE(32)),
    cdSize: Number(rec64.readBigUInt64LE(40)),
    cdOffset: Number(rec64.readBigUInt64LE(48)),
  };
}

/** Parse central-directory records from `cd` (a buffer holding the directory). */
export function parseCentralDirectory(cd, entryCount, start = 0) {
  const entries = [];
  let p = start;
  for (let i = 0; i < entryCount && p + 46 <= cd.length; i++) {
    if (cd.readUInt32LE(p) !== CEN_SIG) break;
    const flags = cd.readUInt16LE(p + 8);
    const method = cd.readUInt16LE(p + 10);
    const crc32 = cd.readUInt32LE(p + 16);
    let compSize = cd.readUInt32LE(p + 20);
    let uncompSize = cd.readUInt32LE(p + 24);
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    let localOffset = cd.readUInt32LE(p + 42);
    const name = cd.toString("utf8", p + 46, p + 46 + nameLen);

    if (compSize === 0xffffffff || uncompSize === 0xffffffff || localOffset === 0xffffffff) {
      const exStart = p + 46 + nameLen;
      const exEnd = Math.min(exStart + extraLen, cd.length);
      for (let e = exStart; e + 4 <= exEnd;) {
        const id = cd.readUInt16LE(e);
        const sz = cd.readUInt16LE(e + 2);
        let q = e + 4;
        if (id === 0x0001) {
          if (uncompSize === 0xffffffff && q + 8 <= exEnd) { uncompSize = Number(cd.readBigUInt64LE(q)); q += 8; }
          if (compSize === 0xffffffff && q + 8 <= exEnd) { compSize = Number(cd.readBigUInt64LE(q)); q += 8; }
          if (localOffset === 0xffffffff && q + 8 <= exEnd) { localOffset = Number(cd.readBigUInt64LE(q)); q += 8; }
          break;
        }
        e += 4 + sz;
      }
    }
    entries.push({ name, method, crc32, compSize, uncompSize, localOffset, encrypted: (flags & 1) === 1, isDir: name.endsWith("/") });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Offset of a member's compressed data, given its 30-byte local header. */
export function localDataStart(localHeader, localOffset) {
  if (localHeader.readUInt32LE(0) !== LOC_SIG) throw new Error("bad ZIP local header");
  return localOffset + 30 + localHeader.readUInt16LE(26) + localHeader.readUInt16LE(28);
}

/** Read a whole archive held in memory. options.inflateRaw(buf) -> buf. */
export function readZip(buf, { inflateRaw } = {}) {
  let eocd = findEOCD(buf);
  if (eocd.zip64EndOffset != null && (eocd.entryCount === 0xffff || eocd.cdOffset === 0xffffffff)) {
    eocd = applyZip64End(eocd, buf.subarray(eocd.zip64EndOffset, eocd.zip64EndOffset + 56));
  }
  const entries = parseCentralDirectory(buf, eocd.entryCount, eocd.cdOffset);

  const extract = (entry) => {
    if (entry.isDir) return buf.subarray(0, 0);
    if (entry.encrypted) throw new Error(`${entry.name} is password-encrypted`);
    const start = localDataStart(buf.subarray(entry.localOffset, entry.localOffset + 30), entry.localOffset);
    const raw = buf.subarray(start, start + entry.compSize);
    if (entry.method === 0) return Buffer.from(raw);
    if (entry.method === 8) {
      if (!inflateRaw) throw new Error("no DEFLATE decompressor available");
      return inflateRaw(raw);
    }
    throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
  };

  return { entries, extract };
}

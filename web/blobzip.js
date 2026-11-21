// ZIP access over a Blob/File without loading the archive into memory.
// Reads the central directory from the end of the file, then slices out only
// the members that are asked for and inflates them with the platform's
// DecompressionStream. A multi-hundred-megabyte IPA costs only the size of
// the members actually analyzed.

import { BrowserBuffer } from "./buffer.js";
import { findEOCD, applyZip64End, parseCentralDirectory, localDataStart } from "./core/zip.js";

const bytes = async (blob) => BrowserBuffer.wrap(new Uint8Array(await blob.arrayBuffer()));

async function inflate(blob, entry) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("This browser can't decompress ZIP data. Update to iOS 16.4 or later, or use a current desktop browser.");
  }
  let stream;
  try {
    stream = blob.stream().pipeThrough(new DecompressionStream("deflate-raw"));
  } catch {
    // No raw-deflate support: wrap the member as a gzip stream instead. The
    // gzip trailer needs the CRC-32 and size, which the ZIP index records.
    const header = new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
    const trailer = new Uint8Array(8);
    const dv = new DataView(trailer.buffer);
    dv.setUint32(0, entry.crc32 >>> 0, true);
    dv.setUint32(4, entry.uncompSize >>> 0, true);
    stream = new Blob([header, blob, trailer]).stream().pipeThrough(new DecompressionStream("gzip"));
  }
  return BrowserBuffer.wrap(new Uint8Array(await new Response(stream).arrayBuffer()));
}

export async function openZipBlob(file) {
  const tailLen = Math.min(file.size, 65557 + 20);
  const tailOff = file.size - tailLen;
  const tail = await bytes(file.slice(tailOff));
  let eocd = findEOCD(tail, tailOff);
  if (eocd.zip64EndOffset != null && (eocd.entryCount === 0xffff || eocd.cdOffset === 0xffffffff || eocd.cdSize === 0xffffffff)) {
    eocd = applyZip64End(eocd, await bytes(file.slice(eocd.zip64EndOffset, eocd.zip64EndOffset + 56)));
  }
  if (eocd.cdOffset + eocd.cdSize > file.size) throw new Error("This ZIP file is truncated: its index points past the end of the file.");
  const cd = await bytes(file.slice(eocd.cdOffset, eocd.cdOffset + eocd.cdSize));
  const entries = parseCentralDirectory(cd, eocd.entryCount, 0);

  const extract = async (entry) => {
    if (entry.isDir) return new BrowserBuffer(0);
    if (entry.encrypted) throw new Error(`${entry.name} is password-protected inside the ZIP.`);
    const lh = await bytes(file.slice(entry.localOffset, entry.localOffset + 30));
    const start = localDataStart(lh, entry.localOffset);
    const raw = file.slice(start, start + entry.compSize);
    if (entry.method === 0) return bytes(raw);
    if (entry.method === 8) return inflate(raw, entry);
    throw new Error(`${entry.name} uses ZIP compression method ${entry.method}, which isn't supported.`);
  };

  return { entries, extract };
}

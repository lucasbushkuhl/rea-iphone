// Mach-O parser — static, execution-free. Parses fat (universal) and thin
// Mach-O images and summarizes the facts that matter for iPhone app analysis:
// architecture slices, file type, FairPlay encryption state, imported dylibs,
// linked platform / minimum OS, UUID, code-signature presence, and language
// (Swift / Objective-C) section hints. No code from the target is executed.

const MAGIC = {
  FAT: 0xcafebabe, // big-endian in file
  FAT_64: 0xcafebabf,
  MH_32: 0xfeedface,
  MH_64: 0xfeedfacf,
};

const CPU_ARCH_ABI64 = 0x01000000;
const CPU_TYPE = {
  7: "x86",
  [0x01000007]: "x86_64",
  12: "arm",
  [0x0100000c]: "arm64",
  [0x0200000c]: "arm64_32",
};
const ARM64_SUBTYPE = { 0: "arm64", 1: "arm64v8", 2: "arm64e" };

const FILETYPE = {
  1: "MH_OBJECT",
  2: "MH_EXECUTE",
  6: "MH_DYLIB",
  7: "MH_DYLINKER",
  8: "MH_BUNDLE",
  9: "MH_DYLIB_STUB",
  10: "MH_DSYM",
};

const LC_REQ_DYLD = 0x80000000;
const LC = {
  SEGMENT: 0x1,
  SEGMENT_64: 0x19,
  LOAD_DYLIB: 0xc,
  ID_DYLIB: 0xd,
  LOAD_WEAK_DYLIB: 0x18 | LC_REQ_DYLD,
  REEXPORT_DYLIB: 0x1f | LC_REQ_DYLD,
  UUID: 0x1b,
  RPATH: 0x1c | LC_REQ_DYLD,
  CODE_SIGNATURE: 0x1d,
  ENCRYPTION_INFO: 0x21,
  ENCRYPTION_INFO_64: 0x2c,
  VERSION_MIN_MACOSX: 0x24,
  VERSION_MIN_IPHONEOS: 0x25,
  VERSION_MIN_TVOS: 0x2f,
  VERSION_MIN_WATCHOS: 0x30,
  BUILD_VERSION: 0x32,
};

const PLATFORM = {
  1: "macOS",
  2: "iOS",
  3: "tvOS",
  4: "watchOS",
  5: "bridgeOS",
  6: "macCatalyst",
  7: "iOSSimulator",
  8: "tvOSSimulator",
  9: "watchOSSimulator",
  10: "driverKit",
  11: "visionOS",
  12: "visionOSSimulator",
};

function archName(cputype, cpusubtype) {
  if (cputype === 0x0100000c) {
    return ARM64_SUBTYPE[cpusubtype & 0xff] ?? "arm64";
  }
  return CPU_TYPE[cputype] ?? `cpu(0x${cputype.toString(16)})`;
}

// Decode an X.Y.Z version packed as nibble-free 32-bit (xxxx.yy.zz).
function decodeVersion(v) {
  return `${v >> 16}.${(v >> 8) & 0xff}.${v & 0xff}`;
}

// Parse a single thin Mach-O image starting at `base` within `buf`.
function parseThin(buf, base) {
  const magic = buf.readUInt32BE(base);
  let le;
  let is64;
  if (magic === MAGIC.MH_64 || buf.readUInt32LE(base) === MAGIC.MH_64) {
    is64 = true;
    le = buf.readUInt32LE(base) === MAGIC.MH_64;
  } else if (magic === MAGIC.MH_32 || buf.readUInt32LE(base) === MAGIC.MH_32) {
    is64 = false;
    le = buf.readUInt32LE(base) === MAGIC.MH_32;
  } else {
    throw new Error(`not a Mach-O image at offset ${base}`);
  }
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  const cputype = u32(base + 4);
  const cpusubtype = u32(base + 8);
  const filetype = u32(base + 12);
  const ncmds = u32(base + 16);
  const headerSize = is64 ? 32 : 28;

  const image = {
    arch: archName(cputype, cpusubtype),
    byteOrder: le ? "little" : "big",
    bits: is64 ? 64 : 32,
    filetype: FILETYPE[filetype] ?? `type(${filetype})`,
    loadCommandCount: ncmds,
    uuid: null,
    platform: null,
    minOS: null,
    sdk: null,
    encryption: { present: false, encrypted: null, cryptId: null },
    codeSignature: false,
    dylibs: [],
    rpaths: [],
    languageHints: [],
    segments: [],
  };

  const langSections = new Set();
  let off = base + headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (off + 8 > buf.length) break;
    const cmd = u32(off);
    const cmdsize = u32(off + 4);
    if (cmdsize < 8 || off + cmdsize > buf.length) break;

    switch (cmd) {
      case LC.LOAD_DYLIB:
      case LC.LOAD_WEAK_DYLIB:
      case LC.REEXPORT_DYLIB:
      case LC.ID_DYLIB: {
        const nameOff = u32(off + 8);
        const str = cstr(buf, off + nameOff, off + cmdsize);
        const weak = cmd === LC.LOAD_WEAK_DYLIB;
        if (cmd === LC.ID_DYLIB) image.installName = str;
        else image.dylibs.push(weak ? `${str} (weak)` : str);
        break;
      }
      case LC.RPATH: {
        const pOff = u32(off + 8);
        image.rpaths.push(cstr(buf, off + pOff, off + cmdsize));
        break;
      }
      case LC.UUID: {
        const b = buf.subarray(off + 8, off + 24);
        image.uuid = [...b].map((x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
        break;
      }
      case LC.ENCRYPTION_INFO:
      case LC.ENCRYPTION_INFO_64: {
        const cryptId = u32(off + 16);
        image.encryption = {
          present: true,
          encrypted: cryptId !== 0,
          cryptId,
        };
        break;
      }
      case LC.CODE_SIGNATURE:
        image.codeSignature = true;
        break;
      case LC.VERSION_MIN_IPHONEOS:
        image.platform ??= "iOS";
        image.minOS = decodeVersion(u32(off + 8));
        image.sdk = decodeVersion(u32(off + 12));
        break;
      case LC.VERSION_MIN_MACOSX:
        image.platform ??= "macOS";
        image.minOS = decodeVersion(u32(off + 8));
        break;
      case LC.VERSION_MIN_TVOS:
        image.platform ??= "tvOS";
        image.minOS = decodeVersion(u32(off + 8));
        break;
      case LC.VERSION_MIN_WATCHOS:
        image.platform ??= "watchOS";
        image.minOS = decodeVersion(u32(off + 8));
        break;
      case LC.BUILD_VERSION: {
        const plat = u32(off + 8);
        image.platform = PLATFORM[plat] ?? `platform(${plat})`;
        image.minOS = decodeVersion(u32(off + 12));
        image.sdk = decodeVersion(u32(off + 16));
        break;
      }
      case LC.SEGMENT_64:
      case LC.SEGMENT: {
        const is64Seg = cmd === LC.SEGMENT_64;
        const segName = cstr(buf, off + 8, off + 24);
        const nsectsOff = off + (is64Seg ? 64 : 48);
        const nsects = u32(nsectsOff);
        image.segments.push(segName);
        const secStride = is64Seg ? 80 : 68;
        let secOff = off + (is64Seg ? 72 : 56);
        for (let s = 0; s < nsects && secOff + 32 <= off + cmdsize; s++) {
          const sect = cstr(buf, secOff, secOff + 16);
          langSections.add(sect);
          secOff += secStride;
        }
        break;
      }
      default:
        break;
    }
    off += cmdsize;
  }

  // Language hints from section names (Swift / Objective-C runtime metadata).
  const hasSwift = [...langSections].some((s) => s.startsWith("__swift5") || s.startsWith("__swift"));
  const hasObjC = [...langSections].some((s) => s.startsWith("__objc"));
  if (hasSwift) image.languageHints.push("Swift");
  if (hasObjC) image.languageHints.push("Objective-C");

  return image;
}

function cstr(buf, start, hardEnd) {
  let end = start;
  while (end < hardEnd && end < buf.length && buf[end] !== 0) end++;
  return buf.toString("utf8", start, end);
}

// Parse a Mach-O buffer, returning { kind, images[] }. `kind` is "fat" or "thin".
export function parseMachO(buf) {
  if (buf.length < 8) throw new Error("buffer too small to be Mach-O");
  const beMagic = buf.readUInt32BE(0);
  const leMagic = buf.readUInt32LE(0);

  if (beMagic === MAGIC.FAT || beMagic === MAGIC.FAT_64) {
    const is64 = beMagic === MAGIC.FAT_64;
    const nfat = buf.readUInt32BE(4);
    const images = [];
    const stride = is64 ? 32 : 20;
    for (let i = 0; i < nfat; i++) {
      const a = 8 + i * stride;
      const offset = is64 ? Number(buf.readBigUInt64BE(a + 8)) : buf.readUInt32BE(a + 8);
      images.push(parseThin(buf, offset));
    }
    return { kind: "fat", sliceCount: nfat, images };
  }

  if ([MAGIC.MH_32, MAGIC.MH_64].includes(beMagic) || [MAGIC.MH_32, MAGIC.MH_64].includes(leMagic)) {
    return { kind: "thin", sliceCount: 1, images: [parseThin(buf, 0)] };
  }

  throw new Error("not a Mach-O file (unknown magic)");
}

export function isMachO(buf) {
  if (!buf || buf.length < 4) return false;
  const be = buf.readUInt32BE(0);
  const le = buf.readUInt32LE(0);
  return [MAGIC.FAT, MAGIC.FAT_64, MAGIC.MH_32, MAGIC.MH_64].includes(be) ||
    [MAGIC.MH_32, MAGIC.MH_64].includes(le);
}

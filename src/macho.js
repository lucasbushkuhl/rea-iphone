// Mach-O image model — static, execution-free.
//
// `openMachO(buf)` returns one MachOImage per architecture slice (fat or
// thin). Each image knows its segments and sections, maps virtual addresses
// to file offsets (and back), reads C strings and integers at addresses,
// knows which file ranges are FairPlay-encrypted, and records the offsets of
// the symbol table, dynamic-symbol table, export trie and fixup data (classic
// LC_DYLD_INFO rebase/bind opcodes or LC_DYLD_CHAINED_FIXUPS). Pointer
// resolution through fixups lives in macho/fixups.js.
//
// `parseMachO(buf)` keeps the original summary shape used by analyze.js.

const MAGIC = { FAT: 0xcafebabe, FAT_64: 0xcafebabf, MH_32: 0xfeedface, MH_64: 0xfeedfacf };

const CPU_TYPE = {
  7: "x86",
  [0x01000007]: "x86_64",
  12: "arm",
  [0x0100000c]: "arm64",
  [0x0200000c]: "arm64_32",
};
const ARM64_SUBTYPE = { 0: "arm64", 1: "arm64v8", 2: "arm64e" };
const FILETYPE = {
  1: "MH_OBJECT", 2: "MH_EXECUTE", 6: "MH_DYLIB", 7: "MH_DYLINKER",
  8: "MH_BUNDLE", 9: "MH_DYLIB_STUB", 10: "MH_DSYM", 11: "MH_KEXT_BUNDLE",
};

const LC_REQ_DYLD = 0x80000000;
export const LC = {
  SEGMENT: 0x1,
  SYMTAB: 0x2,
  DYSYMTAB: 0xb,
  LOAD_DYLIB: 0xc,
  ID_DYLIB: 0xd,
  LOAD_WEAK_DYLIB: (0x18 | LC_REQ_DYLD) >>> 0,
  SEGMENT_64: 0x19,
  UUID: 0x1b,
  RPATH: (0x1c | LC_REQ_DYLD) >>> 0,
  CODE_SIGNATURE: 0x1d,
  REEXPORT_DYLIB: (0x1f | LC_REQ_DYLD) >>> 0,
  LAZY_LOAD_DYLIB: 0x20,
  ENCRYPTION_INFO: 0x21,
  DYLD_INFO: 0x22,
  DYLD_INFO_ONLY: (0x22 | LC_REQ_DYLD) >>> 0,
  LOAD_UPWARD_DYLIB: (0x23 | LC_REQ_DYLD) >>> 0,
  VERSION_MIN_MACOSX: 0x24,
  VERSION_MIN_IPHONEOS: 0x25,
  FUNCTION_STARTS: 0x26,
  MAIN: (0x28 | LC_REQ_DYLD) >>> 0,
  ENCRYPTION_INFO_64: 0x2c,
  VERSION_MIN_TVOS: 0x2f,
  VERSION_MIN_WATCHOS: 0x30,
  BUILD_VERSION: 0x32,
  DYLD_EXPORTS_TRIE: (0x33 | LC_REQ_DYLD) >>> 0,
  DYLD_CHAINED_FIXUPS: (0x34 | LC_REQ_DYLD) >>> 0,
};

const PLATFORM = {
  1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "macCatalyst",
  7: "iOSSimulator", 8: "tvOSSimulator", 9: "watchOSSimulator", 10: "driverKit",
  11: "visionOS", 12: "visionOSSimulator",
};

const ZEROFILL_TYPES = new Set([0x1, 0xc, 0x12]); // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL

function archName(cputype, cpusubtype) {
  if (cputype === 0x0100000c) return ARM64_SUBTYPE[cpusubtype & 0xff] ?? "arm64";
  return CPU_TYPE[cputype] ?? `cpu(0x${cputype.toString(16)})`;
}

const decodeVersion = (v) => `${v >>> 16}.${(v >>> 8) & 0xff}.${v & 0xff}`;

function fixedName(buf, start, len) {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return buf.toString("latin1", start, end);
}

export class MachOImage {
  constructor(buf, base = 0, sliceSize = buf.length - base) {
    this.buf = buf;
    this.base = base;
    this.sliceEnd = Math.min(buf.length, base + sliceSize);
    if (base < 0 || base + 32 > buf.length) throw new Error(`Mach-O slice at offset ${base} lies outside the file`);

    const be = buf.readUInt32BE(base);
    const le = buf.readUInt32LE(base);
    if (le === MAGIC.MH_64 || le === MAGIC.MH_32) this.le = true;
    else if (be === MAGIC.MH_64 || be === MAGIC.MH_32) this.le = false;
    else throw new Error(`not a Mach-O image at offset ${base}`);
    this.is64 = (this.le ? le : be) === MAGIC.MH_64;
    this.ptrSize = this.is64 ? 8 : 4;

    this.cputype = this.u32(base + 4);
    this.cpusubtype = this.u32(base + 8);
    this.filetypeId = this.u32(base + 12);
    this.ncmds = this.u32(base + 16);
    this.flags = this.u32(base + 24);
    this.arch = archName(this.cputype, this.cpusubtype);
    this.filetype = FILETYPE[this.filetypeId] ?? `type(${this.filetypeId})`;

    this.segments = [];
    this.sections = [];
    this.dylibs = []; // { name, kind: load|weak|reexport|lazy|upward }
    this.rpaths = [];
    this.installName = null;
    this.uuid = null;
    this.platform = null;
    this.minOS = null;
    this.sdk = null;
    this.encryption = { present: false, encrypted: null, cryptId: null, cryptOff: 0, cryptSize: 0 };
    this.codeSignature = null; // { dataoff, datasize }
    this.symtab = null; // { symoff, nsyms, stroff, strsize }
    this.dysymtab = null;
    this.dyldInfo = null; // { rebase_off, rebase_size, bind_off, bind_size, weak_bind_*, lazy_bind_*, export_* }
    this.exportsTrie = null; // { dataoff, datasize }
    this.chainedFixups = null; // { dataoff, datasize }
    this.functionStarts = null;
    this.entryOff = null;
    this.loadCommands = [];

    this.#parseLoadCommands();
  }

  u8(o) { return this.buf[o]; }
  u16(o) { return this.le ? this.buf.readUInt16LE(o) : this.buf.readUInt16BE(o); }
  u32(o) { return this.le ? this.buf.readUInt32LE(o) : this.buf.readUInt32BE(o); }
  i32(o) { return this.le ? this.buf.readInt32LE(o) : this.buf.readInt32BE(o); }
  u64(o) { return this.le ? this.buf.readBigUInt64LE(o) : this.buf.readBigUInt64BE(o); }
  /** Read a pointer-sized raw value as BigInt. */
  rawPtr(o) { return this.is64 ? this.u64(o) : BigInt(this.u32(o)); }

  #parseLoadCommands() {
    const { buf, base } = this;
    let off = base + (this.is64 ? 32 : 28);
    for (let i = 0; i < this.ncmds; i++) {
      if (off + 8 > this.sliceEnd) break;
      const cmd = this.u32(off);
      const cmdsize = this.u32(off + 4);
      if (cmdsize < 8 || off + cmdsize > this.sliceEnd) break;
      this.loadCommands.push({ cmd, offset: off, size: cmdsize });

      switch (cmd) {
        case LC.SEGMENT_64:
        case LC.SEGMENT: {
          const s64 = cmd === LC.SEGMENT_64;
          const rd = (o) => (s64 ? Number(this.u64(o)) : this.u32(o));
          const seg = {
            index: this.segments.length,
            name: fixedName(buf, off + 8, 16),
            vmaddr: rd(off + 24),
            vmsize: rd(off + (s64 ? 32 : 28)),
            fileoff: rd(off + (s64 ? 40 : 32)),
            filesize: rd(off + (s64 ? 48 : 36)),
            maxprot: this.u32(off + (s64 ? 56 : 40)),
            initprot: this.u32(off + (s64 ? 60 : 44)),
            sections: [],
          };
          const nsects = this.u32(off + (s64 ? 64 : 48));
          let so = off + (s64 ? 72 : 56);
          const stride = s64 ? 80 : 68;
          for (let s = 0; s < nsects && so + stride <= off + cmdsize; s++, so += stride) {
            const flags = this.u32(so + (s64 ? 64 : 56));
            const sect = {
              name: fixedName(buf, so, 16),
              segname: fixedName(buf, so + 16, 16),
              addr: s64 ? Number(this.u64(so + 32)) : this.u32(so + 32),
              size: s64 ? Number(this.u64(so + 40)) : this.u32(so + 36),
              offset: this.u32(so + (s64 ? 48 : 40)),
              flags,
              type: flags & 0xff,
              segment: seg,
            };
            sect.zerofill = ZEROFILL_TYPES.has(sect.type);
            seg.sections.push(sect);
            this.sections.push(sect);
          }
          this.segments.push(seg);
          break;
        }
        case LC.LOAD_DYLIB:
        case LC.LOAD_WEAK_DYLIB:
        case LC.REEXPORT_DYLIB:
        case LC.LAZY_LOAD_DYLIB:
        case LC.LOAD_UPWARD_DYLIB:
        case LC.ID_DYLIB: {
          const name = this.#lcStr(off, cmdsize, this.u32(off + 8));
          if (cmd === LC.ID_DYLIB) { this.installName = name; break; }
          const kind = cmd === LC.LOAD_WEAK_DYLIB ? "weak"
            : cmd === LC.REEXPORT_DYLIB ? "reexport"
              : cmd === LC.LAZY_LOAD_DYLIB ? "lazy"
                : cmd === LC.LOAD_UPWARD_DYLIB ? "upward" : "load";
          this.dylibs.push({ name, kind, currentVersion: decodeVersion(this.u32(off + 16)) });
          break;
        }
        case LC.RPATH:
          this.rpaths.push(this.#lcStr(off, cmdsize, this.u32(off + 8)));
          break;
        case LC.UUID:
          this.uuid = [...buf.subarray(off + 8, off + 24)].map((x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
          break;
        case LC.ENCRYPTION_INFO:
        case LC.ENCRYPTION_INFO_64: {
          const cryptId = this.u32(off + 16);
          this.encryption = {
            present: true,
            encrypted: cryptId !== 0,
            cryptId,
            cryptOff: this.u32(off + 8),
            cryptSize: this.u32(off + 12),
          };
          break;
        }
        case LC.CODE_SIGNATURE:
          this.codeSignature = { dataoff: this.u32(off + 8), datasize: this.u32(off + 12) };
          break;
        case LC.FUNCTION_STARTS:
          this.functionStarts = { dataoff: this.u32(off + 8), datasize: this.u32(off + 12) };
          break;
        case LC.DYLD_EXPORTS_TRIE:
          this.exportsTrie = { dataoff: this.u32(off + 8), datasize: this.u32(off + 12) };
          break;
        case LC.DYLD_CHAINED_FIXUPS:
          this.chainedFixups = { dataoff: this.u32(off + 8), datasize: this.u32(off + 12) };
          break;
        case LC.SYMTAB:
          this.symtab = {
            symoff: this.u32(off + 8), nsyms: this.u32(off + 12),
            stroff: this.u32(off + 16), strsize: this.u32(off + 20),
          };
          break;
        case LC.DYSYMTAB:
          this.dysymtab = {
            ilocalsym: this.u32(off + 8), nlocalsym: this.u32(off + 12),
            iextdefsym: this.u32(off + 16), nextdefsym: this.u32(off + 20),
            iundefsym: this.u32(off + 24), nundefsym: this.u32(off + 28),
          };
          break;
        case LC.DYLD_INFO:
        case LC.DYLD_INFO_ONLY: {
          const f = (k) => this.u32(off + 8 + k * 4);
          this.dyldInfo = {
            rebase_off: f(0), rebase_size: f(1),
            bind_off: f(2), bind_size: f(3),
            weak_bind_off: f(4), weak_bind_size: f(5),
            lazy_bind_off: f(6), lazy_bind_size: f(7),
            export_off: f(8), export_size: f(9),
          };
          break;
        }
        case LC.MAIN:
          this.entryOff = Number(this.u64(off + 8));
          break;
        case LC.VERSION_MIN_IPHONEOS:
          this.platform ??= "iOS";
          this.minOS = decodeVersion(this.u32(off + 8));
          this.sdk = decodeVersion(this.u32(off + 12));
          break;
        case LC.VERSION_MIN_MACOSX:
          this.platform ??= "macOS";
          this.minOS = decodeVersion(this.u32(off + 8));
          this.sdk = decodeVersion(this.u32(off + 12));
          break;
        case LC.VERSION_MIN_TVOS:
          this.platform ??= "tvOS";
          this.minOS = decodeVersion(this.u32(off + 8));
          break;
        case LC.VERSION_MIN_WATCHOS:
          this.platform ??= "watchOS";
          this.minOS = decodeVersion(this.u32(off + 8));
          break;
        case LC.BUILD_VERSION: {
          const plat = this.u32(off + 8);
          this.platform = PLATFORM[plat] ?? `platform(${plat})`;
          this.minOS = decodeVersion(this.u32(off + 12));
          this.sdk = decodeVersion(this.u32(off + 16));
          break;
        }
        default:
          break;
      }
      off += cmdsize;
    }
  }

  #lcStr(cmdOff, cmdsize, strOff) {
    const start = cmdOff + strOff;
    const end = cmdOff + cmdsize;
    let e = start;
    while (e < end && this.buf[e] !== 0) e++;
    return this.buf.toString("utf8", start, e);
  }

  /** Preferred load address: vmaddr of the segment mapping file offset 0 (normally __TEXT). */
  get imageBase() {
    const text = this.segments.find((s) => s.fileoff === 0 && s.filesize > 0);
    return text ? text.vmaddr : 0;
  }

  segment(name) { return this.segments.find((s) => s.name === name) ?? null; }

  /** Find a section by name, optionally constrained to a segment (or list of segments). */
  section(sectname, segnames) {
    const segs = segnames == null ? null : Array.isArray(segnames) ? segnames : [segnames];
    return this.sections.find((s) => s.name === sectname && (!segs || segs.includes(s.segname))) ?? null;
  }

  /** Absolute buffer offset for a virtual address, or null when not file-backed. */
  vmToOffset(vm) {
    for (const seg of this.segments) {
      if (seg.filesize > 0 && vm >= seg.vmaddr && vm < seg.vmaddr + seg.filesize) {
        const off = this.base + seg.fileoff + (vm - seg.vmaddr);
        return off < this.sliceEnd ? off : null;
      }
    }
    return null;
  }

  /** Virtual address for an absolute buffer offset, or null. */
  offsetToVm(off) {
    const rel = off - this.base;
    for (const seg of this.segments) {
      if (seg.filesize > 0 && rel >= seg.fileoff && rel < seg.fileoff + seg.filesize) {
        return seg.vmaddr + (rel - seg.fileoff);
      }
    }
    return null;
  }

  segmentForVm(vm) {
    return this.segments.find((s) => vm >= s.vmaddr && vm < s.vmaddr + s.vmsize) ?? null;
  }

  sectionForVm(vm) {
    return this.sections.find((s) => vm >= s.addr && vm < s.addr + s.size) ?? null;
  }

  /** Absolute file range [start, end) of a section's bytes, or null for zerofill. */
  sectionRange(sect) {
    if (!sect || sect.zerofill || sect.size === 0) return null;
    const start = this.base + sect.offset;
    return { start, end: Math.min(start + sect.size, this.sliceEnd) };
  }

  /**
   * Addresses of fixed-size slots in a section, bounded by the bytes actually
   * present in the file (never by the declared size alone, which hostile or
   * truncated binaries can inflate).
   */
  *sectionSlots(sect, stride) {
    const range = this.sectionRange(sect);
    if (!range) return;
    const bytes = range.end - range.start;
    for (let o = 0; o + stride <= bytes; o += stride) yield sect.addr + o;
  }

  /** True when an absolute offset falls inside the FairPlay-encrypted range. */
  isEncryptedOffset(off) {
    const e = this.encryption;
    if (!e.encrypted) return false;
    const rel = off - this.base;
    return rel >= e.cryptOff && rel < e.cryptOff + e.cryptSize;
  }

  /** Read a NUL-terminated string at a virtual address (null if unmapped or encrypted). */
  cstringAt(vm, max = 4096) {
    const off = this.vmToOffset(vm);
    if (off == null || this.isEncryptedOffset(off)) return null;
    let end = off;
    const lim = Math.min(this.sliceEnd, off + max);
    while (end < lim && this.buf[end] !== 0) end++;
    return this.buf.toString("utf8", off, end);
  }

  /** Signed 32-bit relative pointer stored at vm: returns target vm (or null). */
  relativeAt(vm) {
    const off = this.vmToOffset(vm);
    if (off == null) return null;
    const rel = this.i32(off);
    return rel === 0 ? null : vm + rel;
  }

  /** Summary in the shape analyze.js has always consumed. */
  summary() {
    const sectNames = new Set(this.sections.map((s) => s.name));
    const languageHints = [];
    if ([...sectNames].some((s) => s.startsWith("__swift"))) languageHints.push("Swift");
    if ([...sectNames].some((s) => s.startsWith("__objc"))) languageHints.push("Objective-C");
    return {
      arch: this.arch,
      byteOrder: this.le ? "little" : "big",
      bits: this.is64 ? 64 : 32,
      filetype: this.filetype,
      loadCommandCount: this.ncmds,
      uuid: this.uuid,
      platform: this.platform,
      minOS: this.minOS,
      sdk: this.sdk,
      encryption: { present: this.encryption.present, encrypted: this.encryption.encrypted, cryptId: this.encryption.cryptId },
      codeSignature: this.codeSignature !== null,
      dylibs: this.dylibs.map((d) => (d.kind === "weak" ? `${d.name} (weak)` : d.name)),
      rpaths: this.rpaths,
      installName: this.installName,
      languageHints,
      segments: this.segments.map((s) => s.name),
      fixupFormat: this.chainedFixups ? "chained" : this.dyldInfo ? "dyld-info" : "none",
    };
  }
}

/** Open every architecture slice of a Mach-O buffer as a MachOImage. */
export function openMachO(buf) {
  if (!buf || buf.length < 8) throw new Error("buffer too small to be Mach-O");
  const be = buf.readUInt32BE(0);
  if (be === MAGIC.FAT || be === MAGIC.FAT_64) {
    const is64 = be === MAGIC.FAT_64;
    const nfat = buf.readUInt32BE(4);
    if (nfat > 64) throw new Error(`implausible fat slice count ${nfat}`);
    const stride = is64 ? 32 : 20;
    const images = [];
    for (let i = 0; i < nfat; i++) {
      const a = 8 + i * stride;
      const offset = is64 ? Number(buf.readBigUInt64BE(a + 8)) : buf.readUInt32BE(a + 8);
      const size = is64 ? Number(buf.readBigUInt64BE(a + 16)) : buf.readUInt32BE(a + 12);
      images.push(new MachOImage(buf, offset, size));
    }
    return { kind: "fat", sliceCount: nfat, images };
  }
  return { kind: "thin", sliceCount: 1, images: [new MachOImage(buf, 0)] };
}

/** Pick the slice to deep-analyze: explicit arch, else arm64e/arm64, else first 64-bit. */
export function selectImage(images, arch) {
  if (arch) return images.find((im) => im.arch === arch) ?? null;
  return images.find((im) => im.arch === "arm64e")
    ?? images.find((im) => im.arch === "arm64")
    ?? images.find((im) => im.is64)
    ?? images[0] ?? null;
}

export function parseMachO(buf) {
  const { kind, sliceCount, images } = openMachO(buf);
  return { kind, sliceCount, images: images.map((im) => im.summary()) };
}

export function isMachO(buf) {
  if (!buf || buf.length < 4) return false;
  const be = buf.readUInt32BE(0);
  const le = buf.readUInt32LE(0);
  return [MAGIC.FAT, MAGIC.FAT_64, MAGIC.MH_32, MAGIC.MH_64].includes(be) || [MAGIC.MH_32, MAGIC.MH_64].includes(le);
}

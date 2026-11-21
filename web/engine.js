// Analysis engine for the web app. Runs in a Web Worker (worker.js) or, as a
// fallback, on the main thread. Everything happens on this device: files are
// read with the File API and never sent anywhere.

import { BrowserBuffer } from "./buffer.js";
import { openZipBlob } from "./blobzip.js";
import { memorySource, machoSource, listBinaries, isBundleMetadata, pickBinary } from "./core/bundle.js";
import { analyzeSource } from "./core/analyzeSource.js";
import { openMachO, selectImage, isMachO } from "./core/macho.js";
import { deepAnalyze } from "./core/deep.js";
import { renderObjCHeader } from "./core/objc.js";
import { renderSwiftInterface } from "./core/swift/metadata.js";
import { demangleSymbol } from "./core/swift/demangle.js";
import { renderText } from "./core/report.js";
import { generateScript, MODES } from "./core/frida/scripts.js";

const MAX_METADATA_BYTES = 8 * 1024 * 1024;
const MAX_UI_STRINGS = 20000;

let state = null; // { name, src, zip, byName, cache, report, binaries }

const mb = (n) => `${(n / 1048576).toFixed(n < 10485760 ? 1 : 0)} MB`;

async function ensureLoaded(path, progress) {
  if (state.cache.has(path)) return state.cache.get(path);
  const entry = state.byName.get(path);
  if (!entry) throw new Error(`${path} isn't in this archive.`);
  progress?.(`Decompressing ${path.split("/").pop()} (${mb(entry.uncompSize)})`);
  const buf = await state.zip.extract(entry);
  state.cache.set(path, buf);
  return buf;
}

/** Open a File/Blob: .ipa, zipped .app, or a bare Mach-O. */
export async function openFile(file, name, progress = () => {}) {
  state = null;
  const head = BrowserBuffer.wrap(new Uint8Array(await file.slice(0, 4).arrayBuffer()));
  if (head.length < 4) throw new Error("This file is empty or too small to be an app or binary.");

  if (head[0] === 0x50 && head[1] === 0x4b) {
    progress("Reading the archive index");
    let zip;
    try {
      zip = await openZipBlob(file);
    } catch (err) {
      throw new Error(/central-directory|truncated/i.test(err.message) ? "This ZIP file is incomplete or damaged. Try downloading or exporting it again." : err.message);
    }
    const files = zip.entries.filter((e) => !e.isDir);
    const listing = files.map((e) => ({ path: e.name, size: e.uncompSize }));
    const byName = new Map(files.map((e) => [e.name, e]));
    const cache = new Map();
    const meta = files.filter((e) => isBundleMetadata(e.name) && e.uncompSize <= MAX_METADATA_BYTES);
    progress(`Reading bundle metadata (${meta.length} files)`);
    for (const e of meta) {
      try { cache.set(e.name, await zip.extract(e)); } catch { /* reported by analysis as missing */ }
    }
    const container = files.some((e) => e.name.startsWith("Payload/")) ? "ipa" : "zip";
    state = { name, zip, byName, cache, src: memorySource(container, cache, listing) };
    state.binaries = listBinaries(state.src);
    if (state.binaries.length === 0) throw new Error("No iOS app was found in this ZIP. Expected Payload/<Name>.app or <Name>.app inside.");
    const main = pickBinary(state.binaries, "main");
    await ensureLoaded(main.path, progress);
  } else if (isMachO(head)) {
    progress(`Reading ${mb(file.size)} Mach-O`);
    const buf = BrowserBuffer.wrap(new Uint8Array(await file.arrayBuffer()));
    state = { name, zip: null, byName: new Map(), cache: new Map([[name, buf]]), src: machoSource(name, buf) };
    state.binaries = listBinaries(state.src);
  } else {
    throw new Error("This isn't an .ipa, a zipped .app, or a Mach-O binary.");
  }

  progress("Analyzing");
  const report = analyzeSource(state.src, name, { deep: false });
  state.report = report;
  const main = pickBinary(state.binaries, "main");
  const deep = await analyzeBinary(main.path, null, progress);
  return { report: JSON.parse(JSON.stringify(report)), text: renderText(report), binaries: state.binaries.map(({ role, path }) => ({ role, path })), deep };
}

/** Deep-analyze one binary of the open target. */
export async function analyzeBinary(path, arch, progress = () => {}) {
  if (!state) throw new Error("Open a file first.");
  const buf = await ensureLoaded(path, progress);
  if (!isMachO(buf)) throw new Error(`${path} isn't a Mach-O binary.`);
  const { kind, images } = openMachO(buf);
  const image = selectImage(images, arch || undefined);
  if (!image) throw new Error(`No ${arch} slice in ${path}.`);
  progress(`Analyzing ${path.split("/").pop()} (${image.arch})`);
  const d = deepAnalyze(image);
  return viewModel(path, kind, images, image, d);
}

function viewModel(path, kind, images, image, d) {
  const dm = (name) => ({ name, demangled: demangleSymbol(name) });
  const objcHeader = renderObjCHeader(d.objc);
  return {
    path,
    kind,
    arch: image.arch,
    slices: images.map((im) => ({ arch: im.arch, platform: im.platform, minOS: im.minOS, encrypted: im.encryption.encrypted, is64: im.is64 })),
    image: {
      platform: image.platform,
      minOS: image.minOS,
      sdk: image.sdk,
      uuid: image.uuid,
      filetype: image.filetype,
      encrypted: image.encryption.encrypted,
      cryptId: image.encryption.present ? image.encryption.cryptId : null,
      signed: image.codeSignature !== null,
      dylibs: image.dylibs,
      segments: image.segments.map((s) => ({ name: s.name, vmaddr: s.vmaddr, vmsize: s.vmsize, sections: s.sections.length })),
    },
    fixups: d.fixups,
    objc: {
      classes: d.objc.classes.map((c) => ({
        ...c,
        header: renderObjCHeader({ protocols: [], classes: [c], categories: [], externalClassRefs: [] }).split("\n").slice(4).join("\n").trim(),
      })),
      categories: d.objc.categories.map((c) => ({
        ...c,
        header: renderObjCHeader({ protocols: [], classes: [], categories: [c], externalClassRefs: [] }).split("\n").slice(4).join("\n").trim(),
      })),
      protocols: d.objc.protocols.map((p) => ({
        ...p,
        header: renderObjCHeader({ protocols: [p], classes: [], categories: [], externalClassRefs: [] }).split("\n").slice(4).join("\n").trim(),
      })),
      externalClassRefs: d.objc.externalClassRefs,
      selectorCount: d.objc.selectorRefs.length,
      methodListFormats: d.objc.methodListFormats,
      header: objcHeader,
    },
    swift: { ...d.swift, interface: renderSwiftInterface(d.swift) },
    symbols: {
      total: d.symbols.total,
      stripped: d.symbols.stripped,
      importsByLibrary: d.symbols.importsByLibrary.map((g) => ({ library: g.library, count: g.count, symbols: g.symbols.map(dm) })),
      exports: d.symbols.exports.map((e) => ({ ...dm(e.name), address: e.address ?? null, reexport: e.reexport ?? null })),
      swift: d.symbols.swift,
    },
    strings: {
      counts: d.strings.counts,
      total: d.strings.total,
      findings: d.strings.findings,
      strings: d.strings.strings.slice(0, MAX_UI_STRINGS).map((s) => ({ v: s.value, s: s.source, a: s.vm })),
      truncated: d.strings.strings.length > MAX_UI_STRINGS,
    },
    limitations: d.limitations,
  };
}

export function fridaScript(mode, options) {
  return generateScript(mode, options);
}

export function demangle(symbols) {
  return symbols.map((s) => ({ symbol: s, demangled: demangleSymbol(s) }));
}

export { MODES };

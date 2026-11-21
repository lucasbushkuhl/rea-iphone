// Mach-O image model, fixups and symbols — against real linked binaries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openMachO, selectImage } from "../src/macho.js";
import { createPointerResolver, decodeChainedPointer } from "../src/macho/fixups.js";
import { readSymbols, readExports, groupImports } from "../src/macho/symbols.js";
import { FIXTURE_BIN } from "./makeFixture.js";

const load = (name) => openMachO(readFileSync(FIXTURE_BIN + name));

test("image model: segments, sections, vm<->file mapping", () => {
  const im = selectImage(load("WalletKit-chained").images);
  assert.equal(im.arch, "arm64");
  assert.equal(im.platform, "iOS");
  assert.equal(im.minOS, "15.0.0");
  assert.equal(im.imageBase, 0x100000000);
  assert.deepEqual(im.segments.map((s) => s.name), ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"]);
  const cs = im.section("__cstring", "__TEXT");
  assert.ok(cs && cs.size > 0);
  const off = im.vmToOffset(cs.addr);
  assert.equal(im.offsetToVm(off), cs.addr);
  assert.equal(im.vmToOffset(0x10), null, "__PAGEZERO is not file-backed");
  assert.equal(im.encryption.present, true);
  assert.equal(im.encryption.encrypted, false);
  assert.ok(im.chainedFixups && !im.dyldInfo);
});

test("fat binary: both slices open; selectImage prefers arm64", () => {
  const m = load("WalletKit-fat");
  assert.equal(m.kind, "fat");
  assert.deepEqual(m.images.map((i) => i.arch).sort(), ["arm64", "x86_64"]);
  assert.equal(selectImage(m.images).arch, "arm64");
  assert.equal(selectImage(m.images, "x86_64").platform, "iOSSimulator");
  assert.equal(selectImage(m.images, "arm64e"), null);
});

for (const [name, mode] of [["WalletKit-classic", "dyld-info"], ["WalletKit-chained", "chained"]]) {
  test(`fixups (${mode}): rebases resolve and external binds are named`, () => {
    const im = selectImage(load(name).images);
    const r = createPointerResolver(im);
    assert.equal(r.mode, mode);
    assert.deepEqual(r.limitations, []);
    const cl = im.section("__objc_classlist");
    const supers = [];
    for (let vm = cl.addr; vm < cl.addr + cl.size; vm += 8) {
      const cls = r.target(vm);
      assert.ok(cls > im.imageBase, "classlist entry rebases into the image");
      supers.push(r.resolve(cls + 8));
    }
    const binds = supers.filter((s) => s.kind === "bind").map((s) => s.symbol);
    assert.deepEqual(binds, ["_OBJC_CLASS_$_NSObject", "_OBJC_CLASS_$_NSObject"]);
    assert.ok(supers.some((s) => s.kind === "null"), "RelativeClass is a root class");
    const allBinds = r.enumerate().filter((l) => l.kind === "bind").map((l) => l.symbol);
    assert.ok(allBinds.includes("_$sSHMp"));
    assert.ok(allBinds.includes("___CFConstantStringClassReference"));
  });
}

test("chained pointer decoding: every supported userland format", () => {
  const base = 0x100000000;
  // DYLD_CHAINED_PTR_64 rebase: target vmaddr in low 36 bits, next=2
  let d = decodeChainedPointer(0x0010_0001_0000_c540n, 2, base);
  assert.deepEqual([d.bind, d.target, d.next], [false, 0x10000c540, 2]);
  // DYLD_CHAINED_PTR_64 bind: ordinal 3, addend 5
  d = decodeChainedPointer((1n << 63n) | (5n << 24n) | 3n, 2, base);
  assert.deepEqual([d.bind, d.ordinal, d.addend], [true, 3, 5]);
  // DYLD_CHAINED_PTR_64_OFFSET rebase: runtime offset + image base
  d = decodeChainedPointer(0x4000n, 6, base);
  assert.equal(d.target, base + 0x4000);
  // ARM64E plain rebase (vmaddr) with high8
  d = decodeChainedPointer((0x12n << 43n) | 0x100004000n, 1, base);
  assert.equal(d.bind, false);
  assert.equal(BigInt(d.target), (0x12n << 56n) | 0x100004000n);
  // ARM64E auth rebase: offset from base, key in bits 49-50
  d = decodeChainedPointer((1n << 63n) | (2n << 49n) | 0x8000n, 1, base);
  assert.deepEqual([d.bind, d.auth, d.target, d.key], [false, true, base + 0x8000, 2]);
  // ARM64E auth bind
  d = decodeChainedPointer((1n << 63n) | (1n << 62n) | 7n, 9, base);
  assert.deepEqual([d.bind, d.auth, d.ordinal], [true, true, 7]);
  // ARM64E_USERLAND24 plain bind: 24-bit ordinal, negative 19-bit addend
  d = decodeChainedPointer((1n << 62n) | (((1n << 19n) - 4n) << 32n) | 0x123456n, 12, base);
  assert.deepEqual([d.bind, d.ordinal, d.addend], [true, 0x123456, -4]);
  // ARM64E_USERLAND plain rebase is an offset
  d = decodeChainedPointer(0x4000n, 9, base);
  assert.equal(d.target, base + 0x4000);
  assert.equal(decodeChainedPointer(0n, 3, base), null, "32-bit formats are reported, not guessed");
});

test("symbols: imports by library, defined Swift symbols, export trie", () => {
  for (const name of ["WalletKit-classic", "WalletKit-chained"]) {
    const im = selectImage(load(name).images);
    const { symbols } = readSymbols(im);
    const imports = groupImports(symbols);
    const flat = imports.find((g) => g.library === "flat-lookup");
    assert.ok(flat.symbols.includes("_OBJC_CLASS_$_NSObject"));
    assert.ok(flat.symbols.includes("_$sSHMp"));
    const defined = symbols.filter((s) => s.kind === "defined").map((s) => s.name);
    assert.ok(defined.includes("_$s9WalletKit15TransferServiceCfD"));
    const ex = readExports(im).exports.map((e) => e.name);
    assert.ok(ex.includes("_main"), `${name} exports _main`);
    assert.ok(ex.includes("_$s9WalletKit7AccountVMn"));
    const main = readExports(im).exports.find((e) => e.name === "_main");
    assert.ok(main.address > im.imageBase);
  }
});

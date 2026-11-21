// Deep static analysis of one Mach-O image: Objective-C class-dump, Swift
// metadata, symbols (imports by library, exports, demangled Swift symbols),
// and classified strings. One fixup resolver is shared by every layer.

import { createPointerResolver } from "./macho/fixups.js";
import { readSymbols, readExports, groupImports } from "./macho/symbols.js";
import { dumpObjC } from "./objc.js";
import { dumpSwift } from "./swift/metadata.js";
import { demangleSymbol, isSwiftSymbol } from "./swift/demangle.js";
import { extractStrings } from "./strings.js";

export function deepAnalyze(image, options = {}) {
  const resolver = createPointerResolver(image);
  // Each layer fails independently: a malformed structure in one never
  // prevents the others from reporting.
  const layer = (name, fn, empty) => {
    try {
      return fn();
    } catch (err) {
      return { ...empty, limitations: [`${name} analysis failed on malformed data: ${err.message}`] };
    }
  };
  const objc = layer("Objective-C", () => dumpObjC(image, { resolver }), { classes: [], categories: [], protocols: [], externalClassRefs: [], selectorRefs: [], methodListFormats: [] });
  const swift = layer("Swift metadata", () => dumpSwift(image, { resolver }), { types: [], protocols: [], conformances: [] });
  const syms = layer("Symbol table", () => readSymbols(image), { symbols: [], stabCount: 0 });
  const exps = layer("Export trie", () => readExports(image), { exports: [] });
  const strings = layer("String", () => extractStrings(image, { resolver, minLength: options.minStringLength ?? 4 }), { counts: {}, total: 0, strings: [], findings: {} });

  const swiftSymbols = [];
  let demangled = 0;
  for (const s of syms.symbols) {
    if (!isSwiftSymbol(s.name)) continue;
    const d = demangleSymbol(s.name);
    if (d) demangled++;
    swiftSymbols.push({ name: s.name, demangled: d, kind: s.kind });
  }

  return {
    fixups: { mode: resolver.mode, formats: resolver.formats, imports: resolver.imports?.length ?? null },
    objc,
    swift,
    symbols: {
      total: syms.symbols.length,
      debugStabs: syms.stabCount,
      defined: syms.symbols.filter((s) => s.kind === "defined").length,
      importsByLibrary: groupImports(syms.symbols),
      exports: exps.exports,
      swift: { total: swiftSymbols.length, demangled, symbols: swiftSymbols },
      stripped: syms.symbols.filter((s) => s.kind === "defined" && !s.external).length === 0,
    },
    strings,
    limitations: [...new Set([...resolver.limitations, ...objc.limitations, ...swift.limitations, ...syms.limitations, ...exps.limitations, ...strings.limitations])],
  };
}

/** Compact, bounded summary for reports and tool output. */
export function summarizeDeep(d, { maxList = 25 } = {}) {
  const cap = (arr) => (arr.length > maxList ? [...arr.slice(0, maxList), `… +${arr.length - maxList} more`] : arr);
  return {
    fixups: d.fixups,
    objc: {
      classes: d.objc.classes.length,
      categories: d.objc.categories.length,
      protocols: d.objc.protocols.length,
      methods: d.objc.classes.reduce((n, c) => n + c.instanceMethods.length + c.classMethods.length, 0)
        + d.objc.categories.reduce((n, c) => n + c.instanceMethods.length + c.classMethods.length, 0),
      method_list_formats: d.objc.methodListFormats,
      class_names: cap(d.objc.classes.map((c) => c.swiftName ?? c.name)),
      external_classes: cap(d.objc.externalClassRefs.map((c) => c.name)),
    },
    swift: {
      types: d.swift.types.length,
      protocols: d.swift.protocols.length,
      conformances: d.swift.conformances.length,
      type_names: cap(d.swift.types.map((t) => `${t.kind} ${t.fullName}`)),
      demangled_symbols: `${d.symbols.swift.demangled}/${d.symbols.swift.total}`,
    },
    symbols: {
      total: d.symbols.total,
      stripped: d.symbols.stripped,
      exports: d.symbols.exports.length,
      imports_by_library: d.symbols.importsByLibrary.map((g) => ({ library: g.library, count: g.count })),
    },
    strings: {
      counts: d.strings.counts,
      findings: Object.fromEntries(Object.entries(d.strings.findings).map(([k, v]) => [k, cap(v.map((f) => f.value))])),
    },
  };
}

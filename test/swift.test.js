// Swift demangler and reflection-metadata reader.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openMachO, selectImage } from "../src/macho.js";
import { demangleSymbol, demangleType, demangleObjCRuntimeName } from "../src/swift/demangle.js";
import { dumpSwift, renderSwiftInterface } from "../src/swift/metadata.js";
import { FIXTURE_BIN } from "./makeFixture.js";

const SYMBOLS = [
  ["_$s9WalletKit7AccountV7balanceSdvg", "WalletKit.Account.balance.getter : Swift.Double"],
  ["_$s9WalletKit7AccountV7balanceSdvs", "WalletKit.Account.balance.setter : Swift.Double"],
  ["_$s9WalletKit7AccountV5ownerSSvM", "WalletKit.Account.owner.modify : Swift.String"],
  ["_$s9WalletKit7AccountV2id5owner7balanceACSi_SSSdtcfC", "WalletKit.Account.init(id: Swift.Int, owner: Swift.String, balance: Swift.Double) -> WalletKit.Account"],
  ["_$s9WalletKit7AccountVMa", "type metadata accessor for WalletKit.Account"],
  ["_$s9WalletKit7AccountVMn", "nominal type descriptor for WalletKit.Account"],
  ["_$s9WalletKit15TransferServiceC4send6amountySd_tF", "WalletKit.TransferService.send(amount: Swift.Double) -> ()"],
  ["_$s9WalletKit15TransferServiceC5fetch3url7timeoutSSSgSS_SdtYaKF", "WalletKit.TransferService.fetch(url: Swift.String, timeout: Swift.Double) async throws -> Swift.String?"],
  ["_$s9WalletKit15TransferServiceCACycfC", "WalletKit.TransferService.__allocating_init() -> WalletKit.TransferService"],
  ["_$s9WalletKit15TransferServiceCfD", "WalletKit.TransferService.__deallocating_deinit"],
  ["_$s9WalletKit0A5ErrorO11descriptionSSvg", "WalletKit.WalletError.description.getter : Swift.String"],
  ["_$s9WalletKit15TransferServiceCAA12TransferablePAAMc", "protocol conformance descriptor for WalletKit.TransferService : WalletKit.Transferable in WalletKit"],
  ["_$sSHMp", "protocol descriptor for Swift.Hashable"],
  ["$s4main3fooyyF", "main.foo() -> ()"],
  ["$s4main3fooyySiF", "main.foo(Swift.Int) -> ()"],
  ["$s4main3foo1xySi_tF", "main.foo(x: Swift.Int) -> ()"],
  ["$s4main3foo_1yySi_SStF", "main.foo(_: Swift.Int, y: Swift.String) -> ()"],
  ["$s4main3FooCACycfc", "main.Foo.init() -> main.Foo"],
  ["$s4main3FooVACycfC", "main.Foo.init() -> main.Foo"],
  ["$s4main3FooCfd", "main.Foo.deinit"],
  ["$s4main3FooCN", "type metadata for main.Foo"],
  ["$s4main3barSaySiGvp", "main.bar : [Swift.Int]"],
  ["$s4main3FooC3runyyFTo", "@objc main.Foo.run() -> ()"],
  ["$sSo8NSObjectCMa", "type metadata accessor for __C.NSObject"],
  ["$s4main3bazSDySSSaySiGGvp", "main.baz : [Swift.String : [Swift.Int]]"],
  ["$s4main5OuterV5InnerVMn", "nominal type descriptor for main.Outer.Inner"],
];

test("demangleSymbol: canonical Swift 5 manglings", () => {
  for (const [m, want] of SYMBOLS) assert.equal(demangleSymbol(m), want, m);
});

test("demangler refuses rather than guesses", () => {
  assert.equal(demangleSymbol("_main"), null);
  assert.equal(demangleSymbol("$s4main3fooyxlF"), null, "generic signature is outside the subset");
  assert.equal(demangleSymbol("$s"), null);
  assert.equal(demangleSymbol("$s9Truncated"), null);
});

test("demangleType: reflection type strings and symbolic references", () => {
  assert.equal(demangleType("SSSg"), "Swift.String?");
  assert.equal(demangleType("SaySiG"), "[Swift.Int]");
  assert.equal(demangleType("SDySSSdG"), "[Swift.String : Swift.Double]");
  assert.equal(demangleType("Si_SSt"), "(Swift.Int, Swift.String)");
  assert.equal(demangleType("SiSgSg"), "Swift.Int??");
  const bytes = [1, 0x10, 0, 0, 0, ..."Sg"].map((c) => (typeof c === "string" ? c.charCodeAt(0) : c));
  assert.equal(demangleType(bytes, (kind, index, rel) => (kind === 1 && index === 1 && rel === 16 ? "Mod.Thing" : null)), "Mod.Thing?");
});

test("demangleObjCRuntimeName", () => {
  assert.equal(demangleObjCRuntimeName("_TtC9WalletKit15TransferService"), "WalletKit.TransferService");
  assert.equal(demangleObjCRuntimeName("_TtCC9WalletKit5Outer5Inner"), "WalletKit.Outer.Inner");
  assert.equal(demangleObjCRuntimeName("_TtP9WalletKit12Transferable_"), "WalletKit.Transferable");
  assert.equal(demangleObjCRuntimeName("Wallet"), null);
});

for (const name of ["WalletKit-classic", "WalletKit-chained", "WalletKit-fat"]) {
  test(`Swift metadata ${name}`, () => {
    const d = dumpSwift(selectImage(openMachO(readFileSync(FIXTURE_BIN + name)).images));
    assert.deepEqual(d.limitations, []);
    assert.deepEqual(d.types.map((t) => `${t.kind} ${t.fullName}`), ["struct WalletKit.Account", "class WalletKit.TransferService", "class WalletKit.PremiumService", "enum WalletKit.TransferState"]);
    const [acct, svc, prem, state] = d.types;
    assert.equal(acct.module, "WalletKit");
    assert.deepEqual(acct.fields, [
      { name: "id", type: "Swift.Int", isVar: false },
      { name: "owner", type: "Swift.String", isVar: false },
      { name: "balance", type: "Swift.Double", isVar: true },
      { name: "nickname", type: "Swift.String?", isVar: true },
    ]);
    assert.deepEqual(svc.fields.map((f) => f.type), ["Swift.String", "Swift.Int", "WalletKit.Account", "[Swift.Int]", "[Swift.String : Swift.Double]"]);
    assert.equal(svc.superclass, null);
    assert.equal(prem.superclass, "WalletKit.TransferService");
    assert.deepEqual(prem.fields.map((f) => `${f.name}: ${f.type}`), ["tier: Swift.Int", "backup: WalletKit.Account?"]);
    assert.deepEqual(state.cases, [
      { name: "failed", payload: "Swift.String", indirect: false },
      { name: "pending", payload: null, indirect: false },
      { name: "completed", payload: null, indirect: false },
    ]);
    assert.equal(state.payloadCases, 1);
    assert.equal(state.emptyCases, 2);
    assert.deepEqual(d.protocols.map((p) => p.fullName), ["WalletKit.Transferable"]);
    assert.deepEqual(d.conformances.map((c) => [c.type, c.protocol, c.typeReference, c.protocolExternal]), [
      ["WalletKit.TransferService", "WalletKit.Transferable", "direct-type-descriptor", false],
      ["WalletKit.TransferService", "Swift.Hashable", "direct-type-descriptor", true],
      ["Wallet", "WalletKit.Transferable", "direct-objc-class-name", false],
    ]);
    const iface = renderSwiftInterface(d);
    assert.match(iface, /class WalletKit\.PremiumService : WalletKit\.TransferService \{\n {2}let tier: Swift\.Int\n {2}var backup: WalletKit\.Account\?\n\}/);
    assert.match(iface, /case failed\(Swift\.String\)/);
  });
}

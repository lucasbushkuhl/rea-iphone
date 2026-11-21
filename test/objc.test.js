// Objective-C class-dump — verified against llvm-objdump --objc-meta-data
// ground truth for the fixture, across classic, chained and fat binaries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openMachO, selectImage } from "../src/macho.js";
import { dumpObjC, renderObjCHeader, decodeType, methodDeclaration, propertyDeclaration } from "../src/objc.js";
import { FIXTURE_BIN } from "./makeFixture.js";

const dump = (name) => dumpObjC(selectImage(openMachO(readFileSync(FIXTURE_BIN + name)).images));

for (const name of ["WalletKit-classic", "WalletKit-chained", "WalletKit-fat"]) {
  test(`class-dump ${name}: classes, methods, ivars, properties`, () => {
    const d = dump(name);
    assert.deepEqual(d.limitations, []);
    assert.deepEqual(d.classes.map((c) => c.name), ["Wallet", "_TtC9WalletKit15TransferService", "RelativeClass"]);

    const w = d.classes[0];
    assert.equal(w.superclass, "NSObject");
    assert.equal(w.superclassExternal, true);
    assert.deepEqual(w.protocols, ["Greeter"]);
    assert.deepEqual(w.instanceMethods.map((m) => m.selector), ["mood", "deposit:", "transferTo:amount:error:", "greet", "balance", "setBalance:", "owner", "setOwner:"]);
    assert.deepEqual(w.classMethods.map((m) => m.selector), ["instanceCount", "sharedWallet"]);
    assert.equal(w.instanceMethods[2].types, "B40@0:8@16d24^@32");
    assert.equal(w.instanceMethods[2].declaration, "- (_Bool)transferTo:(id)arg1 amount:(double)arg2 error:(id *)arg3;");
    assert.equal(w.instanceMethods[3].declaration, "- (const char *)greet;");
    const text = selectImage(openMachO(readFileSync(FIXTURE_BIN + name)).images).section("__text", "__TEXT");
    for (const m of [...w.instanceMethods, ...w.classMethods, ...d.classes[2].instanceMethods]) {
      const imp = parseInt(m.imp, 16);
      assert.ok(imp >= text.addr && imp < text.addr + text.size, `${m.selector} IMP ${m.imp} lies in __text`);
    }
    assert.deepEqual(w.ivars.map((i) => [i.name, i.offset]), [["_balance", 0], ["_owner", 8], ["_flags", 16], ["_location", 24]]);
    assert.equal(w.ivars[1].declaration, "NSString *_owner;");
    assert.equal(w.ivars[2].declaration, "unsigned char _flags[4];");
    assert.deepEqual(w.properties.map((p) => p.attributes), ["Tq,N,V_balance", 'T@"NSString",C,N,V_owner', "Ti,R,N"]);
    assert.equal(w.properties[1].declaration, "@property (nonatomic, copy) NSString *owner; // @synthesize owner=_owner");
    assert.equal(w.classProperties[0].declaration, "@property (class, nonatomic, readonly) int instanceCount;");

    const s = d.classes[1];
    assert.equal(s.swiftName, "WalletKit.TransferService");
    assert.equal(s.isSwift, true);

    const r = d.classes[2];
    assert.equal(r.superclass, null, "root class");
    assert.deepEqual(r.flags, ["root"]);
    assert.deepEqual(r.instanceMethods.map((m) => [m.selector, m.types]), [["ping", "v16@0:8"], ["pongWith:", "@24@0:8@16"]]);
    assert.deepEqual(r.classMethods.map((m) => m.selector), ["make"]);
    assert.deepEqual(d.methodListFormats.sort(), ["pointer", "relative"]);
  });

  test(`class-dump ${name}: categories, protocols, refs`, () => {
    const d = dump(name);
    const audit = d.categories.find((c) => c.name === "Audit");
    assert.equal(audit.class, "Wallet");
    assert.equal(audit.classExternal, false);
    assert.deepEqual(audit.instanceMethods.map((m) => m.selector), ["audit"]);
    assert.deepEqual(audit.classMethods.map((m) => m.selector), ["resetAuditLog"]);
    const tel = d.categories.find((c) => c.name === "Telemetry");
    assert.equal(tel.class, "NSObject");
    assert.equal(tel.classExternal, true, "category target resolved through a bind");
    const g = d.protocols.find((p) => p.name === "Greeter");
    assert.deepEqual(g.instanceMethods.map((m) => m.selector), ["greet"]);
    assert.deepEqual(g.optionalInstanceMethods.map((m) => m.selector), ["wave:", "mood"]);
    assert.equal(g.properties[0].name, "mood");
    assert.deepEqual(d.externalClassRefs.map((c) => c.name), ["NSObject"]);
    assert.ok(d.selectorRefs.includes("pongWith:"));
  });
}

test("header rendering is identical regardless of fixup format", () => {
  const strip = (h) => h;
  assert.equal(strip(renderObjCHeader(dump("WalletKit-classic"))), strip(renderObjCHeader(dump("WalletKit-chained"))));
  const h = renderObjCHeader(dump("WalletKit-chained"));
  assert.match(h, /@interface Wallet : NSObject <Greeter>/);
  assert.match(h, /@interface NSObject \(Telemetry\)/);
  assert.match(h, /\/\/ Swift class WalletKit\.TransferService/);
  assert.match(h, /@optional\n- \(void\)wave:\(int\)arg1;/);
});

test("type-encoding decoder", () => {
  assert.equal(decodeType("@\"NSString\"").type, "NSString *");
  assert.equal(decodeType("@\"<Greeter>\"").type, "id<Greeter>");
  assert.equal(decodeType("@?").type, "id /* block */");
  assert.equal(decodeType("^{CGRect=}").type, "struct CGRect *");
  assert.equal(decodeType("r^v").type, "const void *");
  assert.equal(decodeType("[16C]").decl("buf"), "unsigned char buf[16]");
  assert.equal(decodeType("b3").decl("bits"), "unsigned int bits : 3");
  assert.equal(decodeType("{GeoPoint=\"lat\"d\"lon\"d}").type, "struct GeoPoint");
  assert.equal(methodDeclaration("initWithFrame:", "@48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16", false), "- (id)initWithFrame:(struct CGRect)arg1;");
  assert.equal(propertyDeclaration("delegate", "T@\"<Greeter>\",W,N,V_delegate"), "@property (nonatomic, weak) id<Greeter> delegate; // @synthesize delegate=_delegate");
  assert.equal(propertyDeclaration("name", "T@\"NSString\",R,C,N,Gfullname"), "@property (nonatomic, readonly, copy, getter=fullname) NSString *name;");
});

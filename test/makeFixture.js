// Builds a synthetic but structurally valid iOS app fixture:
//  - a hand-crafted thin arm64 Mach-O executable (iOS, FairPlay cryptid=1,
//    a __swift5_types section, LC_LOAD_DYLIB, LC_BUILD_VERSION, UUID, code sig)
//    with an entitlements XML plist appended (simulating the signature blob)
//  - an XML Info.plist
//  - an embedded.mobileprovision (CMS-wrapped XML plist, here just the plist)
//  - a Frameworks/Flutter.framework marker (runtime-family hint)
// Produces both a Payload/Demo.app directory and a Demo.ipa (deflated zip).

import { mkdirSync, writeFileSync, rmSync, readdirSync, statSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { deflateRawSync, crc32 } from "node:zlib";

const LE = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const pad8 = (buf) => { const r = buf.length % 8; return r ? Buffer.concat([buf, Buffer.alloc(8 - r)]) : buf; };

function fixedStr(s, len) { const b = Buffer.alloc(len); b.write(s, 0, "utf8"); return b; }

export function buildMachO() {
  // --- Header (filled in after commands) ---
  const cmds = [];

  // LC_SEGMENT_64 __TEXT with one section __swift5_types
  {
    const section = Buffer.concat([
      fixedStr("__swift5_types", 16), // sectname
      fixedStr("__TEXT", 16), // segname
      Buffer.alloc(8), Buffer.alloc(8), // addr, size
      Buffer.alloc(4), Buffer.alloc(4), // offset, align
      Buffer.alloc(4), Buffer.alloc(4), // reloff, nreloc
      Buffer.alloc(4), Buffer.alloc(4), Buffer.alloc(4), Buffer.alloc(4), // flags, reserved1/2/3
    ]);
    const body = Buffer.concat([
      fixedStr("__TEXT", 16),
      Buffer.alloc(8), Buffer.alloc(8), Buffer.alloc(8), Buffer.alloc(8), // vmaddr,vmsize,fileoff,filesize
      LE(7), LE(5), // maxprot, initprot
      LE(1), LE(0), // nsects, flags
      section,
    ]);
    cmds.push(Buffer.concat([LE(0x19), LE(8 + body.length), body]));
  }

  // LC_ENCRYPTION_INFO_64 (cryptid=1 => FairPlay encrypted)
  cmds.push(Buffer.concat([LE(0x2c), LE(24), LE(0x4000), LE(0x100000), LE(1), LE(0)]));

  // LC_LOAD_DYLIB libSystem
  {
    const name = Buffer.from("/usr/lib/libSystem.B.dylib\0", "utf8");
    const fixed = Buffer.concat([LE(24), LE(0x010000), LE(0x010000)]); // name.offset(24),ts? -> see below
    // dylib_command: cmd,cmdsize,name.offset,timestamp,current_version,compat_version
    const pre = Buffer.concat([LE(24), LE(2), LE(0x010000), LE(0x010000)]); // name.offset=24, ts=2, cur, compat
    const payload = pad8(Buffer.concat([pre, name]));
    cmds.push(Buffer.concat([LE(0xc), LE(8 + payload.length), payload]));
    void fixed;
  }

  // LC_BUILD_VERSION platform=iOS(2) minos=14.0 sdk=17.0 ntools=0
  cmds.push(Buffer.concat([LE(0x32), LE(24), LE(2), LE((14 << 16)), LE((17 << 16)), LE(0)]));

  // LC_UUID
  cmds.push(Buffer.concat([LE(0x1b), LE(24), Buffer.from("0123456789abcdef", "utf8")]));

  // LC_CODE_SIGNATURE
  cmds.push(Buffer.concat([LE(0x1d), LE(16), LE(0x200000), LE(0x4000)]));

  const cmdsBuf = Buffer.concat(cmds);
  const header = Buffer.concat([
    LE(0xfeedfacf), // magic MH_64 (LE)
    LE(0x0100000c), // cputype arm64
    LE(0), // cpusubtype
    LE(2), // filetype MH_EXECUTE
    LE(cmds.length), // ncmds
    LE(cmdsBuf.length), // sizeofcmds
    LE(0), // flags
    LE(0), // reserved
  ]);

  // Append an entitlements plist to simulate the __LINKEDIT code-signature blob.
  const entitlements = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>application-identifier</key><string>ABCDE12345.com.example.demo</string>
<key>get-task-allow</key><true/>
<key>com.apple.developer.team-identifier</key><string>ABCDE12345</string>
<key>keychain-access-groups</key><array><string>ABCDE12345.com.example.demo</string></array>
</dict></plist>`, "utf8");

  return Buffer.concat([header, cmdsBuf, Buffer.alloc(64), entitlements]);
}

const INFO_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.demo</string>
  <key>CFBundleName</key><string>Demo</string>
  <key>CFBundleDisplayName</key><string>Demo App</string>
  <key>CFBundleExecutable</key><string>Demo</string>
  <key>CFBundleShortVersionString</key><string>2.4.1</string>
  <key>CFBundleVersion</key><string>2041</string>
  <key>MinimumOSVersion</key><string>14.0</string>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
  <key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
  <key>CFBundleURLTypes</key><array><dict>
    <key>CFBundleURLSchemes</key><array><string>demoapp</string><string>example</string></array>
  </dict></array>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>`;

const MOBILEPROVISION = `signed-cms-wrapper-bytes-ignored
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Name</key><string>Demo Development Profile</string>
  <key>AppIDName</key><string>Demo</string>
  <key>TeamName</key><string>Example Inc.</string>
  <key>TeamIdentifier</key><array><string>ABCDE12345</string></array>
  <key>CreationDate</key><date>2025-01-01T00:00:00Z</date>
  <key>ExpirationDate</key><date>2027-01-01T00:00:00Z</date>
  <key>Platform</key><array><string>iOS</string></array>
  <key>ProvisionedDevices</key><array><string>00008030-XXXX</string><string>00008110-YYYY</string></array>
  <key>Entitlements</key><dict>
    <key>application-identifier</key><string>ABCDE12345.com.example.demo</string>
    <key>get-task-allow</key><true/>
    <key>aps-environment</key><string>development</string>
  </dict>
</dict></plist>
trailer-bytes-ignored`;

export function writeAppDir(root) {
  rmSync(root, { recursive: true, force: true });
  const app = join(root, "Payload", "Demo.app");
  mkdirSync(join(app, "Frameworks", "Flutter.framework"), { recursive: true });
  writeFileSync(join(app, "Demo"), buildMachO());
  writeFileSync(join(app, "Info.plist"), INFO_PLIST);
  writeFileSync(join(app, "embedded.mobileprovision"), MOBILEPROVISION);
  writeFileSync(join(app, "Frameworks", "Flutter.framework", "Flutter"), buildMachO());
  return app;
}

// Minimal deflate zip writer (method 8), enough for readZip to parse.
export function writeIpa(appRootDir, ipaPath) {
  const files = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const f = join(d, n);
      if (statSync(f).isDirectory()) walk(f);
      else files.push(f);
    }
  };
  walk(appRootDir);

  const chunks = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = relative(appRootDir, f).split(sep).join("/");
    const data = readFileSync(f);
    const comp = deflateRawSync(data);
    const crc = crc32(data) >>> 0;
    const nameBuf = Buffer.from(name, "utf8");

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(8, 8); // method deflate
    local.writeUInt32LE(0, 10); // time/date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, nameBuf, comp);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0, 8); cen.writeUInt16LE(8, 10);
    cen.writeUInt32LE(0, 12);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(comp.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cen, nameBuf]));

    offset += local.length + nameBuf.length + comp.length;
  }

  const cdBuf = Buffer.concat(central);
  const cdOffset = offset;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);

  writeFileSync(ipaPath, Buffer.concat([...chunks, cdBuf, eocd]));
  return ipaPath;
}

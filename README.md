# REA-iPhone — Reverse Engineer Anything, iPhone edition

**See a feature in an iPhone app. Understand how it works, down to the binary.**

REA-iPhone is the iOS counterpart to [REA](https://github.com/morluto/rea)'s
Android provider: one toolkit, usable from the terminal or by an AI agent over
MCP, that takes an iOS app apart and returns **evidence** — every fact says how
it was derived and what its limits are.

| Layer | What you get |
| --- | --- |
| **Static analysis** (execution-free) | Bundle identity, Info.plist, Mach-O slices, FairPlay state, entitlements, provisioning, frameworks, app extensions, runtime families, third-party SDKs |
| **Objective-C class-dump** | Classes, metaclasses, categories, protocols, ivars, properties, method type signatures and IMP addresses, rendered as a class-dump header |
| **Swift metadata** | Structs/classes/enums with stored properties or cases and their types, superclasses, protocols, conformances, rendered as Swift declarations |
| **Swift demangler** | `$s…` symbols to readable signatures (`WalletKit.TransferService.fetch(url: Swift.String, timeout: Swift.Double) async throws -> Swift.String?`) |
| **Symbols & fixups** | Imports grouped by library, exports, every dyld bind site; classic *and* chained fixups |
| **Strings** | C strings, NSString literals, selectors, Swift reflection strings, classified into endpoints, embedded credentials, jailbreak-detection and TLS-pinning indicators |
| **Device layer** | The `adb` analog over libimobiledevice: devices, device info, installed apps, bounded syslog capture, crash-report pull + summaries |
| **Frida bridge** | Runtime observation: ObjC method tracing with type-aware argument decoding, native export tracing, HTTP/DNS observation, runtime class listing |
| **MCP server** | All of the above as 14 typed tools for Claude Code, Codex, Cursor, Claude Desktop |

Zero dependencies. Node 20+. MIT.

## Signal Sweep: find trackers and hidden cameras (web app)

`scanner/` is **Signal Sweep**, a counter-surveillance web app for your
phone. Add it to your home screen; there's no App Store involved. It runs
entirely on the device.

| Tool | What it does | Where it works |
| --- | --- | --- |
| Bluetooth trackers | Live scan that identifies AirTags and Find My trackers away from their owner, Tile, Samsung SmartTag, Google Find My Device tags and Chipolo, ranked by concern. Devices that stay near you are flagged. A hot/cold finder with a rising tone walks you to one. | iPhone: in the free **Bluefy** browser (Safari has no Bluetooth). Android, Mac, PC: Chrome with *Experimental Web Platform features* on. |
| Lens finder | Marks the small, steady, sharp reflections a hidden camera lens throws back; red-filter view and flashlight toggle. | Any phone browser |
| Infrared finder | Marks the infrared LEDs of night-vision cameras, with a TV-remote test so you know whether your camera can see infrared. | Any phone browser |
| Wi-Fi names | Flags network names that budget spy cameras broadcast (IPC-, V380, Yoosee, HD-CAM…). You read the names from Settings › Wi-Fi. | Anywhere |
| Sweep checklist | Room, car, and bag checklists, saved on the phone. | Anywhere |

What no phone can do, which the app says plainly: list Wi-Fi networks on
iPhone (Apple blocks it for every app), and detect raw radio frequencies
(phones have no receiver apps can read; use a handheld RF detector).

Tracker identification follows public research and Bluetooth SIG assigned
numbers (Heinrich et al., PETS 2021; the AirGuard project). It's covered by
unit tests on real advertisement bytes. An end-to-end test drives the app in
Chromium with a simulated Bluetooth radio, and feeds the lens finder a camera
video containing a lens glint.

After GitHub Pages is enabled (below), Signal Sweep is at
`https://<user>.github.io/rea-iphone/scanner/`.

## Use it on your iPhone (web app, no App Store)

The static analysis also runs as a **web app you add to your home screen**.
There is no App Store listing, no developer account, and no cost. Everything
runs inside Safari on the phone. The `.ipa` you open is read in place and
never uploaded.

1. Open the web app in Safari (see *Hosting* below for the link).
2. Tap **Share › Add to Home Screen**.
3. Open it from the home screen and tap **Open app** to pick an `.ipa`, a
   zipped `.app`, or a Mach-O binary from the Files app, iCloud Drive, or a
   download.

You get the same analysis as the command line: overview and security
findings, the Objective-C class-dump, Swift types, classified strings,
symbols, a Frida script builder, and a Swift demangler. You can switch between
the app, its frameworks and its extensions, and between architecture slices.

How it handles large apps on a phone:

- It reads the `.ipa`'s ZIP index from the end of the file. It then
  decompresses **only the files it needs** (bundle metadata plus the selected
  binary), using Safari's built-in decompressor, so a 300 MB app costs
  about the size of its main binary.
- Analysis runs in a background Web Worker, so scrolling stays smooth.
- After the first visit it works **offline** (service worker).

The device and Frida *runner* layers need a computer: a browser can't drive a
phone over USB. The web app writes the Frida script and the exact command for
you to run there.

### Hosting

- **GitHub Pages (free, installable, offline):** Pages is free for *public*
  repositories. Make the repository public, then set **Settings › Pages ›
  Source: GitHub Actions**. Every push to `main` runs the tests and deploys
  `https://<user>.github.io/rea-iphone/`. The workflow skips deploying while
  the repository is private.
- **Any static host:** `npm run build:web` writes the site to `site/`.
  Upload that folder anywhere that serves static files over HTTPS.
- **Locally:** `npm run serve:web`, then open http://127.0.0.1:8080/.

```bash
git clone https://github.com/lucasbushkuhl/rea-iphone && cd rea-iphone
node bin/rea-iphone.js analyze examples/Demo.ipa --deep
```

---

## Quick start

```bash
# Everything at once
rea-iphone analyze MyApp.ipa --deep

# Objective-C headers, like class-dump
rea-iphone classdump MyApp.ipa > MyApp.h
rea-iphone classdump MyApp.ipa --filter 'Payment|Wallet'

# Swift types, recovered from reflection metadata
rea-iphone swift MyApp.ipa

# Endpoints, embedded keys, integrity checks, pinning
rea-iphone strings MyApp.ipa
rea-iphone strings MyApp.ipa --all --filter 'api\.'

# What does it call, and from where?
rea-iphone symbols MyApp.ipa                 # imports grouped by library
rea-iphone symbols MyApp.ipa --exports
rea-iphone fixups  MyApp.ipa --binds

# Any binary inside the app, any slice of a fat binary
rea-iphone classdump MyApp.ipa --binary Flutter.framework/Flutter
rea-iphone swift     MyApp.ipa --binary PlugIns/Widget.appex/Widget --arch arm64

rea-iphone demangle '$s9WalletKit7AccountV7balanceSdvg'
#  -> WalletKit.Account.balance.getter : Swift.Double
```

`TARGET` is an `.ipa`, an unpacked `.app` directory, or a bare Mach-O file.
Add `--json` to any command for structured output.

### What the class-dump looks like

From a real linked arm64 binary (`test/fixtures/bin/WalletKit-chained`):

```objc
@interface Wallet : NSObject <Greeter>
{
    long long _balance; // +0
    NSString *_owner; // +8
    unsigned char _flags[4]; // +16
    struct GeoPoint _location; // +24
}

@property (class, nonatomic, readonly) int instanceCount;
@property (nonatomic, copy) NSString *owner; // @synthesize owner=_owner

+ (id)sharedWallet; // IMP 0x100004018
- (void)deposit:(long long)arg1; // IMP 0x100004048
- (_Bool)transferTo:(id)arg1 amount:(double)arg2 error:(id *)arg3; // IMP 0x100004074
@end

@interface NSObject (Telemetry)
- (void)rea_trackEvent:(id)arg1; // IMP 0x100004188
@end
```

### …and the Swift metadata

```swift
struct WalletKit.Account {
  let id: Swift.Int
  let owner: Swift.String
  var balance: Swift.Double
  var nickname: Swift.String?
}

class WalletKit.PremiumService : WalletKit.TransferService {
  let tier: Swift.Int
  var backup: WalletKit.Account?
}

enum WalletKit.TransferState {
  case failed(Swift.String)
  case pending
  case completed
}

extension WalletKit.TransferService : Swift.Hashable {}
extension Wallet : WalletKit.Transferable {} // Objective-C class
```

---

## Use it from an agent (MCP)

```bash
rea-iphone setup        # prints the exact commands for your machine
claude mcp add rea-iphone -- node /path/to/rea-iphone/bin/rea-iphone.js mcp
```

Then ask your agent things like:

> Analyze ~/Downloads/MyApp.ipa deeply. How does it talk to its backend? Show me
> the classes involved and the evidence, then sketch how I'd build the same
> feature in my app.

| Tool | Purpose |
| --- | --- |
| `analyze_ios_application` | Full report; `deep: true` adds every static layer |
| `dump_objc_classes` | class-dump header or JSON, regex filter |
| `dump_swift_types` | Swift declarations or JSON |
| `extract_strings` | Classified findings, optional raw strings with filter/limit |
| `list_symbols` | Imports / exports / defined symbols, demangled |
| `inspect_fixups` | Fixup format, imports, bind sites |
| `demangle_swift` | Batch demangling |
| `list_ios_devices`, `ios_device_info`, `list_installed_apps` | Device inventory |
| `capture_device_syslog`, `pull_crash_reports` | Device diagnostics |
| `generate_frida_script`, `run_frida_session` | Runtime observation |

The server speaks MCP 2024-11-05 through 2025-06-18 over stdio, validates every
argument against the tool's JSON Schema, bounds output size, and reports tool
failures as `isError` results.

---

## Device layer

Requires [libimobiledevice](https://libimobiledevice.org/) and
`ideviceinstaller` (`brew install libimobiledevice ideviceinstaller`). It only
talks to devices that are **paired** with your computer, which iOS makes the
device owner approve on screen ("Trust This Computer?").

```bash
rea-iphone device list
rea-iphone device info
rea-iphone device apps --type user
rea-iphone device syslog --process MyApp --seconds 30
rea-iphone device crashes --out ./crashes --filter MyApp
```

Each result records the exact command it ran. Syslog capture is bounded
(1–300 s, line caps); crash reports are copied (kept on the device) and
summarized: exception, termination reason, top frames of the faulting thread.
Tools are found on `PATH` or in `REA_IPHONE_TOOLS_DIR`. Both the classic and
the newer `ideviceinstaller` command syntaxes are supported.

## Frida bridge

Requires `frida-tools` on your computer (`pip install frida-tools`) and
`frida-server` (or a Frida gadget in your own build) on a device you control.

```bash
# What does tapping "Pay" actually call?
rea-iphone frida run objc-trace --bundle com.example.myapp \
    --pattern '-[PaymentController *]' --pattern '+[APIClient *]' --seconds 30

# Which endpoints does the app hit?  (credential headers redacted by default)
rea-iphone frida run network --bundle com.example.myapp --seconds 60

# Classes as they exist at runtime (works even if the file on disk is encrypted)
rea-iphone frida run classes --bundle com.example.myapp --attach

# Or just get the script
rea-iphone frida script objc-trace --pattern '-[NSURLSession *]' --out trace.js
```

Modes: `objc-trace`, `native-trace`, `network`, `classes`, `modules`.

The scripts only **observe**. They don't patch behavior or bypass protections.
`objc-trace` reads each hooked method's real type encoding from the ObjC
runtime, so it decodes objects, selectors, C strings, BOOLs and exact signed
64-bit integers instead of guessing which arguments are objects (guessing is
what crashes target processes). Event counts are capped per hook and globally.
The scripts run on both Frida 16 and Frida 17.

---

## The things that make or break iOS reverse engineering

**FairPlay.** App Store binaries are encrypted (`LC_ENCRYPTION_INFO`
`cryptid = 1`). REA-iPhone detects this and says so. In an encrypted binary,
strings, selectors and Swift metadata in `__TEXT` can't be read, and the tool
reports that rather than returning noise. Class *structures* in `__DATA` are
still recovered. For full static analysis, use a build you produced yourself,
or a decrypted copy obtained from a device you own. The Frida `classes` mode
sees the decrypted app at runtime.

**Chained fixups.** Since iOS 15, almost every App Store binary stores pointers
as `LC_DYLD_CHAINED_FIXUPS` encodings rather than plain addresses. A class-dump
that reads them naively gets garbage; even `llvm-objdump --objc-meta-data`
prints the raw encoded values. REA-iPhone decodes every userland pointer format
(`DYLD_CHAINED_PTR_64`, `64_OFFSET`, `ARM64E`, `ARM64E_USERLAND`,
`ARM64E_USERLAND24`, including pointer-auth variants). It also handles classic
rebase/bind opcodes, so external superclasses and category targets resolve to
names like `NSObject`.

**Relative method lists.** Modern toolchains emit 12-byte relative method
lists. Both relative and pointer-based lists are supported.

---

## How it's verified

The test suite (`npm test`: 73 tests, a few seconds, no tools or devices needed)
runs against **real linked arm64 Mach-O binaries**, not mocks:

- `test/fixtures/src/` holds an Objective-C source file and two hand-laid
  assembly fixtures:
  - one with genuine Swift 5 metadata structures, whose relative pointers are
    resolved by the linker;
  - one with an iOS 14+ relative method-list class.
- `test/fixtures/build.sh` compiles and links them with clang and lld into
  three binaries: classic fixups, chained fixups, and a fat binary (device +
  simulator). The outputs are committed.
- The class-dump is checked against `llvm-objdump --objc-meta-data` ground
  truth, and the output is **byte-identical** across the classic, chained and
  fat binaries.
- The Swift demangler is checked against canonical manglings, including word
  substitutions, substitutions, labels, `async throws`, accessors and
  initializers.
- The Frida agents are **executed** against a mock Frida runtime: hooks are
  installed, arguments decoded, headers redacted, and caps enforced. The runner
  is driven through a real subprocess.
- The device layer runs against shim executables that reproduce
  libimobiledevice's real output formats, including the bounded syslog stream
  and the `ideviceinstaller` syntax fallback.
- The MCP server is tested at the protocol level and through a live stdio
  session.
- The web app's build is checked: no Node built-ins reach the browser bundle,
  and the PWA head and offline precache are present. The browser `Buffer` is
  compared against Node's `Buffer`. The engine runs through the same
  Blob/stream path Safari uses, and must reproduce the CLI's results,
  including the gzip fallback for browsers without raw-deflate streams. The UI
  runs in headless Chromium at iPhone size, in light and dark: it uses the
  worker, has no sideways scrolling or console errors, opens files, and
  reloads offline.
- **Robustness:** mutation fuzzing of both fixup formats, plus truncation tests
  and hostile Swift symbols. Malformed input yields limitations, never crashes,
  hangs, or unbounded work. In development fuzzing, 3,000 mutants produced zero
  crashes and none took longer than 200 ms.

## Honest limitations

- The Swift demangler covers the commonly emitted subset. Generic signatures,
  opaque types, closures and specializations return `null` (raw name kept)
  rather than a guess.
- The Objective-C class-dump supports 64-bit images, which covers every iOS 11+
  app.
- Entitlements and provisioning profiles are read from their embedded plists.
  CMS and code-signature chains are not cryptographically validated.
- Third-party SDK and runtime-family detection are static hints (framework
  paths, class prefixes). They don't prove an SDK is initialized or collecting
  data.
- The device and Frida layers are tested against faithful shims and mocks.
  Running them for real needs your device, the tools listed above, and (for
  Frida) `frida-server` or a gadget.

## Architecture

```text
src/
  target.js          .ipa / .app / Mach-O loading; main, framework, extension binaries
  zip.js             zero-dep ZIP reader (STORE, DEFLATE, Zip64)
  plist.js           binary (bplist00) and XML property lists
  macho.js           Mach-O image model: segments, sections, vm<->file, encryption
  macho/fixups.js    classic bind opcodes + chained fixups -> pointer resolver
  macho/symbols.js   nlist symbol table, export trie, imports by library
  objc.js            Objective-C class-dump + type-encoding decoder + header renderer
  swift/demangle.js  Swift 5 demangler (stack-based, like swift's Demangler.cpp)
  swift/metadata.js  Swift 5 reflection metadata reader + interface renderer
  strings.js         string extraction + security/privacy classification
  provisioning.js    embedded.mobileprovision + entitlements
  evidence.js        evidence records, runtime families, third-party SDKs
  deep.js            all static layers over one image, shared fixup resolver
  analyze.js         report orchestrator
  ips.js             Apple crash reports (.ips JSON and legacy .crash)
  device/idevice.js  libimobiledevice adapter
  frida/scripts.js   observational Frida agents
  frida/runner.js    frida CLI driver + event parser
  mcp/server.js      MCP stdio server (JSON-RPC 2.0)
  util/exec.js       safe process execution (argv only, process groups, timeouts)
  util/sha256.js     SHA-256 in plain JavaScript (Node and browsers)
  bundle.js          app-bundle logic shared by Node and the web app
  analyzeSource.js   report orchestrator (environment-independent)
web/
  index.html         the app page (mobile-first, light and dark)
  app.js             UI
  engine.js          analysis engine (runs in worker.js)
  blobzip.js         streaming ZIP access over a File, no full load
  buffer.js          the Node Buffer API subset, for browsers
  sw.js              offline cache
scripts/
  build-web.mjs      builds site/ and refuses any Node built-in in the bundle
  serve.mjs          local static server
  make-icons.mjs     generates the home-screen icons
```

Every external tool is run with an argv array, never a shell. Each tool gets
its own process group with a hard timeout, so nothing it spawns outlives the
command.

## Responsible use

For lawful work only: security research, interoperability, privacy and
supply-chain auditing, debugging, and education, on software and devices you
**own or are explicitly authorized to examine**. Don't use it to circumvent
DRM or FairPlay, defeat access controls, or tamper with other people's apps,
accounts or services. Getting decrypted binaries, device containers or runtime
access requires a device and accounts you control. You are responsible for
complying with applicable law, license agreements and Apple's terms.

## License

MIT.

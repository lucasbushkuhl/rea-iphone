# REA-iPhone — Reverse Engineer Anything, iPhone edition

Static, **execution-free**, evidence-based analysis of iOS applications
(`.ipa` archives and unpacked `.app` bundles). Built in the spirit of
[REA](https://github.com/morluto/rea): every reported fact is an *evidence
record* that states how it was derived and the limitation behind the
conclusion. Nothing from the target is ever executed.

REA ships a first-class **Android** provider (APK → JADX decompile, apktool
resources, adb device access, signature inspection) but no first-class
**iPhone/iOS** provider. This is that missing analog — the Apple-platform
counterpart — as a standalone, zero-dependency Node tool you own.

```
npx rea-iphone analyze /path/to/App.ipa
node bin/rea-iphone.js analyze /path/to/Payload/MyApp.app --json
```

## What it extracts

| Area | Facts | Source |
| --- | --- | --- |
| **Bundle identity** | bundle id, name, display name, short/build version, minimum iOS, supported platforms, required capabilities, custom URL schemes, App Transport Security `NSAllowsArbitraryLoads` | `Info.plist` (binary `bplist00` **and** XML) |
| **Mach-O (per arch slice)** | architecture (arm64/arm64e/…), 32/64-bit, file type, linked **platform + min OS + SDK**, UUID, **FairPlay encryption state** (`LC_ENCRYPTION_INFO` cryptid), code-signature presence, linked dylibs, `@rpath`s, **Swift / Objective-C** language hints | fat + thin Mach-O header & load-command parse |
| **Entitlements** | application-identifier, team-identifier, `get-task-allow`, aps-environment, app groups, keychain groups, associated domains, all keys | embedded entitlements plist in the code-signature blob |
| **Provisioning** | profile name, team, team identifiers, **distribution type** (development / ad-hoc / enterprise / app-store), `get-task-allow`, expiry (+ expired flag), provisioned device count | `embedded.mobileprovision` (embedded XML plist from the CMS container) |
| **Composition** | embedded frameworks inventory, **runtime-family hints**: Flutter, React Native (+ Hermes), Unity, Capacitor/Cordova, .NET/Xamarin/MAUI, Kotlin Native | container path conventions |

Output is a human-readable report by default, or a full evidence-linked JSON
document with `--json`.

## Why the facts matter (reverse-engineering workflow)

1. **FairPlay / cryptid** — the single most important gate. `cryptid != 0`
   means `__TEXT` is encrypted by the App Store; static strings and
   decompilation are meaningless until you have a decrypted copy dumped from a
   device *you own and are authorized to analyze*. `cryptid == 0` means it's a
   dev build or already decrypted and ready to read.
2. **Language hints** — Swift vs. Objective-C decides your tooling (Swift
   metadata demanglers vs. ObjC runtime class-dump).
3. **Runtime family** — a Flutter/React Native/Unity app means the real logic
   lives in a Dart snapshot / JS bundle / IL2CPP blob, not the Mach-O; it points
   you at the right secondary target.
4. **Entitlements + URL schemes + ATS** — the app's attack/interop surface:
   what it can talk to, what deep links it exposes, whether it allows cleartext.
5. **Provisioning** — tells you instantly whether a build is debuggable
   (`get-task-allow`), who signed it, and whether it's still valid.

## Architecture

Mirrors REA's hexagonal shape — small, pure modules behind a uniform source
abstraction, so an `.ipa` zip and an unpacked `.app` directory are analyzed by
identical code:

```
src/
  zip.js           minimal zero-dep ZIP reader (STORE + DEFLATE, Zip64 fallback)
  plist.js         binary (bplist00) + XML property-list parser
  macho.js         fat/thin Mach-O header + load-command parser
  provisioning.js  embedded.mobileprovision + entitlements extraction
  evidence.js      evidence records, SHA-256, runtime-family detection
  analyze.js       orchestrator (source -> app roots -> evidence report)
  report.js        human-readable renderer
bin/rea-iphone.js  CLI
test/              crafted arm64 Mach-O fixture + full end-to-end tests
```

Run the suite:

```
npm test          # node --test
```

The test fixture hand-crafts a structurally valid arm64 iOS Mach-O (FairPlay
cryptid=1, a `__swift5_types` section, `LC_LOAD_DYLIB`, `LC_BUILD_VERSION`,
UUID, code signature), builds a `Payload/Demo.app` and a deflated `Demo.ipa`,
and asserts the full report — so parsing is verified against real byte layouts,
not mocks.

## Roadmap (parity with REA's Android depth)

Static core is done. The natural next layers, each with the same
evidence/limitation discipline:

- **Objective-C class-dump** — walk `__objc_classlist` / `__objc_const` to
  recover class, method and protocol names (works on decrypted binaries).
- **Swift metadata** — parse `__swift5_types`/`__swift5_proto` and demangle.
- **Symbol & string projection** — nlist symbol table, `__cstring` extraction.
- **Device layer (the `adb` analog)** — a `libimobiledevice`/`ideviceinstaller`
  adapter: list installed apps, pull containers, read `syslog`, over USB, from
  devices you own.
- **Dynamic layer** — a Frida bridge for runtime tracing (REA already has a
  Frida instrumentation manager to model this on).
- **MCP server** — expose `analyze_ios_application` as an MCP tool so an agent
  can call it the way REA exposes its tools.

## Responsible use

For lawful analysis only: security research, interoperability, app-store/privacy
auditing, and analysis of software **you own or are explicitly authorized to
examine**. Do not use it to circumvent DRM/FairPlay, defeat access controls, or
analyze apps you have no right to. Obtaining decrypted binaries or device
containers requires a device and an account you control. You are responsible for
compliance with applicable law, license terms, and Apple's agreements.

## License

MIT.

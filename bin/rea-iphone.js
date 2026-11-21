#!/usr/bin/env node
// REA-iPhone CLI — static, evidence-based iOS application analysis.

import { analyze } from "../src/analyze.js";
import { renderText } from "../src/report.js";

const argv = process.argv.slice(2);

function usage() {
  process.stdout.write(`rea-iphone — reverse-engineer iPhone apps (static, execution-free)

USAGE
  rea-iphone analyze <path-to.ipa | path-to.app> [--json]
  rea-iphone --help

WHAT IT REPORTS
  • Bundle identity (Info.plist: id, name, versions, min iOS, URL schemes, ATS)
  • Mach-O facts per architecture slice: arch, platform, min OS/SDK, UUID,
    FairPlay encryption state (cryptid), code-signature presence, linked dylibs,
    Swift / Objective-C language hints
  • Code-signing entitlements (from the signature blob)
  • Embedded provisioning profile: team, distribution type, expiry, device count
  • Embedded frameworks and runtime-family hints (Flutter, React Native, Unity, …)

Every fact is an evidence record with its derivation method and limitations.
Lawful use only: analyze apps you own or are authorized to examine. FairPlay-
encrypted App Store binaries require a decrypted copy from a device you own
before static strings/decompilation are meaningful.
`);
}

async function main() {
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    usage();
    process.exit(argv.length === 0 ? 1 : 0);
  }
  const cmd = argv[0];
  if (cmd !== "analyze") {
    process.stderr.write(`unknown command: ${cmd}\n`);
    usage();
    process.exit(2);
  }
  const target = argv[1];
  if (!target) {
    process.stderr.write("analyze requires a path to an .ipa or .app\n");
    process.exit(2);
  }
  const json = argv.includes("--json");
  try {
    const report = analyze(target);
    if (json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    else process.stdout.write(`${renderText(report)}\n`);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(1);
  }
}

main();

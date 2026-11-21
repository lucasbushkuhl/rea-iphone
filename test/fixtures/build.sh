#!/usr/bin/env bash
# Rebuild the real Mach-O test fixtures from source. Requires clang + lld
# (with the Mach-O / ld64 flavor) + llvm-lipo. The prebuilt outputs in bin/
# are committed, so the test suite itself needs none of these tools.
set -euo pipefail
cd "$(dirname "$0")"
OUT=bin
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LIPO=$(command -v llvm-lipo || command -v llvm-lipo-18 || command -v lipo)

cc() { clang -target "$1" -c "$2" -o "$3"; }
link() { # out arch platform-min-version extra-flags... objects...
  local out=$1 arch=$2 plat=$3 min=$4; shift 4
  lld -flavor darwin -arch "$arch" -platform_version "$plat" "$min" 17.0 \
      -undefined dynamic_lookup -e _main -o "$out" "$@"
}

cc arm64-apple-ios14.0 src/demo.m "$TMP/demo-arm64.o"
cc arm64-apple-ios14.0 src/swiftmeta.s "$TMP/swift-arm64.o"
cc arm64-apple-ios14.0 src/objc_relative.s "$TMP/rel-arm64.o"
cc x86_64-apple-ios14.0-simulator src/demo.m "$TMP/demo-x86_64.o"

# Classic LC_DYLD_INFO rebase/bind opcodes (pre-iOS 15 style).
link "$OUT/WalletKit-classic" arm64 ios 14.0 "$TMP/demo-arm64.o" "$TMP/swift-arm64.o" "$TMP/rel-arm64.o"
# LC_DYLD_CHAINED_FIXUPS (iOS 15+ style, what modern App Store apps use).
link "$OUT/WalletKit-chained" arm64 ios 15.0 -fixup_chains "$TMP/demo-arm64.o" "$TMP/swift-arm64.o" "$TMP/rel-arm64.o"
# Simulator slice, then a universal (fat) binary of device + simulator.
link "$TMP/sim" x86_64 ios-simulator 14.0 "$TMP/demo-x86_64.o"
"$LIPO" -create "$OUT/WalletKit-chained" "$TMP/sim" -output "$OUT/WalletKit-fat"

ls -la "$OUT"

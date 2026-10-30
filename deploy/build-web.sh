#!/bin/sh
# Assembles the notary's webroot in dist-web/: the web app (apps/demo) at
# /app/, and at /dl/ the tlsnc binaries (cross-compiled with cargo-zigbuild)
# and the browser extension zip. Written for a macOS (arm64) build machine;
# deploy/deploy.sh copies the result to the server.
#
#   deploy/build-web.sh            # app + extension + binaries
#   deploy/build-web.sh --no-bin   # app + extension, keep dist-web/dl binaries
set -eu
cd "$(dirname "$0")/.."
OUT=dist-web

# tlsn needs rustc >= 1.95; Homebrew's cargo would shadow rustup's.
TOOLCHAIN="${TLSNC_TOOLCHAIN:-1.97.1}"
RUSTUP_BIN="$HOME/.rustup/toolchains/$TOOLCHAIN-$(uname -m | sed 's/arm64/aarch64/')-apple-darwin/bin"

mkdir -p "$OUT"
find "$OUT" -mindepth 1 -maxdepth 1 ! -name dl -exec rm -rf {} +
npm run build
cp -R apps/demo/dist "$OUT/app"

# The browser extension, as a zip to load unpacked (not in a store yet).
npm run build:extension
mkdir -p "$OUT/dl"
rm -f "$OUT/dl/tlsnc-extension.zip"
(cd apps/extension/dist && zip -qr -X "../../../$OUT/dl/tlsnc-extension.zip" .)

if [ "${1:-}" != "--no-bin" ]; then
  mkdir -p "$OUT/dl"
  # Source paths end up in panic messages; keep the build machine's home out.
  export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build"
  build() { # rust target, zig glibc suffix, asset name
    PATH="$RUSTUP_BIN:$HOME/.cargo/bin:$PATH" cargo zigbuild --release -p tlsnc --target "$1$2"
    cp "target/$1/release/tlsnc" "$OUT/dl/$3"
  }
  build x86_64-unknown-linux-gnu .2.28 tlsnc-x86_64-linux
  build aarch64-unknown-linux-gnu .2.28 tlsnc-aarch64-linux
  PATH="$RUSTUP_BIN:$PATH" cargo build --release -p tlsnc
  cp target/release/tlsnc "$OUT/dl/tlsnc-aarch64-macos"
fi
(cd "$OUT/dl" && shasum -a 256 tlsnc-* > SHA256SUMS)
ls -la "$OUT" "$OUT/dl" 2>/dev/null

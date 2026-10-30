#!/bin/sh
# Builds the browser package into ./pkg (wasm-pack, target web).
#
# Needs: rustup with the nightly toolchain (rust-toolchain.toml pulls it in),
# wasm-pack >= 0.14, jq, and a clang that targets wasm32 for ring
# (Homebrew llvm on macOS, see .cargo/config.toml).
set -e
cd "$(dirname "$0")"

# Homebrew's cargo/rustc shadow rustup's proxies; put the nightly toolchain
# first so build-std and the atomics flags work.
NIGHTLY_BIN="$(dirname "$(rustup which --toolchain nightly rustc)")"
export PATH="$NIGHTLY_BIN:$PATH"

rm -rf pkg
wasm-pack build --release --target web --out-name tlsnc_wasm .

# web-spawn's worker snippet imports the package by a relative path that
# breaks once the package is moved; point it at the module (same fix as
# upstream tlsn-wasm's build.sh).
file=$(find ./pkg/snippets -name "spawn.js" -print -quit)
if [ -z "$file" ]; then
    echo "error: spawn.js snippet not found" >&2
    exit 1
fi
tmp=$(mktemp)
sed 's|../../..|../../../tlsnc_wasm.js|' "$file" > "$tmp" && mv "$tmp" "$file"
cp "$file" ./pkg

tmp=$(mktemp)
jq '.files += ["tlsnc_wasm_bg.wasm.d.ts", "spawn.js", "snippets/"] | .name = "@tlsnc/wasm"' pkg/package.json > "$tmp" && mv "$tmp" pkg/package.json
echo "built $(du -h pkg/tlsnc_wasm_bg.wasm | cut -f1) wasm in pkg/"

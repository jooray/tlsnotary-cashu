#!/bin/sh
# Builds crates/verify to WebAssembly into ./wasm (stable Rust, no threads,
# so pages that only verify need no cross-origin isolation).
set -e
cd "$(dirname "$0")"
STABLE_BIN="$(dirname "$(rustup which --toolchain stable rustc)")"
export PATH="$STABLE_BIN:$PATH"
# ring needs a clang that targets wasm32 (Apple's cannot).
if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then
    export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
    export AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar
fi
export RUSTFLAGS='--cfg getrandom_backend="wasm_js"'
rm -rf wasm
wasm-pack build --release --target web --out-dir ../../packages/verify/wasm --out-name tlsnc_verify ../../crates/verify
rm -f wasm/.gitignore wasm/package.json wasm/README.md
echo "built $(du -h wasm/tlsnc_verify_bg.wasm | cut -f1) wasm in wasm/"

#!/bin/sh
# Installs the tlsnc CLI from the latest GitHub release into ~/.local/bin
# (or --dir DIR), after checking it against SHA256SUMS. TLSNC_DL points it
# at another directory with the same files, such as a notary's /dl/.
#
#   curl -fsSL https://jooray.github.io/tlsnotary-cashu/install.sh | sh
#   curl -fsSL https://jooray.github.io/tlsnotary-cashu/install.sh | sh -s -- --dir /usr/local/bin
set -eu

BASE="${TLSNC_DL:-https://github.com/jooray/tlsnotary-cashu/releases/latest/download}"
DIR="$HOME/.local/bin"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64 | Linux-amd64) asset=tlsnc-x86_64-linux ;;
  Linux-aarch64 | Linux-arm64) asset=tlsnc-aarch64-linux ;;
  Darwin-arm64) asset=tlsnc-aarch64-macos ;;
  *)
    echo "no prebuilt tlsnc for $(uname -s) $(uname -m); build it with:" >&2
    echo "  cargo install --locked --git https://github.com/jooray/tlsnotary-cashu tlsnc" >&2
    exit 1 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$BASE/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl -fsSL "$BASE/$asset" -o "$tmp/tlsnc"
want="$(awk -v a="$asset" '$2 == a { print $1 }' "$tmp/SHA256SUMS")"
got="$(sha "$tmp/tlsnc")"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "checksum mismatch for $asset (expected ${want:-none}, got $got)" >&2
  exit 1
fi

mkdir -p "$DIR"
chmod 0755 "$tmp/tlsnc"
mv "$tmp/tlsnc" "$DIR/tlsnc"
echo "installed $("$DIR/tlsnc" --version) to $DIR/tlsnc"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "note: $DIR is not on PATH" ;;
esac
echo "next: export TLSNC_NOTARY=https://your-notary.example   # there is no public notary"
echo "      tlsnc receive 500                                   # top up the wallet over Lightning"

#!/usr/bin/env bash
# Downloads the signed Wintun driver DLL, verifies the pinned SHA-256 and
# copies wintun.dll for the requested architecture into the output directory.
#   usage: fetch-wintun.sh <amd64|arm64|x86|arm> <outdir>
set -euo pipefail

WINTUN_VERSION="0.14.1"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"

arch="${1:?arch}"
out="${2:?outdir}"
case "$arch" in amd64|arm64|x86|arm) ;; *) echo "unsupported arch: $arch" >&2; exit 2 ;; esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL --proto '=https' --tlsv1.2 -o "$work/wintun.zip" "$URL"
if command -v sha256sum >/dev/null; then
  got="$(sha256sum "$work/wintun.zip" | cut -d' ' -f1)"
else
  got="$(shasum -a 256 "$work/wintun.zip" | cut -d' ' -f1)"
fi
if [ "$got" != "$WINTUN_SHA256" ]; then
  echo "wintun.zip checksum mismatch: got $got" >&2
  exit 1
fi
unzip -q "$work/wintun.zip" -d "$work"
mkdir -p "$out"
cp "$work/wintun/bin/$arch/wintun.dll" "$out/wintun.dll"
cp "$work/wintun/LICENSE.txt" "$out/WINTUN-LICENSE.txt"
echo "wintun $WINTUN_VERSION ($arch) -> $out/wintun.dll"

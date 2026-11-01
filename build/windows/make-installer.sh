#!/usr/bin/env bash
# Builds the Private VPN Pro Windows installer with NSIS (makensis 3.x, which
# also runs on Linux and macOS).
#   usage: make-installer.sh <amd64|arm64> <version> <srcdir> <out.exe>
# srcdir holds private-vpn-pro.exe, wintun.dll and WINTUN-LICENSE.txt (as
# produced by fetch-wintun.sh); LICENSE is taken from the repository.
set -euo pipefail

arch="${1:?arch}"
version="${2:?version}"
src="${3:?srcdir}"
out="${4:?out.exe}"
here="$(cd "$(dirname "$0")" && pwd)"
case "$arch" in amd64|arm64) ;; *) echo "unsupported arch: $arch" >&2; exit 2 ;; esac

# VIProductVersion needs four numeric parts: v1.2.3-rc1 → 1.2.3(.0).
ver="$(printf '%s' "${version#v}" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
[ -n "$ver" ] || ver="0.0.0"

src="$(cd "$src" && pwd)"
cp "$here/../../LICENSE" "$src/LICENSE"
mkdir -p "$(dirname "$out")"
out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"

# makensis aborts without a UTF-8 locale (empty LANG on macOS).
export LC_ALL="${LC_ALL:-${LANG:-en_US.UTF-8}}"
makensis -V2 -WX -DARCH="$arch" -DVERSION="$ver" -DSRCDIR="$src" -DOUTFILE="$out" "$here/installer.nsi"
echo "built $out"

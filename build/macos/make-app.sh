#!/usr/bin/env bash
# Builds Private VPN Pro.app (tray-only: LSUIElement, no Dock icon) from a
# compiled binary.   usage: make-app.sh <binary> <version> <outdir>
set -euo pipefail

bin="${1:?binary}"
version="${2:?version}"
out="${3:?outdir}"
here="$(cd "$(dirname "$0")" && pwd)"

app="$out/Private VPN Pro.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin" "$app/Contents/MacOS/private-vpn-pro"
chmod 755 "$app/Contents/MacOS/private-vpn-pro"
sed "s/__VERSION__/${version#v}/g" "$here/Info.plist" > "$app/Contents/Info.plist"
if [ -f "$here/icon.icns" ]; then
  cp "$here/icon.icns" "$app/Contents/Resources/icon.icns"
fi
# Ad-hoc signature: required on Apple silicon; not notarised.
codesign --force --deep -s - "$app"
echo "built $app"

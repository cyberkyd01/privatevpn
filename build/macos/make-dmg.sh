#!/usr/bin/env bash
# Packs Private VPN Pro.app into a compressed disk image with an Applications
# link for drag-and-drop install.   usage: make-dmg.sh <Private VPN Pro.app> <out.dmg>
set -euo pipefail

app="${1:?Private VPN Pro.app}"
out="${2:?out.dmg}"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

ditto "$app" "$stage/Private VPN Pro.app"
ln -s /Applications "$stage/Applications"
rm -f "$out"
hdiutil create -quiet -volname "Private VPN Pro" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$out"
echo "built $out"

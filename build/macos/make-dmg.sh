#!/usr/bin/env bash
# Packs PrivateVPN.app into a compressed disk image with an Applications
# link for drag-and-drop install.   usage: make-dmg.sh <PrivateVPN.app> <out.dmg>
set -euo pipefail

app="${1:?PrivateVPN.app}"
out="${2:?out.dmg}"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

ditto "$app" "$stage/PrivateVPN.app"
ln -s /Applications "$stage/Applications"
rm -f "$out"
hdiutil create -quiet -volname "PrivateVPN" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$out"
echo "built $out"

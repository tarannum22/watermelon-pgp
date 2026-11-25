#!/usr/bin/env bash
# Write the Chocolatey package sources for a release, from its SHA256SUMS file:
#
#   packaging/chocolatey/package.sh 0.4.0 SHA256SUMS out/
#   choco pack out/watermelon-pgp.nuspec --out out/      # on Windows: watermelon-pgp.0.4.0.nupkg
#
# Used by the release workflow; a manual run gives the same package. The templates next to this
# script hold @VERSION@, @REPO@, @URL64@, @ZIPDIR@ and @CHECKSUM64@. The install script downloads the
# release's Windows zip from GitHub and checks it against the checksum from SHA256SUMS.
# WATERMELON_DOWNLOAD_BASE replaces the download folder URL (the release workflow's smoke test
# uses a file:// URL before the release exists).
set -euo pipefail

version=$1
sums=$2
out=$3
repo=${GITHUB_REPOSITORY:-tarannum22/watermelon-pgp}
here=$(cd "$(dirname "$0")" && pwd)

zip="watermelon-pgp-v${version}-x86_64-pc-windows-msvc.zip"
checksum=$(awk -v f="$zip" '$2 == f || $2 == "*"f { print $1 }' "$sums" | grep -E '^[0-9a-f]{64}$') \
  || { echo "no checksum for $zip in $sums" >&2; exit 1; }
base=${WATERMELON_DOWNLOAD_BASE:-https://github.com/${repo}/releases/download/v${version}}

mkdir -p "$out/tools"
fill() {
  sed -e "s|@VERSION@|${version}|g" -e "s|@REPO@|${repo}|g" \
      -e "s|@URL64@|${base}/${zip}|g" -e "s|@ZIPDIR@|${zip%.zip}|g" -e "s|@CHECKSUM64@|${checksum}|g" "$here/$1" > "$out/$1"
}
fill watermelon-pgp.nuspec
for script in common.ps1 chocolateyInstall.ps1 chocolateyUninstall.ps1; do
  fill "tools/$script"
done

if grep -rnE '@[A-Z0-9_]+@' "$out"; then
  echo "placeholders left in $out" >&2
  exit 1
fi
echo "$out: watermelon-pgp $version, $zip sha256 $checksum"

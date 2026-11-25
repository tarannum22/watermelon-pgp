#!/usr/bin/env bash
# Tests for package.sh: run `packaging/chocolatey/package_test.sh` (bash, no Windows needed).
# What the package does on Windows is tested by the release workflow's chocolatey job.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

zip=watermelon-pgp-v1.2.3-x86_64-pc-windows-msvc.zip
sum=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
cat > "$tmp/SHA256SUMS" <<EOF
ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  watermelon-pgp-v1.2.3-x86_64-unknown-linux-gnu.tar.gz
${sum} *${zip}
EOF

# The package for a release: version, download URL and checksum filled in, nothing left over.
out="$tmp/pkg"
GITHUB_REPOSITORY=acme/wm "$here/package.sh" 1.2.3 "$tmp/SHA256SUMS" "$out" > /dev/null
nuspec="$out/watermelon-pgp.nuspec"
install="$out/tools/chocolateyInstall.ps1"
for f in "$nuspec" "$install" "$out/tools/chocolateyUninstall.ps1"; do
  test -s "$f" || fail "no $f"
done
grep -q '<id>watermelon-pgp</id>' "$nuspec" || fail "nuspec id"
grep -q '<version>1.2.3</version>' "$nuspec" || fail "nuspec version"
grep -q 'https://github.com/acme/wm/releases/tag/v1.2.3' "$nuspec" || fail "nuspec release notes link"
grep -qF "https://github.com/acme/wm/releases/download/v1.2.3/${zip}" "$install" || fail "download URL"
grep -qF "'${sum}'" "$install" || fail "checksum"
grep -qF "'sha256'" "$install" || fail "checksum type"
grep -qF "'watermelon-pgp-v1.2.3-x86_64-pc-windows-msvc'" "$out/tools/common.ps1" || fail "zip folder"
if grep -rnE '@[A-Z0-9_]+@' "$out"; then fail "placeholders left"; fi

# A local download base, for the dry run's smoke test before the release exists.
WATERMELON_DOWNLOAD_BASE=file:///D:/dist "$here/package.sh" 1.2.3 "$tmp/SHA256SUMS" "$tmp/local" > /dev/null
grep -qF "file:///D:/dist/${zip}" "$tmp/local/tools/chocolateyInstall.ps1" || fail "WATERMELON_DOWNLOAD_BASE"

# No zip in SHA256SUMS: an error, and no package.
if "$here/package.sh" 9.9.9 "$tmp/SHA256SUMS" "$tmp/missing" 2> "$tmp/err"; then
  fail "succeeded without a checksum for the zip"
fi
grep -q 'no checksum for watermelon-pgp-v9.9.9-x86_64-pc-windows-msvc.zip' "$tmp/err" || fail "error message: $(cat "$tmp/err")"
test ! -e "$tmp/missing" || fail "wrote a package without a checksum"

if [ "$failures" -ne 0 ]; then echo "$failures failure(s)" >&2; exit 1; fi
echo "package.sh: all tests passed"

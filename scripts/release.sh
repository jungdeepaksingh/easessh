#!/usr/bin/env bash
# Builds static, reproducible binaries for all platforms plus SHA256SUMS.
# Usage: scripts/release.sh [version]
#
# Code signing needs your certificates; add it after the build loop, e.g.
#   macOS:   codesign --options runtime -s "Developer ID Application: ..." then xcrun notarytool
#   Windows: signtool sign /fd sha256 /tr <timestamp-url> ...
#   any:     cosign sign-blob or minisign over SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-${VERSION:-0.2.0}}"
platforms="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
dist=dist

go vet ./...
go test -count=1 ./...

rm -rf "$dist" && mkdir -p "$dist"
for p in $platforms; do
	os=${p%/*} arch=${p#*/} ext=""
	[ "$os" = windows ] && ext=".exe"
	out="$dist/easessh_${version}_${os}_${arch}${ext}"
	echo "build $out"
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" .
done

cd "$dist"
if command -v sha256sum >/dev/null; then sha256sum easessh_* >SHA256SUMS; else shasum -a 256 easessh_* >SHA256SUMS; fi
cat SHA256SUMS

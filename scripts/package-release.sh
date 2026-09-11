#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# == 3 ]] || { echo 'Usage: package-release.sh TAG TARGET OUTPUT_DIRECTORY' >&2; exit 1; }
release=$1
target=$2
case "$target" in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) echo "Unsupported Linux target: $target" >&2; exit 1 ;; esac
output=$3
[[ "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid release tag' >&2; exit 1; }
mkdir -p "$output"
output=$(cd "$output" && pwd)
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
install -m 755 target/release/dnsuck target/release/cmd "$staging/"
printf '%s\n' "$release" > "$staging/VERSION"
asset="dnsuck-$target.tar.gz"
tar -czf "$output/$asset" -C "$staging" dnsuck cmd VERSION
cd "$output"
if command -v sha256sum >/dev/null; then sha256sum "$asset" > "$asset.sha256"; else shasum -a 256 "$asset" > "$asset.sha256"; fi

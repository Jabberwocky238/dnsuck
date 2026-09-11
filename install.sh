#!/usr/bin/env bash
set -euo pipefail

# Stamped with the current repository when published by the release workflow.
repository='Jabberwocky238/dnsuck'
version=latest
prefix=''
uninstall=false
fail() { echo "Error: $*" >&2; exit 1; }
usage() {
    cat <<'HELP'
Usage: install.sh [--repo OWNER/REPO] [--version TAG] [--prefix PATH]
       install.sh --uninstall [--prefix PATH]
Installs dnsuckd and dnsuck from a checksummed GitHub release.
Default prefix: /usr/local for root, ~/.local otherwise.
--uninstall removes managed binaries and links; databases remain untouched.
Requires bash, curl, tar, and sha256sum or shasum for installation.
HELP
}
while (($#)); do
    case "$1" in
        --repo|--version|--prefix)
            (($# >= 2)) || fail "$1 needs a value"
            case "$1" in
                --repo) repository=$2 ;;
                --version) version=$2 ;;
                --prefix) prefix=$2 ;;
            esac
            shift 2 ;;
        --uninstall) uninstall=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
if [[ -z "$prefix" ]]; then
    if [[ $(id -u) == 0 ]]; then prefix=/usr/local; else prefix="$HOME/.local"; fi
fi
[[ "$prefix" == /* && "$prefix" != / ]] || fail 'Prefix must be an absolute path other than /'
prefix=${prefix%/}
bindir="$prefix/bin"
store="$prefix/lib/dnsuck"
[[ ! -L "$store" ]] || fail "Refusing symlinked installation directory: $store"
owned_link() {
    [[ -L "$bindir/$1" ]] || return 1
    case "$(readlink "$bindir/$1")" in ../lib/dnsuck/*/"$1") return 0 ;; *) return 1 ;; esac
}
if $uninstall; then
    if [[ ! -e "$store" ]]; then echo 'Nothing installed.'; exit 0; fi
    [[ -f "$store/.managed-install" ]] || fail "Unrecognized directory: $store"
    for binary in dnsuckd dnsuck cmd; do
        if owned_link "$binary"; then rm "$bindir/$binary"; fi
    done
    rm -rf -- "$store"
    echo "Uninstalled dnsuckd and dnsuck from $prefix; databases preserved."
    exit 0
fi
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'Use --repo OWNER/REPO'
[[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'Invalid release tag'
for tool in curl tar; do command -v "$tool" >/dev/null || fail "Missing $tool"; done
if command -v sha256sum >/dev/null; then checksum=(sha256sum); else
    command -v shasum >/dev/null || fail 'Missing sha256sum or shasum'
    checksum=(shasum -a 256)
fi
[[ "$(uname -s)" == Linux ]] || fail 'Only Linux is supported'
os=unknown-linux-gnu
case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; arm64|aarch64) arch=aarch64 ;; *) fail 'Supported CPUs: x86-64 and ARM64' ;; esac
target="$arch-$os"
asset="dnsuck-$target.tar.gz"
base="https://github.com/$repository/releases"
if [[ "$version" == latest ]]; then base="$base/latest/download"; else base="$base/download/$version"; fi
[[ ! -e "$store" || -f "$store/.managed-install" ]] || fail "Unrecognized directory: $store"
for binary in dnsuckd dnsuck; do
    if [[ -e "$bindir/$binary" || -L "$bindir/$binary" ]]; then
        owned_link "$binary" && [[ -f "$store/.managed-install" ]] || fail "Refusing to replace $bindir/$binary"
    fi
done
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$base/$asset" -o "$temporary/$asset"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$base/$asset.sha256" -o "$temporary/checksum"
expected=$(awk 'NR == 1 {print $1}' "$temporary/checksum")
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'Invalid checksum file'
actual=$("${checksum[@]}" "$temporary/$asset")
[[ "${actual%% *}" == "$expected" ]] || fail 'Release checksum mismatch'
# Only accept the three expected regular files, never arbitrary archive paths.
entries=$(tar -tzf "$temporary/$asset" | LC_ALL=C sort)
[[ "$entries" == $'VERSION\ndnsuck\ndnsuckd' ]] || fail 'Unexpected release archive contents'
[[ $(tar -tvzf "$temporary/$asset" | awk 'substr($0,1,1) != "-" {n++} END {print n+0}') == 0 ]] || fail 'Archive contains non-regular files'
mkdir "$temporary/extracted"
tar -xzf "$temporary/$asset" -C "$temporary/extracted"
release=$(cat "$temporary/extracted/VERSION")
[[ "$release" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'Invalid packaged version'
[[ "$version" == latest || "$version" == "$release" ]] || fail 'Release version mismatch'
mkdir -p "$bindir" "$store"
chmod 755 "$store"
touch "$store/.managed-install"
installed=$(mktemp -d "$store/$release-$target.XXXXXX")
chmod 755 "$installed"
for binary in dnsuckd dnsuck; do
    install -m 755 "$temporary/extracted/$binary" "$installed/$binary"
done
install -m 644 "$temporary/extracted/VERSION" "$installed/VERSION"
for binary in dnsuckd dnsuck; do
    if owned_link "$binary"; then rm "$bindir/$binary"; fi
    ln -s "../lib/dnsuck/${installed##*/}/$binary" "$bindir/$binary"
done
# Remove the former CLI name only when it belongs to this installation.
if owned_link cmd; then rm "$bindir/cmd"; fi
echo "Installed $release ($target): $bindir/dnsuckd and $bindir/dnsuck"
case ":$PATH:" in *":$bindir:"*) ;; *) echo "Add $bindir to your PATH." ;; esac

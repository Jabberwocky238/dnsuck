#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
prepare_mmdb=true
refresh_mmdb=false
mmdb_source=''
while (($#)); do
    case "$1" in
        --skip-mmdb) prepare_mmdb=false; shift ;;
        --refresh-mmdb) refresh_mmdb=true; shift ;;
        --mmdb) [[ $# -ge 2 ]] || { echo '--mmdb needs a file path' >&2; exit 1; }; mmdb_source=$2; shift 2 ;;
        *) echo "Unknown doctor option: $1" >&2; exit 1 ;;
    esac
done
for tool in cargo python3 cc ar pkg-config; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing $tool. Install Rust, Python 3, a C toolchain, and pkg-config first." >&2
        echo "macOS: xcode-select --install; brew install pkgconf" >&2
        echo "Debian/Ubuntu: sudo apt-get install build-essential python3 pkg-config" >&2
        exit 1
    fi
done

# Reuse the exact LMDB sources shipped with the locked Rust dependency.
source_dir=$(cargo metadata --locked --format-version 1 | python3 -c '
import json, pathlib, sys
packages = json.load(sys.stdin)["packages"]
package = next(p for p in packages if p["name"] == "lmdb-sys")
print(pathlib.Path(package["manifest_path"]).parent / "lmdb/libraries/liblmdb")
')
prefix="$PWD/.local/lmdb"
mkdir -p "$prefix/lib/pkgconfig" "$prefix/include" "$prefix/build"
for name in mdb midl; do
    cc -O2 -fPIC -pthread -I "$source_dir" -c "$source_dir/$name.c" -o "$prefix/build/$name.o"
done
ar rcs "$prefix/lib/liblmdb.a" "$prefix/build/mdb.o" "$prefix/build/midl.o"
cp "$source_dir/lmdb.h" "$prefix/include/"
# pkg-config resolves this relative to the .pc file, so checkout paths can move.
cat > "$prefix/lib/pkgconfig/liblmdb.pc" <<'PC'
prefix=${pcfiledir}/../..
libdir=${prefix}/lib
includedir=${prefix}/include

Name: liblmdb
Description: LMDB from the Cargo.lock lmdb-sys dependency
Version: @VERSION@
Libs: -L${libdir} -llmdb
Libs.private: -lpthread
Cflags: -I${includedir}
PC
python3 - "$source_dir/lmdb.h" "$prefix/lib/pkgconfig/liblmdb.pc" <<'PY'
import pathlib, re, sys
header = pathlib.Path(sys.argv[1]).read_text()
version = ".".join(re.search(r"#define MDB_VERSION_" + part + r"\s+(\d+)", header)[1]
                   for part in ("MAJOR", "MINOR", "PATCH"))
pc = pathlib.Path(sys.argv[2])
pc.write_text(pc.read_text().replace("@VERSION@", version))
PY
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" pkg-config --modversion liblmdb
# Re-run the dependency build script if it previously compiled its bundled copy.
cargo clean -p lmdb-sys
echo "LMDB prepared at $prefix/lib/liblmdb.a. Run cargo build."

if $prepare_mmdb; then
    python3 - "$mmdb_source" "$refresh_mmdb" <<'PYMMDB'
import datetime, gzip, hashlib, os, pathlib, sys, tempfile, urllib.request, urllib.error
source, refresh = sys.argv[1:]
target = pathlib.Path('.local/geo/country.mmdb')
target.parent.mkdir(parents=True, exist_ok=True)
if source:
    data = pathlib.Path(source).read_bytes()
elif target.exists() and refresh != 'true':
    data = target.read_bytes()
else:
    month = datetime.datetime.now(datetime.timezone.utc).date().replace(day=1)
    for attempt in range(3):
        url = f'https://download.db-ip.com/free/dbip-country-lite-{month:%Y-%m}.mmdb.gz'
        print('Downloading ' + url, flush=True)
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'dnsuck-doctor/1.0'})
            compressed = urllib.request.urlopen(request, timeout=60).read()
            break
        except urllib.error.HTTPError as error:
            if error.code != 404 or attempt == 2:
                raise
            month = (month - datetime.timedelta(days=1)).replace(day=1)
    data = gzip.decompress(compressed)
if b'\xab\xcd\xefMaxMind.com' not in data[-131072:]:
    raise SystemExit('Invalid MMDB: MaxMind metadata marker is missing')
# Preserve an existing database if downloading, decompression, or validation fails.
with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
    output.write(data)
    temporary = output.name
os.replace(temporary, target)
target.chmod(0o644)
target.with_suffix('.mmdb.sha256').write_text(hashlib.sha256(data).hexdigest() + '  country.mmdb\n')
print('MMDB prepared at ' + str(target) + '. Enable with --mmdb ' + str(target))
if not source:
    print('IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0')
PYMMDB
fi

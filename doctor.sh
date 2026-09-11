#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
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

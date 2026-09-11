#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/python-env.sh
cargo build --release --locked
exec "$DNS_TEST_PYTHON" scripts/bench.py "$@"

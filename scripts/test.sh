#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/python-env.sh
cargo fmt --all --check
cargo clippy --workspace --locked --all-targets -- -D warnings
# Rust integration tests also launch the Python wire-protocol suite.
cargo build --workspace --locked
export DNS_TEST_CLI="$PWD/target/debug/cmd"
cargo test --workspace --locked

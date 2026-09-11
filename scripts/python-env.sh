#!/usr/bin/env bash
# Source from repository-root scripts.
if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv .venv
fi
if ! .venv/bin/python -c 'import dns, cryptography, httpx, h2, aioquic; assert dns.__version__ == "2.8.0"' 2>/dev/null; then
    .venv/bin/python -m pip install -r tests/requirements.txt
fi
export DNS_TEST_PYTHON="$PWD/.venv/bin/python"

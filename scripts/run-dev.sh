#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec cargo run -- --graphql --listen 127.0.0.1:3080 --dns 127.0.0.1:5353 --doh 127.0.0.1:8443 --dot 127.0.0.1:853 --doq 127.0.0.1:853 \
  --doh-cert .local/tls/cert.pem --doh-key .local/tls/key.pem \
  --dot-cert .local/tls/cert.pem --dot-key .local/tls/key.pem \
  --doq-cert .local/tls/cert.pem --doq-key .local/tls/key.pem \
  --api-token "$(cat .local/api-token)" \
  --dnssec-zone secure.test. --dnssec-key-file .local/dnssec/key.pem "$@"

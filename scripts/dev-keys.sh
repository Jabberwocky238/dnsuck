#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
command -v openssl >/dev/null || { echo 'openssl is required' >&2; exit 1; }
mkdir -p .local/tls .local/dnssec
if [[ ! -f .local/tls/key.pem ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out .local/tls/key.pem
fi
if [[ ! -f .local/tls/cert.pem ]]; then
    cat > .local/tls/openssl.cnf <<'CONF'
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=localhost
[ext]
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyCertSign
extendedKeyUsage=serverAuth
CONF
    openssl req -new -x509 -key .local/tls/key.pem -out .local/tls/cert.pem -days 30 -config .local/tls/openssl.cnf
fi
if [[ ! -f .local/dnssec/key.pem ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out .local/dnssec/key.pem
fi
echo 'Development keys ready. Start with ./scripts/run-dev.sh'

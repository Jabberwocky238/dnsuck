#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run --quiet -p dnsuck -- write <<'RECORDS'
[
  {"name":"secure.test.","recordType":"SOA","ttl":300,"data":"ns.secure.test. hostmaster.secure.test. 1 3600 600 86400 300"},
  {"name":"secure.test.","recordType":"NS","ttl":300,"data":"ns.secure.test."},
  {"name":"ns.secure.test.","recordType":"A","ttl":300,"data":"127.0.0.1"},
  {"name":"host.secure.test.","recordType":"A","ttl":300,"data":"192.0.2.10"},
  {"name":"host.secure.test.","recordType":"AAAA","ttl":300,"data":"2001:db8::10"}
]
RECORDS

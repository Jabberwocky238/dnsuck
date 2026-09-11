# dnsuck

```bash
bash <(curl -fsSL https://github.com/Jabberwocky238/dnsuck/releases/latest/download/install.sh)
```

Linux DNS server with LMDB, UDP/TCP, DoH, DoT, DoQ, DNSSEC, and a separate GraphQL API. Installation requires a published release, Linux x86-64/ARM64, and glibc 2.35+.

## Install

The installer verifies checksums and links `dnsuck` and `cmd` into `/usr/local/bin` for root or `~/.local/bin` for users. Run from a root shell for system-wide installation; add `~/.local/bin` to PATH if needed.

Options: `--version TAG`, `--prefix PATH`, `--repo OWNER/REPO`. Uninstall preserves databases and configuration:

```bash
bash <(curl -fsSL https://github.com/Jabberwocky238/dnsuck/releases/latest/download/install.sh) --uninstall
```

## Start

```bash
dnsuck --listen 127.0.0.1:3080 --dns 127.0.0.1:5353
```

Management uses plain HTTP without authentication at `http://127.0.0.1:3080/graphql`. Set its address with `--listen ADDRESS:PORT`; the default is `127.0.0.1:3080`.

| Flag | Transport | Certificates |
| --- | --- | --- |
| `--dns ADDRESS:PORT` | UDP/TCP | None |
| `--doh ADDRESS:PORT` | HTTPS `/dns-query`, GET/POST | `--doh-cert PATH --doh-key PATH` |
| `--dot ADDRESS:PORT` | TLS/TCP, standard port 853 | `--dot-cert PATH --dot-key PATH` |
| `--doq ADDRESS:PORT` | QUIC/UDP, standard port 853 | `--doq-cert PATH --doq-key PATH` |

Omitted listeners stay disabled. Behind a TLS-terminating proxy, use `--doh-no-cert` for plain HTTP or `--dot-no-cert` for plain TCP instead of certificate/key flags. GraphQL remains separate from DoH.

## Configuration

Create `dnsuck.toml` using [dnsuck.example.toml](dnsuck.example.toml):

```toml
listen = "127.0.0.1:3080"
database = "data/lmdb"
dns = "127.0.0.1:5353"
```

```bash
dnsuck -c dnsuck.toml
# After editing, run from another shell:
dnsuck --reload
```

With `-c`, no other configuration flags or local-write subcommands are allowed. Keys match long flags; explicit paths resolve relative to the file. No environment-variable configuration.

Only config-file servers are reloadable, with one instance per Unix user. Reload restarts listeners briefly and restores the previous configuration if binding fails. Changing the database path requires a restart.

## Records

```bash
cmd set app.test A 192.0.2.20
cmd set app.test AAAA 2001:db8::20 --ttl 60
cmd set app.test TXT '"hello world"'
cmd set mail.test MX '10 smtp.test.'
cmd get app.test A
cmd del app.test A
cmd batch --item "set,app.test,A,192.0.2.20" --item "get,app.test,A"
```

`cmd` defaults to the management URL above; use `--endpoint URL` as needed. `set` replaces one RRset, preserving other types; TTL defaults to 300. `--raw` accepts base64 wire RDATA. Batch CSV items run sequentially without rollback of earlier writes.

GraphQL supports `records(name, recordType)`, `names(prefix, after, limit)`, atomic `upsert(records)`, and `delete(name, recordType)`. Record inputs contain `name`, `recordType`, `ttl`, and exactly one of `data` or `rdataBase64`.

Local writes: `dnsuck put NAME IP [TTL]`, `dnsuck record NAME TYPE VALUE`, or `dnsuck write` with a JSON record array on stdin. Use `--database PATH`; the default is `data/lmdb`.

## LMDB and DNSSEC

LMDB is the only record store; no zone files. The `records` database maps lowercase fully qualified names to all their records, encoded as `DNS1` plus a Hickory DNS wire message. Reads filter by type; CNAME lookups follow target keys. Writes replace supplied RRsets; deletes remove types or whole names. Batches commit atomically with the `metadata[revision]` big-endian u64 counter.

DNSSEC uses `--dnssec-zone DOMAIN --dnssec-key-file PATH` with an ECDSA P-256 PKCS#8 PEM key. Apex SOA/NS records must exist in LMDB. Hickory generates signatures and negative-answer proofs; public trust requires a parent DS record.

## Releases

[CI](.github/workflows/ci.yaml) checks every push on Linux x86-64 and ARM64. Pushing a tag such as `v0.1.0` runs the same checks before [publishing binaries](.github/workflows/release.yml).

## Debug

```bash
./doctor.sh                              # Prepare static LMDB; requires Rust, Python, cc, ar, pkg-config
cargo build --release --workspace --locked
./scripts/test.sh                       # Rust and Python integration tests
./scripts/bench.sh                      # 100k records, 10k random queries in under 1s
./scripts/dev-keys.sh && ./scripts/seed-dev.sh && ./scripts/run-dev.sh
```

Benchmark output: `dist/benchmark.json`. After a crash, remove `<temporary-directory>/dnsuck-control-<uid>/reload.sock` only after confirming its server has stopped.

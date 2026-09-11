# dnsuck

```bash
bash <(curl -fsSL https://github.com/Jabberwocky238/dnsuck/releases/latest/download/install.sh)
```

Linux DNS server with LMDB storage, UDP/TCP, DoH, DoT, DoQ, DNSSEC, and a separate GraphQL management API. The installer downloads the latest tagged release for x86-64 or ARM64; it requires a published release, glibc 2.35+, and a CA certificate bundle.

## Install and uninstall

Installs `dnsuck` and `cmd`, verifies SHA-256 checksums, and creates command symlinks:

| Account | Commands | Managed binaries |
| --- | --- | --- |
| Root | `/usr/local/bin/` | `/usr/local/lib/dnsuck/` |
| User | `~/.local/bin/` | `~/.local/lib/dnsuck/` |

Run the installer in a root shell for a system-wide installation. Add `~/.local/bin` to PATH if needed. Optional arguments: `--version v0.1.0`, `--prefix /absolute/path`, or `--repo OWNER/REPO`.

```bash
bash <(curl -fsSL https://github.com/Jabberwocky238/dnsuck/releases/latest/download/install.sh) --uninstall
```

Use the same account and prefix as installation. Uninstall preserves databases, configuration, and unrelated commands. Installation does not start a service.

## Start

```bash
dnsuck --graphql --dns 127.0.0.1:5353
```

`--graphql` is required in server mode. Management runs over plain HTTP at `http://127.0.0.1:3080/graphql`; change its address with `--listen ADDRESS:PORT`. Use `--api-token TOKEN` to require bearer authentication.

DNS listeners start only when specified, and each requires `ADDRESS:PORT`:

| Listener | Transport | TLS options |
| --- | --- | --- |
| `--dns` | UDP and TCP | None |
| `--doh` | HTTPS, `/dns-query` GET/POST | `--doh-cert PATH --doh-key PATH` |
| `--dot` | TLS over TCP, standard port 853 | `--dot-cert PATH --dot-key PATH` |
| `--doq` | QUIC over UDP, standard port 853 | `--doq-cert PATH --doq-key PATH` |

When a proxy terminates TLS:

```bash
dnsuck --graphql \
  --doh 127.0.0.1:8080 --doh-no-cert \
  --dot 127.0.0.1:853 --dot-no-cert
```

`--doh-no-cert` accepts plain HTTP; `--dot-no-cert` accepts plain TCP DNS. They conflict with their listener's certificate/key flags. DoQ always requires certificates. GraphQL stays separate from DoH.

## TOML configuration

Create a file using [dnsuck.example.toml](dnsuck.example.toml), or start with:

```toml
graphql = true
listen = "127.0.0.1:3080"
database = "data/lmdb"
dns = "127.0.0.1:5353"
```

```bash
dnsuck -c dnsuck.toml
# After editing the file, from another shell:
dnsuck --reload
```

With `-c`, the file is the only configuration source: other configuration flags and local-write subcommands are rejected. Keys match long flags; underscores may replace hyphens. Explicit file paths resolve relative to the TOML file. Environment variables are not used for configuration.

Only servers started with `-c` are reloadable. `--reload` takes no other arguments and targets the single config-file instance for the same Unix user. Reload validates settings and keys, then restarts listeners with a brief interruption. Failed binds restore the previous configuration. Changing the database path requires a restart.

The private reload socket is at `<temporary-directory>/dnsuck-control-<uid>/reload.sock`. After a crash, remove a stale socket only after confirming its server has stopped.

## Manage records

`cmd` uses `http://127.0.0.1:3080/graphql` by default. Set `--endpoint URL` or `--token TOKEN` when needed; `--ca-cert PATH` supports HTTPS endpoints behind a proxy.

```bash
cmd set app.test A 192.0.2.20
cmd set app.test AAAA 2001:db8::20 --ttl 60
cmd set app.test TXT '"hello world"'
cmd set mail.test MX '10 smtp.test.'
cmd set custom.test TYPE65280 '3q2+7w==' --raw
cmd get app.test A
cmd del app.test A

cmd batch \
  --item "set,app.test,A,192.0.2.20" \
  --item "get,app.test,A" \
  --item "del,app.test,A"
```

`set` replaces that name/type RRset and preserves other types. TTL defaults to 300 seconds. `--raw` accepts base64-encoded wire RDATA. Batch items use CSV syntax and run sequentially; errors stop the batch without rolling back earlier writes. Output is JSON.

GraphQL provides `records(name, recordType)`, `names(prefix, after, limit)`, `upsert(records)`, and `delete(name, recordType)`. An atomic multi-record write uses:

```graphql
mutation {
  upsert(records: [
    {name: "app.test", recordType: "A", ttl: 60, data: "192.0.2.20"}
    {name: "app.test", recordType: "AAAA", ttl: 60, data: "2001:db8::20"}
  ])
}
```

Record inputs require exactly one of `data` or `rdataBase64`. Named types and `TYPE<number>` are accepted; query/pseudo types cannot be stored. SPF type 99 is supported, though modern SPF policies use TXT.

Local writes work without starting the server:

```bash
dnsuck put app.test 192.0.2.5 60
dnsuck record mail.test MX '10 smtp.test.' --ttl 300
printf '%s' '[{"name":"app.test","recordType":"A","ttl":60,"data":"192.0.2.5"}]' | dnsuck write
```

Use `--database PATH` to select the LMDB directory; the default is `data/lmdb`.

## LMDB keys and values

Records live only in LMDB; there are no zone files.

| Database | Key | Value |
| --- | --- | --- |
| `records` | Lowercase fully qualified name, e.g. `app.test.` | All records at that name, encoded as `DNS1` plus a Hickory DNS wire message |
| `metadata` | `revision` | Big-endian u64 counter for DNSSEC cache invalidation |

Reads fetch a name and filter by type; CNAME resolution follows target keys. Writes replace supplied RRsets while preserving other types. Deletes remove a type or the entire name, dropping empty keys. Each write batch and revision update commits atomically; invalid batches change nothing.

## DNSSEC

Set `--dnssec-zone DOMAIN` and `--dnssec-key-file PATH` using an ECDSA P-256 PKCS#8 PEM key. Apex SOA and NS records must already exist in LMDB. Hickory generates DNSKEY, signatures, and negative-answer proofs, refreshing them after record changes. Public trust requires a matching parent DS record; key rollover and recursive validation are not automated.

For local development:

```bash
./scripts/dev-keys.sh
./scripts/seed-dev.sh
./scripts/run-dev.sh
```

## Build, test, and release

```bash
./doctor.sh
cargo build --release --workspace --locked
./scripts/test.sh
./scripts/bench.sh
```

`doctor.sh` compiles the locked LMDB sources into `.local/lmdb/lib/liblmdb.a`. Building requires Rust, Python 3, a C compiler, `ar`, and `pkg-config`.

Tests cover 27 record types across all DNS transports, DNSSEC, GraphQL, CLI commands, TOML reload, persistence, and installation. The benchmark loads 100,000 records and requires 10,000 random UDP queries plus answer validation to finish within one second. Results go to `dist/benchmark.json`.

[CI](.github/workflows/ci.yaml) checks every push on Linux x86-64 and ARM64. Pushing a tag runs the same checks before [building and publishing releases](.github/workflows/release.yml). Use tags such as `v0.1.0`.

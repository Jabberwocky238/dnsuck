# dnsuck

Tokio DNS server with LMDB as the only record store. UDP/TCP, DoT, DoQ,
DoH, DNSSEC signing, and an authenticated GraphQL management API share the
same records. There are no zone files, zone-file parsers, or file imports.
Hickory handles DNS wire encoding and RDATA parsing; Clap handles both CLIs.

```sh
./doctor.sh
cargo run -- put app.test 192.0.2.5 60
cargo run -- --graphql --dns 127.0.0.1:5353
```

Enable listeners explicitly with `--dns`, `--doh`, `--dot`, and `--doq`.
Each requires an explicit `ADDRESS:PORT` value. The database defaults to `data/lmdb`;
use `--database PATH` to change it. Configure through flags or a TOML file,
with no environment-variable fallback.
Port zero selects one available port shared by UDP/TCP. Stop with Ctrl-C.

## Persistent configuration and reload

```sh
cp dnsuck.example.toml dnsuck.toml
# Edit dnsuck.toml, then start:
dnsuck -c dnsuck.toml
# After editing the same file:
dnsuck --reload
```

With `-c PATH`, TOML is the sole configuration source: configuration flags and
local-write subcommands cannot be combined with it. Keys match the long flags;
underscores are also accepted in place of hyphens. Unknown keys and incorrect
types are rejected. Paths explicitly set in the file resolve relative to that
file. Defaults remain the same as CLI mode. Records stay exclusively in LMDB.

`dnsuck --reload` takes no other arguments and asks the running config-file
instance to reread its original file. Flag-only servers are not reloadable.
Only one config-file instance per Unix user is supported; the same user must
request reload. The private control socket is under the system temporary
directory (`dnsuck-control-<uid>/reload.sock`) and is removed on orderly shutdown.
After a crash, remove a stale socket only once its server is confirmed stopped.

Reload validates TOML, TLS keys, and DNSSEC settings before restarting listeners.
It applies listener and authentication changes, including disabling transports
by removing their entries. Rebinding causes a brief interruption; if binding
fails, the previous in-memory configuration is restored. The database path
cannot change during reload; restart for that change. Invalid reloads return a
nonzero exit status. Configuration loading and reload lifecycle live together
in `src/config.rs`.

## Linux releases and installation

`.github/workflows/ci.yaml` checks every push on Linux x86-64 and ARM64:
shell syntax, formatting, Clippy, Rust tests, and Python integration tests.
Pushing a tag (for example `v0.1.0`) runs `.github/workflows/release.yml`, which
calls the same CI workflow for that tag. Release builds wait for CI to pass
before building and publishing
`dnsuck` and `cmd`, SHA-256 checksums, and `install.sh` as GitHub release assets.
Builds use Ubuntu 22.04 and statically link LMDB; the host needs glibc 2.35+
and a CA certificate bundle. macOS and Windows release binaries are not built.
Use simple tags containing letters, digits, dots, underscores, or hyphens.

After the first tagged release:

```sh
curl -fsSL https://github.com/Jabberwocky238/dnsuck/releases/latest/download/install.sh -o install.sh
bash install.sh
# Or install system-wide:
sudo bash install.sh
```

The published installer knows its repository and detects Linux/CPU architecture.
Use `--repo OWNER/REPO` to install from a fork instead.
Use `--version v0.1.0` to choose a tag; the default is the latest release.

| User | Binary symlinks | Managed versions |
| --- | --- | --- |
| Root | `/usr/local/bin/dnsuck`, `/usr/local/bin/cmd` | `/usr/local/lib/dnsuck/` |
| Regular user | `~/.local/bin/dnsuck`, `~/.local/bin/cmd` | `~/.local/lib/dnsuck/` |

The installer verifies the archive checksum before writing files, refuses to
replace unrelated commands, and relinks both commands when upgrading. Previous
versions remain under the managed directory until uninstall. Add `~/.local/bin`
to PATH if necessary. `--prefix /absolute/path` overrides the default prefix.
It does not create a system service or start the server.

```sh
bash install.sh --uninstall
# For the root installation:
sudo bash install.sh --uninstall
```

Uninstall removes the managed versions and their command links. It preserves
LMDB databases, configuration, unrelated commands, and PATH settings. Use the
same account or `--prefix` used for installation.

## How LMDB keys and values are managed

LMDB is the only persistent record store, with two named KV databases:

| Database | Key | Value |
| --- | --- | --- |
| `records` | Lowercase, fully qualified DNS name, e.g. `app.test.` | All records for that name, across all types, encoded as `DNS1` followed by a Hickory DNS wire message |
| `metadata` | `revision` | An eight-byte big-endian counter used to invalidate DNSSEC snapshots |

- **Read:** normalize the requested name, fetch its value, and filter by record
  type. CNAME lookups follow the target key in the same read transaction.
- **Write:** replace the supplied name/type RRsets while preserving other
  types at that name. Multiple records of one type share the same TTL.
- **Delete:** remove the requested type, or the whole name. Delete the key
  when no records remain.
- **Commit:** apply a batch and increment `revision` in one transaction.
  Invalid batches change neither records nor revision; no-op deletes leave
  the revision unchanged.
- **DNSSEC:** derive signed answers from LMDB and refresh the in-memory
  snapshot when `revision` changes. No separate persistent record store exists.

For example, `records["app.test."]` can contain an A record, an AAAA record,
and two TXT records. Updating its A record preserves its AAAA and TXT records.

The implementation is in `src/store.rs`. Existing address-only values remain
readable and are upgraded to `DNS1` when their name is next written.

## Structured record management

GraphQL accepts `RecordInput` objects:

```json
{"name":"app.test.","recordType":"A","ttl":60,"data":"192.0.2.5"}
```

Specify exactly one of `data` (type-specific RDATA text) or `rdataBase64`
(base64-encoded DNS wire RDATA). The latter supports uncommon types and
DNSSEC records without a text parser for each type. Type names and numeric
`TYPE<number>` labels are accepted. Hickory validates known binary types
before committing. Only IN-class data records are stored; pseudo/query types
such as ANY, AXFR, and OPT cannot be written.

Direct local writes to LMDB:

```sh
cargo run -- record app.test TXT '"hello world"' --ttl 300
cargo run -- record mail.test MX '10 smtp.test.' --ttl 300
cargo run -- record spf.test SPF '"v=spf1 -all"' --ttl 300
cargo run -- record custom.test TYPE65280 '3q2+7w==' --raw
printf '%s' '[{"name":"app.test.","recordType":"A","ttl":60,"data":"192.0.2.5"}]' | cargo run -- write
```

`write` reads a structured JSON array from stdin and commits it directly to
LMDB; it does not create a data file. It supports multiple records per RRset.
`put` replaces an A/AAAA RRset; `record` replaces one type; `write` replaces
only the RRsets present in the batch. Modern SPF policies normally use TXT;
legacy SPF type 99 is also supported.

## HTTPS, DNSSEC, and GraphQL

```sh
./scripts/dev-keys.sh
./scripts/seed-dev.sh
./scripts/run-dev.sh
```

The seed script writes structured records directly into LMDB. The keys script
creates separate TLS/DNSSEC P-256 keys, a localhost certificate, and a random
API token under ignored `.local/`, preserving existing keys. Use your own TLS
certificate and key for a deployed service.

| Flag | Behavior |
| --- | --- |
| `--dns ADDRESS:PORT` | UDP/TCP, e.g. `127.0.0.1:5353` |
| `--doh ADDRESS:PORT` | HTTPS, e.g. `127.0.0.1:8443` |
| `--dot ADDRESS:PORT` | DNS over TLS, e.g. `127.0.0.1:853` |
| `--doq ADDRESS:PORT` | DNS over QUIC, e.g. `127.0.0.1:853` (UDP) |
| `--doh-cert PATH`, `--doh-key PATH` | PEM certificate chain/key unless `--doh-no-cert` |
| `--dot-cert PATH`, `--dot-key PATH` | PEM certificate chain/key unless `--dot-no-cert` |
| `--doq-cert PATH`, `--doq-key PATH` | Required PEM certificate chain/key for DoQ |
| `--doh-no-cert` | Plain HTTP backend; proxy terminates DoH TLS |
| `--dot-no-cert` | Plain TCP DNS backend; proxy terminates DoT TLS |
| `--graphql` | Required in server mode; enables the separate HTTP management API |
| `--listen ADDRESS:PORT` | Management bind address; default `127.0.0.1:3080` |
| `--api-token TOKEN` | Optionally requires a bearer token for management requests |
| `--dnssec-zone DOMAIN` | Authoritative signing domain, e.g. `secure.test.` |
| `--dnssec-key-file PATH` | ECDSA P-256 PKCS#8 PEM signing key, algorithm 13 |

For example, enable only DoT with its own certificate:

```sh
cargo run -- --graphql --dot 127.0.0.1:853 --dot-cert cert.pem --dot-key key.pem
```

When a proxy handles TLS, use plaintext backends without certificate/key flags:

```sh
cargo run -- --graphql --listen 127.0.0.1:3080 \
  --doh 127.0.0.1:8080 --doh-no-cert \
  --dot 127.0.0.1:853 --dot-no-cert
```

DoT's standard public port is TCP 853. The backend can use any explicit port;
if proxy and backend share a host, give them distinct bind addresses or ports.
The `--*-no-cert` flags conflict with that listener's certificate/key flags.
DoQ continues to require its certificate/key because QUIC integrates TLS.

Omitted DNS listener flags leave those listeners disabled. `--graphql` is
required in server mode; local write commands do not require it. The management
API can run alone with `cargo run -- --graphql`, without certificates or keys. Certificate files may be
shared, but each encrypted listener requires its own explicit flags. Hickory
handles DoT and DoQ; DoQ uses TLS 1.3 and ALPN `doq`. Actix serves DoH GET/POST
over HTTP/1.1 and HTTP/2 with Rustls. GraphQL uses a separate plain HTTP
listener at `http://127.0.0.1:3080/graphql`; it is never exposed on DoH. The server has no Hyper
dependency (the CLI's reqwest client still uses Hyper internally).

Without `--api-token`, management requests do not require authentication. DoH uses `/dns-query`: GET with
a base64url `dns` parameter or POST with `application/dns-message`.
Limits are 65,535 bytes for DoH and 1 MiB for GraphQL. HTTP responses use
`Cache-Control: no-store`. See `cargo run -- --help` for all flags.

DNSSEC requires apex SOA and NS records already in LMDB. Hickory signs positive
and negative responses, including NXDOMAIN/NODATA proofs, and honors EDNS's DO
bit. Signatures last seven days. Failed re-signing returns SERVFAIL. The
DNSKEY can be a local trust anchor; public trust requires a matching DS at
the parent. Key rollover and recursive upstream validation are not automated.

```graphql
query {
  names(prefix: "app", limit: 100)
  records(name: "app.test", recordType: "A") {
    name recordType ttl data
  }
}

mutation {
  upsert(records: [
    {name: "app.test.", recordType: "A", ttl: 60, data: "192.0.2.20"}
  ])
}

mutation {
  delete(name: "app.test", recordType: "A")
}
```

`names` is paginated lexically: pass the last returned name as `after`.
`records` returns exact LMDB records, not CNAME resolution or generated
signatures. Omit `recordType` to read/delete all types at a name. GraphQL
prevents deleting the signing domain's apex SOA/NS. GraphQL execution errors
are returned in the JSON `errors` field.

## GraphQL CLI

`cmd/` is the workspace's `dnsctl` Cargo package, producing the `cmd` binary.
It uses Clap and communicates with GraphQL over HTTP. Its default endpoint
is `http://127.0.0.1:3080/graphql`.

```text
cmd <get/set/del> <domain> <record-type> [value]
```

```sh
cargo build -p dnsctl
# Add these connection flags to each cmd invocation:
# --token "$(cat .local/api-token)"
./target/debug/cmd get host.secure.test A
./target/debug/cmd del app.secure.test A
./target/debug/cmd set app.secure.test A 192.0.2.20
./target/debug/cmd set app.secure.test AAAA 2001:db8::20 --ttl 60
./target/debug/cmd set app.secure.test TXT '"hello world"'
./target/debug/cmd set mail.secure.test MX '10 smtp.secure.test.'
./target/debug/cmd set custom.test TYPE65280 '3q2+7w==' --raw
```

Or run through Cargo: `cargo run -p dnsctl -- get app.secure.test A`.
`get` and `del` accept no value. `del` removes only the specified record type. `set` requires a value and replaces that name/type
RRset while preserving other types. TTL defaults to 300 seconds; use `--ttl`
to override it. `--raw` interprets the value as base64-encoded wire RDATA.

Batch commands run in the supplied order:

```sh
./target/debug/cmd batch \
  --item "set,app.secure.test,A,192.0.2.20" \
  --item "get,app.secure.test,A"
```

Each `--item` is one CSV record: `get,domain,record`, `del,domain,record`,
or `set,domain,record,value`. Values containing commas use CSV quoting; for
example, `--item 'set,app.test,TXT,"""hello, world"""'` stores a TXT string.
Batch sets use a 300-second TTL. The output is a JSON array in item order.
All item formats are checked before any request is sent. Requests then run
sequentially using one HTTP client, so later reads see earlier writes. A
server error stops execution with a nonzero status; preceding writes remain
committed. The batch is not one transaction.

Connection options: `--endpoint`, `--token`, and `--ca-cert`. Options can appear before or after the positional
arguments. Output is JSON; TLS, HTTP, authentication, and GraphQL errors
produce a nonzero exit status. Redirects are disabled. Listing and atomic multi-record writes remain available through GraphQL.

## Tests and benchmark

```sh
./scripts/test.sh
./scripts/bench.sh
```

The test script prepares Python dependencies, checks formatting/Clippy, builds
both packages, and runs Rust plus Python integration tests. Fixtures are
structured records written directly to temporary LMDB environments. Tests
cover 27 record types over UDP/TCP/DoH/DoT/DoQ, DNSSEC signature/proof validation,
GraphQL and CLI CRUD, authentication, TLS, concurrent queries, persistence,
atomic rollback, and UDP truncation/TCP fallback.

The release benchmark writes 100,000 mixed-type records to LMDB through stdin,
then queries 10,000 distinct random names over UDP loopback with a window of
128 requests. A 1,000-query warmup precedes measurement. The one-second gate
includes network exchange and independent Python validation of every answer;
setup, database writes, and query encoding are excluded. No retries or response
cache are used. Results go to ignored `dist/benchmark.json`. DNSSEC signing is
disabled for this baseline throughput benchmark.

## Source and native library

`src/` is flat: `store.rs`, `records.rs`, `resolver.rs`, `dnssec.rs`, `doh.rs`,
`dot.rs`, `doq.rs`, `graphql.rs`, `config.rs`, `lib.rs`, and `main.rs`.
Shared HTTP routing, server startup, and TLS helpers are in `doh.rs`.

`doctor.sh` compiles the locked `lmdb-sys` dependency's LMDB sources into
`.local/lmdb/lib/liblmdb.a`. Cargo uses `.cargo/config.toml` to link it statically.
Requires Cargo, Python 3, a C compiler, `ar`, and `pkg-config` (`brew install
pkgconf` on macOS). Re-run after changing LMDB versions or host architecture.
Build output, libraries, virtual environments, database files, and benchmark
results are gitignored; keep `Cargo.lock` in version control.

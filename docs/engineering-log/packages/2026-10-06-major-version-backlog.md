# The major-version backlog: what is behind, and the order to take it in (2026-10-06)

Dependabot's weekly pull request takes minor and patch releases and ignores
major ones (`.github/dependabot.yml`). This is the list of what that leaves.

## Measured

Every direct dependency of every workspace member (105 distinct crates from
the registry), compared with the newest stable release in the crates.io
index. 29 are behind a breaking release (a new major, or a new minor of a
0.x crate):

| Crate | Locked | Newest | Workspace crates that declare it |
|---|---|---|---|
| `aes-gcm` | 0.10.3 | 0.11.1 | 5 |
| `age` | 0.11.5 | 0.12.1 | 1 |
| `async-nats` | 0.47.0 | 0.50.0 | 25 |
| `bcrypt` | 0.18.0 | 0.19.3 | 10 |
| `cap-std` | 3.4.6 | 4.0.3 | 3 |
| `constant_time_eq` | 0.3.1 | 0.6.1 | 3 |
| `criterion` | 0.5.1 | 0.8.2 | 1 |
| `croner` | 2.2.0 | 4.0.1 | 3 |
| `ed25519-dalek` | 2.2.0 | 3.0.0 | 2 |
| `hkdf` | 0.12.4 | 0.13.0 | 3 |
| `jsonwebtoken` | 10.4.0 | 11.1.0 | 8 |
| `md5` | 0.7.0 | 0.8.1 | 1 |
| `opentelemetry` | 0.32.0 | 0.33.0 | 7 |
| `opentelemetry-otlp` | 0.32.0 | 0.33.0 | 3 |
| `opentelemetry-prometheus` | 0.32.0 | 0.33.0 | 1 |
| `opentelemetry_sdk` | 0.32.1 | 0.33.0 | 6 |
| `petgraph` | 0.6.5 | 0.8.3 | 5 |
| `quick-xml` | 0.41.0 | 0.42.0 | 1 |
| `redis` | 0.27.6 | 1.7.1 | 22 |
| `reqwest` | 0.12.28 | 0.13.5 | 29 |
| `sqlparser` | 0.53.0 | 0.63.0 | 3 |
| `sqlx` | 0.8.6 | 0.9.0 | 76 |
| `testcontainers` | 0.27.3 | 0.28.0 | 1 |
| `totp-rs` | 5.7.2 | 6.0.0 | 2 |
| `tracing-opentelemetry` | 0.33.0 | 0.34.0 | 5 |
| `wasmparser` | 0.224.1 | 0.261.0 | 1 |
| `wit-component` | 0.224.1 | 0.261.0 | 1 |
| `wit-parser` | 0.224.1 | 0.261.0 | 1 |
| `x25519-dalek` | 2.0.1 | 3.0.0 | 1 |

Frontend and Node are not in this table; they are a separate survey.

## Order

One dependency, or one family that must move together, per pull request.
Smallest reach first, so the method is settled before the wide ones.

1. **Done here:** `constant_time_eq` — removed as a direct dependency
   (`2026-10-06-csrf-compare-uses-subtle.md`).
2. **One or few users:** `md5`, `quick-xml`, `criterion`, `cap-std`,
   `petgraph`, `croner`. `croner` parses schedule expressions: compare the
   next-run times of every schedule on the fleet before and after.
3. **One family:** `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`,
   `opentelemetry-prometheus` with `tracing-opentelemetry`.
4. **Authentication:** `bcrypt`, `totp-rs`, `jsonwebtoken`. Each guards a
   login or a token; mutation-prove.
5. **The SQL classifier:** `sqlparser`, ten releases. It decides whether a
   statement is a read (the write ceiling and the sandbox depend on it);
   mutation-prove, and replay the classifier's corpus.
6. **Transport:** `async-nats`, `redis`, `reqwest`. Wide (22 to 29 crates);
   each on its own.
7. **Encryption, as one family:** `aes-gcm`, `hkdf`, `ed25519-dalek`,
   `x25519-dalek` (they share the RustCrypto trait crates). Stored
   ciphertext and signed wire formats must read back byte-for-byte: the
   wire-format snapshots and a decrypt of rows written before the change are
   the tests.
8. **`sqlx`**, last: 76 crates, the offline query cache, and 0.9.0 is the
   first release of its line.

## Held, with the reason

* **`age` 0.12.** `talos-offhost-backup/Cargo.toml` records the decision:
  0.12 adds post-quantum recipients and brings `hpke`, `ml-kem`, `p256` and
  `sha3` for a feature nothing here uses. New fact since: its build-time
  dependency `proc-macro-error2` will be rejected by a future Rust
  (`2026-10-06-rust-1.99.md`). That makes the hold temporary, not wrong
  today.
* **`testcontainers` 0.28.** `testcontainers-modules` has no release for it.
* **`wasmparser` / `wit-component` / `wit-parser`.** One crate declares
  them. The lockfile already carries three other versions of each (0.244,
  0.258, 0.259 of `wasmparser`) as transitive dependencies, not looked into
  here. Move the direct pin with the next `wasmtime` bump, to a version the
  tree already carries, rather than adding a fifth.

## How the table was made

`cargo metadata` for the members' direct registry dependencies, the sparse
index (`https://index.crates.io/…`) for each crate's newest non-yanked stable
release. A first attempt through the crates.io API with Python's `urllib`
reported "0 behind": every request failed certificate verification and the
script skipped failures. The second version reports unreadable crates; it
read all 105.

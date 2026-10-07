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
2. **One or few users:** `md5` (#1161), `quick-xml` (#1162), `criterion`
   (#1165), `cap-std` (#1166). (`petgraph` and `croner` were in this group;
   both are held, below.)
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
* **`croner` 3 and 4** (measured 2026-10-06; `2026-10-06-croner-held.md`).
  Both fire a daily job twice on the spring-forward day when it is scheduled
  in the hour before the gap. 2.2 does not. Held until that is fixed
  upstream; `dst_behaviour_tests` in `talos-scheduler` is what a future bump
  has to pass or consciously change.
* **`petgraph` 0.8** (measured 2026-10-06). `wasmtime` 49 depends on
  `wasm-compose`, which requires `petgraph ^0.6.2` — and so does the newest
  `wasm-compose` (0.261.0). Moving the five workspace crates to 0.8 would
  therefore ship two copies (0.6.5 and 0.8.3, with `fixedbitset` 0.4 and 0.5)
  in the controller and the worker, for an API the workspace uses only the
  stable core of (`DiGraph`, `NodeIndex`, `neighbors_directed`,
  `edges_directed`, `is_cyclic_directed`, `Dfs`). Move when `wasm-compose`
  does. `controller` declares `petgraph` and calls it nowhere; that goes
  with the unused-declaration sweep below.
* **`wasmparser` / `wit-component` / `wit-parser`.** One crate declares
  them. The lockfile already carries three other versions of each (0.244,
  0.258, 0.259 of `wasmparser`) as transitive dependencies, not looked into
  here. Move the direct pin with the next `wasmtime` bump, to a version the
  tree already carries, rather than adding a fifth.

## Found while working the list: declared and never named

Done the same day: `2026-10-06-unused-declarations.md` (136 declarations,
47 crates, and a check in `make lint`). The paragraph below is the finding
as first written.

Three times in the first five items a crate declared a dependency it never
calls (`constant_time_eq` in two crates, `cap-std` and `petgraph` in
`controller`). A sweep of every workspace crate for a declared dependency
whose name appears nowhere in that crate's code lists 117 candidates, 45 of
them in `controller` (left over from the May-2026 split, when its modules
became crates and its manifest kept their dependencies). It is a heuristic:
a declaration can exist only to switch on a feature of a crate another
dependency uses, and removing that one changes what is compiled without
failing a build. So the sweep is its own package, verified by comparing the
resolved feature set of every package in the shipped binaries before and
after, not by a green build alone.

## How the table was made

`cargo metadata` for the members' direct registry dependencies, the sparse
index (`https://index.crates.io/…`) for each crate's newest non-yanked stable
release. A first attempt through the crates.io API with Python's `urllib`
reported "0 behind": every request failed certificate verification and the
script skipped failures. The second version reports unreadable crates; it
read all 105.

## Closed out, and corrected (2026-10-07)

**Every item in the order above is merged**: `md5` (#1161), `quick-xml`
(#1162), `criterion` (#1165), `cap-std` (#1166), the OpenTelemetry family
(#1174), `bcrypt` (#1175), `totp-rs` (#1176), `jsonwebtoken` (#1177),
`sqlparser` (#1180), `async-nats` (#1182), `redis` (#1183), `reqwest`
(#1184, with `oci-client` in #1185), `sha2`/`hmac`/`hkdf` (#1186), `aes-gcm`
(#1187), `ed25519-dalek`/`x25519-dalek` (#1188), `sqlx` (#1189).

**The table above was short by five.** Re-measured after the last merge, 12
direct dependencies are behind a breaking release — the seven held ones, and
five the table never listed:

| Crate | Built with | Newest | Workspace crates that declare it |
|---|---|---|---|
| `secrecy` | 0.8.0 | 0.10.3 | 1 |
| `syn` | 2.0.119 | 3.0.6 | 1 |
| `governor` | 0.6.3 | 0.10.4 | 2 |
| `base64` | 0.22.1 | 0.23.1 | 11 |
| `rand` | 0.8.8 | 0.10.3 | 22 |

For each of the five the lockfile already holds the newer version, brought
in by some other crate (`rand` 0.10.1, `base64` 0.23.1, `governor` 0.10.4,
`secrecy` 0.10.3, `syn` 3.0.6). The script that made the table was not kept,
so why it missed them cannot be shown; comparing the newest copy of a name
anywhere in the lockfile, rather than the version the member is built with,
would miss exactly these — and `sha2` and `hmac`, which were also absent and
were only moved because `hkdf` needed them. All five releases predate the
table, so none is a new arrival.

The survey is now `scripts/survey-major-versions.py`. It reads the version
each member's declaration resolves to, reports a crate it cannot read rather
than skipping it, and its self-test holds the case above: a newer copy
elsewhere in the tree does not hide the one the member is built with.

**The five are the remaining list**, smallest reach first: `secrecy`, `syn`,
`governor`, `base64`, `rand`. Each also removes a second copy of the crate
from the build.

**The held ones were re-tested against the index, and each reason still
holds**: `testcontainers-modules` 0.15.0 (the newest) requires
`testcontainers ^0.27`; `wasm-compose` 0.261.0 (the newest) requires
`petgraph ^0.6.2`; `wasmtime` 49.0.2 is the newest and is what is locked, so
there is no bump to move the `wasmparser` family with; `croner` 4.0.1 is the
release that was measured; `age` 0.12.1 is unchanged.

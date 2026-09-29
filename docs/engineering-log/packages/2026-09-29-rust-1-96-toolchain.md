# 2026-09-29 — Rust toolchain 1.95 → 1.96

**Why.** Wasmtime backported RUSTSEC-2026-0313…0316 only to 36.0.16 (LTS) and
48.0.3. 48 stops receiving security backports once Wasmtime 50 ships, and the
next line, 49.x, requires Rust 1.96. This package moves the toolchain alone, so
the Wasmtime 49 upgrade that follows is a dependency change reviewed on its own.
Neither change should hide inside the other.

**Decided.**
- **Every pin moved together, as `rust-toolchain.toml`'s own bump strategy
  says.** The pins:
  - `rust-toolchain.toml` (`channel = "1.96"`, resolved locally to 1.96.1);
  - the workspace `rust-version`;
  - `RUST_TOOLCHAIN` in `quality.yml` and `ci.yml`;
  - the three Dockerfiles' five `FROM` lines;
  - the pentest-scope doc's stack line.
- **Image digests are the official index digests**, read with
  `docker buildx imagetools inspect`:
  - `rust:1.96` (`sha256:1f0dbad1…`) for the controller and worker;
  - `rust:1.96-slim-bookworm` (`sha256:e18a79fc…`) for `Dockerfile.builder`.

  Check 93 (every image digest-pinned) passes.
- **The worker's runtime stage is unchanged,** because the builder's Debian
  release is. `rust:1.96` and `rust:1.96-trixie` share one digest, so the builder
  is still trixie, matching `debian:trixie-slim` (the worker Dockerfile's
  GLIBC/OpenSSL rule).
- **The `clippy 0.1.95` mentions in `clippy.toml`, `docs/ci.md` and
  `lint-structural.sh` are left as written:** they record what was measured on
  that version, not a pin.

**Proof, all on rustc/cargo/clippy 1.96.1.**
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets --no-deps -- -D warnings`: clean. The
  new release raised no lint in this workspace, so there was nothing to fix.
- CI's three DB-free test steps, exactly as `quality.yml` runs them:
  - `nextest --workspace --lib --bins`: 6 909 passed (5 skipped);
  - `scripts/ci-run-dbfree-tests.sh`: all passed;
  - `cargo test --workspace --doc`: all passed.
- `scripts/check-catalog.sh`: all 75 catalog templates compile for
  `wasm32-wasip2` with cargo-component 0.21.1.
- Structural lints and `make lint`: clean.
- The builder, controller and worker images build on the new base images (tagged
  `:rust196-check` locally, never over the running stack's tags).

**Stated limits.**
- **The DB integration suite was not run locally.** It needs the harness's
  Postgres, Redis and NATS, which CI provisions; the three `quality.yml`
  integration shards are its gate.
- **Found, not fixed:** `scripts/check-catalog.sh` fails under macOS's bash 3.2
  (CI uses bash 5 and is unaffected). Flagged as its own task.
- **Local side effect, stated:** installing 1.96 self-updated rustup 1.29.0 →
  1.29.1 on the build host.
- **The first local controller image build failed on Docker Desktop's VM disk**
  (`apt-get`: not enough free space), not on Rust. It passed after removing
  this session's own check images. That VM holds ~34 GB of build cache and
  ~37 GB of volumes, most of it reclaimable; pruning it is the operator's call.

**Next:** Wasmtime 48.0.3 → 49.0.1 on this toolchain, with the upgrade
checklist in `docs/wasmtime-version-tracking.md` and a `TALOSV10` AOT header.

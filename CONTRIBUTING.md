# Contributing to Talos

This page gets you from a fresh clone to a **safe first PR**. It is deliberately short; the deep material lives in `CLAUDE.md` (the de-facto architecture doc) and `docs/`.

## First-time setup

```bash
make setup      # generates .env with secrets, builds, starts the stack
make hooks      # installs the git hooks (core.hooksPath=.githooks) — DO THIS ONCE
```

`make hooks` is not optional in spirit: the **pre-push** hook runs the same CI-parity gates as `quality.yml` (`make lint` + `make lint-frontend`), and the **pre-commit** hook runs the fast secret/migration/compile checks. Skipping it means CI catches what your machine should have.

## Before you open a PR

```bash
make lint                 # rustfmt + WIT drift + the structural lints + clippy + cargo-deny
make lint-frontend        # eslint + prettier + vitest
cargo test --workspace    # (heavy; the pre-push hook + quality.yml also run this)
```

`bash scripts/lint-structural.sh --count` prints the number of structural checks; `bash scripts/lint-structural.sh` runs them. Each check is tied to a specific past regression and is documented inline in the script.

## The lint opt-out convention

The structural lints (`scripts/lint-structural.sh`) are grep-based and intentionally conservative. When a check flags a line that is a **documented, legitimate exception**, you suppress it with a same-line or nearby marker comment carrying a reason — never by deleting the check. Each check documents its own marker; the common ones:

- `// allow-actor-memory-sql: <reason>` — raw `actor_memory` SQL outside `talos-memory/`
- `// allow-mcp-sqlx: <reason>` — raw `sqlx::query` in `talos-mcp-handlers/`
- `// allow-bare-pool-rls: <reason>` — a bare-pool read on an RLS table in `talos-api/src/schema`
- `// allow-secrets-manager-new` — a `SecretsManager::new` outside canonical wiring
- `// no-nginx-route: <reason>` / `# no-controller-route` — intentional route↔nginx asymmetry
- `// allow-unscoped-org-write` — an org-pinned create on a non-tenant-scoped tx (engine/seeding)

A marker without a real reason is a review red flag. The default path is almost always "do the thing the check wants" (push SQL into a repository, scope the tx, etc.), not to suppress it.

## Required reading, by task

- **Adding an integration** (OAuth provider, third-party API, push source) → `docs/adding-an-integration.md` (the authoritative guide + checklist) and, for watch/webhook push, `docs/integration-pattern.md`. `talos-slack` is the canonical `OAuthIntegration` reference.
- **Adding a signed-RPC primitive** → `docs/platform-primitive-checklist.md` (ten defense-in-depth fixes captured so the next primitive doesn't repeat them; `talos-rpc-subscribers/src/kernel.rs` is the shared kernel to build on).
- **Adding an MCP tool** → keep the handler thin (parse → validate → service → format); new logic goes in a domain/application service, not inline. Register the tool's `tool_schemas()` module in `schema_parity_tests.rs` and `static_tool_count()`.
- **Anything touching secrets / encryption** → the "Secret Handling Rules" and "Per-context AEAD subkeys" sections of `CLAUDE.md`.
- **Security architecture / threat model** → `docs/security/`.

## Where things live

The controller binary is bootstrap only; ~110 `talos-*` workspace crates own the implementation. A path like `crate::foo::bar` in the controller is sugar for `talos_foo::bar` (re-export shims). New logic goes in the home crate, never in a shim.

## Migrations

- Never edit an already-applied migration (breaks the sqlx checksum). Ship a follow-up migration that corrects it.
- New files: `YYYYMMDDHHMMSS_description.sql`, idempotent (`IF NOT EXISTS` / `IF EXISTS`), no `CONCURRENTLY` (sqlx runs them in a transaction).

## Getting unstuck

`QUICKSTART.md` has a troubleshooting section mapping common failure modes (stale Docker cache, sealed Vault, migration failures) to fixes. Docker build oddities usually want `make docker-clean-rebuild`.

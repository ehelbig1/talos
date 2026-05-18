# Talos — Repository Guidelines for Automated Agents

## Architecture & Terminology

Talos is a visual workflow automation platform. Use these terms precisely; they are enforced at the
database, API, and UI layers:

| Term | Definition | DB table |
|---|---|---|
| **Template** | Reusable blueprint: Rust source + JSON config schema | `node_templates` |
| **Module** | Compiled WASM binary produced from a template | `wasm_modules` |
| **Node** | A module instance placed on a workflow canvas | `workflow_nodes` |
| **Workflow** | A DAG of connected nodes | `workflows` |
| **Module Execution** | A standalone run of a module (webhook / manual / schedule) | `module_executions` |
| **Webhook Trigger** | HTTP endpoint config that fires a module execution | `webhook_triggers` |

**"Node" means a canvas element only.** Never use "node" for a compiled module or a standalone execution.

---

## Project Structure

```
talos/
├── controller/          # Rust — GraphQL API + REST endpoints (Axum + async-graphql)
│   ├── src/
│   │   ├── api/schema.rs          # All GraphQL types, queries, mutations
│   │   ├── module_executions.rs   # ModuleExecutionService + logs
│   │   ├── registry/mod.rs        # ModuleRegistry (templates + compiled modules)
│   │   ├── webhooks/mod.rs        # WebhookRouter, WebhookTrigger
│   │   ├── compilation/mod.rs     # Rust→WASM compile pipeline
│   │   ├── secrets/mod.rs         # Envelope encryption, DEK caching
│   │   ├── auth/mod.rs            # JWT + 2FA
│   │   ├── security_headers.rs    # CSP, HSTS, rate limiting
│   │   └── main.rs                # Server bootstrap, middleware stack
│   └── tests/                     # Integration tests (require live DB)
├── worker/              # Rust — WASM runtime (Wasmtime + WASI)
│   └── src/
│       ├── runtime.rs             # TalosRuntime, component execution
│       ├── host_impl.rs           # WIT host function implementations
│       └── metrics.rs             # Prometheus metrics
├── job-protocol/        # Rust — shared NATS job message types
├── frontend/            # TypeScript/React — visual workflow editor
│   └── src/
│       ├── components/            # React components
│       │   ├── builder/ModuleBuilder.tsx    # Compile-from-template wizard
│       │   ├── CreateModuleDialog.tsx        # Template → module dialog
│       │   ├── TalosNode.tsx                # Workflow canvas node (ReactFlow)
│       │   └── Workspace.tsx               # Workflow canvas
│       ├── store/workflowStore.ts           # Zustand canvas state
│       └── lib/graphqlClient.ts            # GraphQL fetch helper
├── migrations/          # Sequential PostgreSQL migrations (sqlx)
├── templates/           # Built-in node template source files
├── wit/talos.wit        # WIT interface definitions for WASM capabilities
└── docker-compose.yml   # Dev environment
```

---

## Build & Development Commands

| Command | Description |
|---|---|
| `make up` | Start all services (Docker Compose) |
| `make down` | Stop all services |
| `make build` | Build all Docker containers |
| `make rebuild` | Rebuild containers without cache |
| `make logs` | Follow logs from all services |
| `make dev` | Start dev environment and follow frontend logs |
| `make up-dev` | Build, start, and open an ngrok tunnel |
| `make lint` | `cargo fmt --check` + `cargo clippy --workspace` |
| `make db-shell` | Open a psql shell against the dev database |
| `make reset-db` | Drop and recreate the database (destroys data) |

### Rust (controller / worker)

```bash
# Compile-check without a live DB (required for CI / offline development)
SQLX_OFFLINE=true cargo check -p controller
SQLX_OFFLINE=true cargo check -p worker

# Run unit tests (no DB required)
SQLX_OFFLINE=true cargo test --lib -p controller
SQLX_OFFLINE=true cargo test --lib -p worker

# Run all tests including integration tests (requires live DB)
cargo test --workspace

# Format & lint
cargo fmt
cargo clippy --workspace
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # Dev server on http://localhost:3000
npm run build      # Production build
npx tsc --noEmit   # Type check only
```

### Database migrations

```bash
# Apply pending migrations (requires live DB)
sqlx migrate run

# After changing any sqlx::query! macros, regenerate the offline cache:
cargo sqlx prepare -p controller -- --lib
```

---

## Coding Conventions

### Rust
- `snake_case` for functions, variables, modules, file names
- `PascalCase` for structs, enums, traits
- `SCREAMING_SNAKE_CASE` for constants
- File names match the module they contain (`module_executions.rs`)
- Tests live in a companion file included via `#[path = "…_tests.rs"]`

### TypeScript / React
- `PascalCase` for component files and names (`ModuleBuilder.tsx`)
- `camelCase` for functions, variables, props
- Component filenames match the exported component name exactly

### SQL / Migrations
- Table names: `snake_case`, plural
- Sequential numbered files: `migrations/NNN_description.sql`
- Always use `IF NOT EXISTS` / `IF EXISTS` guards
- Include a self-validating `DO $$ … $$` block at the end of each migration

---

## Key Patterns

### Authorization — always verify ownership
```rust
let result = sqlx::query!(
    "UPDATE module_executions SET ... WHERE id = $1 AND user_id = $2",
    id, user_id
).execute(&self.db_pool).await?;

if result.rows_affected() == 0 {
    anyhow::bail!("Not found or access denied");
}
```

### SQLX offline cache
When adding a new `sqlx::query!` macro, you must add a matching entry to
`.sqlx/query-<sha256>.json` and `controller/.sqlx/query-<sha256>.json`.
The hash is `SHA256(query_string_bytes)`.

```python
import hashlib
print(hashlib.sha256(query.encode()).hexdigest())
```

### UTF-8 safe string truncation
```rust
// WRONG — can panic at a multi-byte boundary:
let s = &long_string[..10_000];

// CORRECT — truncate by character count:
let s: String = long_string.chars().take(10_000).collect();
```

### Best-effort logging (never fail an operation due to a log write)
```rust
if let Err(e) = service.add_log(execution_id, level, msg, metadata).await {
    tracing::warn!("Failed to write log: {}", e);
}
```

---

## GraphQL API Shape

```graphql
# Queries
templateAiToolSchemas     # MCP-compatible tool list (one per node_template)
nodeTemplates             # List all templates
myModules                 # List user's compiled modules
webhookTriggers           # List user's webhook trigger configs
workflows                 # List user's workflows

# Mutations
createModuleFromTemplate(input: CreateModuleInput!)  # Compile template → WASM module
createWebhookTrigger(input: CreateWebhookTriggerInput!)
createWorkflow / triggerWorkflow
createSecret / updateSecret
```

---

## Testing Guidelines

- Unit tests live in `controller/src/*_tests.rs` (loaded via `#[path = "…"]`)
- Integration tests live in `controller/tests/`
- All tests must pass with `SQLX_OFFLINE=true`
- Aim for tests covering: UTF-8 boundary conditions, authorization (wrong user_id),
  JSONB size limits, and happy paths
- Do **not** commit tests that require secrets or external network access

---

## Security Rules

1. **Never expose raw error details to the client** — log internally, return a generic message
2. **Always filter queries by `user_id`** — never return cross-user data
3. **Sanitize all user-supplied strings** — strip control characters, truncate at character (not byte) boundaries
4. **JSONB fields have a 1 MB size limit** — validate before inserting
5. **Secrets are envelope-encrypted** — never store plaintext; use `SecretsManager`
6. **Never commit `.env` files or real credentials**

---

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `JWT_SECRET` | Yes | Signs access tokens |
| `WORKER_SHARED_KEY` | Yes | HMAC key for controller↔worker job signing |
| `BASE_URL` | Yes | Public base URL (used in webhook URLs) |
| `ALLOWED_ORIGIN` | Prod only | CORS allowed origin |
| `RUST_ENV=production` | Prod only | Enables strict CSP, HSTS, rate limiting, disables GraphiQL |
| `NATS_URL` | Optional | NATS server for job dispatch |
| `REDIS_URL` | Optional | Redis for caching / deduplication |

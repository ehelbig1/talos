# Integrating Talos with an external app

How to wire a Talos workflow to push results into a sister application
running on the same host (the canonical example: `pa-followup-tracker`
dispatching tasks into the `nova` PA app on `localhost:3030`).

This doc captures the friction encountered the first time this pattern
was implemented end-to-end so the next operator hits zero of those
issues. The platform-side fixes that lowered the friction are noted
inline.

## The reference shape

```
                          ┌──────────────────────────────┐
                          │ Talos workflow               │
                          │   detect-node (agent-node)   │
                          │     │                        │
                          │     ▼                        │
                          │   webhook-fanout (catalog)   │
                          └─────┬────────────────────────┘
                                │ POST /api/talos/webhook
                                │ x-auth-token: <vault-resolved>
                                ▼
                  ┌──────────────────────────────┐
                  │ External app                 │
                  │   /api/talos/webhook         │
                  │     │ verify token           │
                  │     ▼                        │
                  │   inserts row in app DB      │
                  └──────────────────────────────┘
```

## Setup checklist

### 1. External app side

- Pick a stable bearer-style auth header (we use `x-nova-webhook-token`
  in nova). RFC 7235 `Authorization: Bearer <token>` also works — set
  `AUTH_HEADER_NAME` accordingly.
- Generate a strong shared secret: `openssl rand -hex 32`.
- Store the token in the app's env (`NOVA_WEBHOOK_TOKEN=<value>`).
- Webhook handler MUST: (a) reject if token is missing/wrong using
  constant-time compare, (b) reject if the env-side token is unset
  (don't fail open), (c) parse the body with a typed validator.
- Restart the app so it loads the new env var.

### 2. Talos vault

Add the same token to Talos vault at a stable path (we use
`nova/webhook_token`):

```
key_path: nova/webhook_token
value:    <the same hex string>
```

Set via the Talos frontend (Secrets → New). MCP is intentionally
read-only for secrets (MCP-1201) — secret writes require 2FA, which
MCP bearer tokens cannot provide.

### 3. Module install + workflow node

```text
install_module_from_catalog(name: "webhook-fanout")
# returns: module_id <UUID>

add_node_to_workflow(
  workflow_id: <your workflow>,
  node_id: "post-to-nova",
  module_id: <UUID from above>,
  connect_from: "<upstream node id>",
  config: {
    "URL": "http://host.docker.internal:3030/api/talos/webhook",
    "INPUT_FIELD": "stale",                       # field on upstream output
    "AUTH_HEADER_NAME": "x-nova-webhook-token",
    "AUTH_HEADER_VALUE": "vault://nova/webhook_token",
    "TIMEOUT_MS": 5000
  },
  continue_on_error: true,
)
```

The `webhook-fanout` module:
- Reads `data["input"][INPUT_FIELD]` as an array (falls back to
  `data["input"]` itself if it's already an array).
- POSTs each item as a JSON body, fanning out one request per item.
- Resolves `AUTH_HEADER_VALUE` from vault at fetch time so the token
  never enters guest WASM memory.
- Rejects literal (non-`vault://`) tokens as a fail-closed guard
  against accidental plaintext leakage.

### 4. Worker private-network bridge

The worker container reaches host services via `host.docker.internal`
(Mac/Windows Docker). Talos's SSRF protection blocks DNS-resolved
private IPs by default — opt in for explicitly-allowlisted hostnames:

```bash
# /Users/<you>/projects/talos/.env
WORKER_ALLOW_PRIVATE_HOST_TARGETS=true
```

Then `docker compose restart worker`. Verify:

```bash
docker exec talos-worker-1 sh -c 'echo $WORKER_ALLOW_PRIVATE_HOST_TARGETS'
# → true
```

Security properties:

- IP literals to private ranges (e.g. `http://192.168.1.10/`) remain
  blocked unconditionally regardless of the env var.
- Wildcard `allowed_hosts: ["*"]` keeps full SSRF protection — the
  bypass requires an exact hostname match in `allowed_hosts`.
- Bypass triggers a debug log so operators can audit when it fires.

Linux Docker doesn't ship `host.docker.internal` by default — add an
`extra_hosts` entry to the worker service in `docker-compose.yml`:

```yaml
worker:
  extra_hosts:
    - "host.docker.internal:host-gateway"
```

### 5. Test

```text
call_workflow(workflow_id: <your workflow>)
```

Expected output from the `webhook-fanout` node:

```json
{
  "url": "http://host.docker.internal:3030/api/talos/webhook",
  "candidate_count": 1,
  "dispatched": 1,
  "errors": 0,
  "error_samples": [],
  "truncated_to_max_items": false,
  "stopped_on_error": false
}
```

Verify the row landed in the app's DB.

## Common errors and what they mean

| Error                                                         | Cause                                                                                        | Fix                                                                                              |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `forbiddenhost`                                               | Worker SSRF blocked the DNS-resolved private IP                                              | Set `WORKER_ALLOW_PRIVATE_HOST_TARGETS=true` AND list the hostname in `allowed_hosts` explicitly |
| `AUTH_HEADER_VALUE must start with 'vault://'`                | You configured a literal token in node config instead of a vault path                        | Use `vault://path/to/secret`. Storing literal tokens in graph_json defeats the no-plaintext guarantee. |
| `Header 'X' references vault://path which is not in this module's allowed_secrets grant` | Module wasn't compiled with this vault path in `allowed_secrets`                  | For `webhook-fanout` (catalog), the vault path must be added to the module's `allowed_secrets` via `update_module_secrets`. |
| `vault://...` literal arriving inside guest code via `data["config"]["X"]` | You expected node-config vault-substitution. It only happens for HTTP HEADER values. | Either (a) use the value as a header (worker resolves at fetch time) or (b) use `secrets::get-secret(path)` from inside the module. |
| `Module not found or access denied` (from `hot_update_module`) | UUID confusion: workflow graphs reference template_id; wasm_modules has a different id      | As of post-this-doc Talos, `hot_update_module` and `get_module_info` accept either UUID. If you're on an older controller, look up `wasm_modules.id` via `psql` and retry. |

## Platform fixes shipped to lower this friction

These are applied — listed here so future operators know the rough
edges have already been smoothed.

- **`WORKER_ALLOW_PRIVATE_HOST_TARGETS` env var** — operator opt-in for
  worker → host-bridge calls. (commit `5d10d06`)
- **`hot_update_module` accepts EITHER `wasm_modules.id` OR `template_id`** —
  no more "which UUID do I pass?" confusion. (this commit)
- **`get_module_info` returns both `wasm_module_id` and `template_id`** —
  no `psql` round-trip to find the other id. (this commit)
- **`webhook-fanout` catalog module** — replaces ~200 lines of inline
  custom Rust per integration. (this commit)
- **SSRF rejection log includes the env-var hint** — first-time hitters
  see the unblock command in the worker logs without spelunking. (this commit)
- **`hot_update_module.affected_count` matches workflows by both
  `wasm_modules.id` and `template_id`** — no more misleading
  "affected_count: 0" on graphs that ARE affected. (this commit)
- **Nova webhook receiver pattern** — see `nova/src/app/api/talos/webhook/route.ts`
  for the canonical inbound shape: discriminated-union event types,
  constant-time token compare, fail-closed when env-side token unset.

## Out of scope (deferred backlog)

- `validate_workflow` does not currently probe declared `*_url` config
  values for reachability. Tradeoff: outbound HTTP from controller at
  validation time has its own rate-limit and timeout headaches; punt
  until a real failure makes it worth doing.
- No per-execution module-dispatch trace tool (`module_dispatch_trace`
  proposed). Would surface "engine served bytes from wasm_modules /
  node_templates / Fallback 2; content_hash; compiled_at" so cache /
  hot-update issues are one query away. Substantial enough to deserve
  its own session.
- MCP is read-only for secrets by design (MCP-1201). Webhook tokens
  and other secrets are provisioned exclusively via the Talos
  frontend (Secrets → New) — secret writes require 2FA, which MCP
  bearer tokens cannot provide.

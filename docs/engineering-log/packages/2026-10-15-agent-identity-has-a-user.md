# An MCP agent identity always has a user (2026-10-15)

Package 16 of the 2026-10-14 security review remediation: D-7 / A-21.

## Decided

- **`AgentIdentity.user_id` is a `Uuid`, not an `Option<Uuid>`.** `mcp_agents.user_id`
  stays nullable, because a deleted user's agents keep their rows. The `/mcp`
  middleware refuses such a row where it would build the identity: `r.user_id`
  is `None` → `McpAuthRefusal::UnscopedAgent(unscoped_agent_refusal(..))`. An
  identity without a user therefore cannot exist, cannot be cached in
  `BCRYPT_VERIFY_CACHE`, and cannot reach a handler. Until this change the
  refusal was a separate check after construction, made at two call sites
  (`refuse_unscoped_agent`). A future transport that skipped it would have run
  every handler as the nil tenant.
- **Every nil fallback in `talos-mcp-handlers` is gone:**
  `agent.user_id.unwrap_or_else(Uuid::nil)` and the
  `match agent.user_id { Some(u) => u, None => … }` /
  `let Some(..) = agent.user_id else { … }` refusals. Each site now reads
  `agent.user_id`. The branches that described an unbound agent are deleted
  with them:
  - the per-user rate-limit exemption ("system agents");
  - `whoami`'s unbound answer;
  - `get_system_health`'s `None => false`;
  - the unbound refusals in the resource, ML, evaluation, sandbox-capture,
    replay, pin and restore-pins handlers;
  - `star_module`'s nil check;
  - `local_llm_complete`'s unscoped `is_nil()` branch, so the token ledger now
    always attributes usage.
- **`/mcp/local`** builds its identity with the resolved dev user, as before;
  the field is no longer wrapped in `Some`.
- Calls into other crates whose API takes `Option<Uuid>` (the catalog install,
  the sandbox template lookups, the LLM vault-key prefetch) pass
  `Some(agent.user_id)`. Their `None` arms serve other callers.

## Deliberately NOT done

- **A structural lint** forbidding `unwrap_or_else(Uuid::nil)` on a `user_id`.
  The review offered it as the alternative to the type change. With the type
  change, the compiler is the gate, and a lint would only restate it.
- **The engine's `user_id().unwrap_or_else(Uuid::nil)`** in
  `scheduler_handlers.rs` (capability dispatch, three sites) and
  `talos-workflow-engine-nats/src/dispatcher.rs` (two). An engine without a
  user is a legitimate state there; capability dispatch with the nil user
  matches no workflow. That is a different finding's territory, and it is not
  the MCP identity.

## Measured

- About 120 handler sites read `agent.user_id.unwrap_or_else(Uuid::nil)`, and
  a further 17 refused, branched on `None` or checked `is_nil()`. The review counted 127.
- The workspace compiles with `--all-targets`; no test constructed an unbound
  agent except the four fixtures that now carry a fresh id.

## Stated limits

- Built on package 11 (`security/p11-ceilings-second-factor`): that package's
  `require_world_permitted` and `module_grant_bearer_tests` read
  `agent.user_id` as an `Option`, so this one merges after it.

- `mcp_agents.user_id` stays nullable and keeps `ON DELETE SET NULL`. The
  refusal is at the one place an identity is built from a row; the schema is
  unchanged.

## Mutations

| gate | mutation | caught by |
|---|---|---|
| unbound agent refused before an identity exists | `r.user_id` replaced by `Some(Uuid::nil())` when absent | `mcp_auth_metrics_tests::every_path_through_the_middleware_moves_its_own_outcome` (now calls twice, so a cached identity would also show) |

## One home

- `talos_mcp_handlers::auth::authenticate_mcp_request` (the `let Some(user_id) = r.user_id else` arm) and `unscoped_agent_refusal`.

# The data plane has a size and a spend bound per tenant (2026-10-15)

Security review 2026-10-14, package 13: findings **I-1**, **I-2** (Medium) and
**I-3**, **I-4**, **I-5**, **I-7**, **I-8** (Low / informational). I-6 (one
graph node and edge cap) is delivered with package 12's graph-writer helper,
where the chokepoint is; I-9 is the recorded RPC trust boundary.

## Measured (reference deployment, read-only)

- `llm_usage`: every recorded token is `ollama`; no platform-key (external)
  spend at all. The busiest actor-day was 379 452 tokens. Existing actor
  budget caps run from 100 000 to 500 000 tokens/day.
- `ml_datasets`: 2, one with no `max_examples`. The largest dataset holds 3 297
  examples; the largest user 3 721.

## Decided

- **I-1.** `talos_ml::DEFAULT_MAX_EXAMPLES` (50 000): `create_dataset` writes it
  into a schema that names no cap (`schema_with_default_cap`), and
  `enforce_growth_cap` falls back to it for a dataset made before, so the
  ungated `__ml_distill__` protocol can no longer grow one without bound.
  `MAX_EXAMPLES_PER_USER` (500 000) is checked before every insert
  (`refuse_past_user_example_ceiling`, one indexed count — migration
  `20261015110000` adds `idx_ml_examples_user`).
- **I-2.** `ActorRepository::external_llm_spend_refused` is the ONE check
  graph-RAG extraction and memory consolidation ask (each kept a copy). It
  consults first a deployment ceiling on the platform key —
  `TALOS_PLATFORM_LLM_TOKENS_PER_DAY`, default 1 000 000, summed over external
  (non-`ollama`) tokens spent with no execution behind them, every actor and
  user, trailing 24 h — which fails CLOSED on a read error; then the actor's
  own `max_llm_tokens_per_day`, which keeps the recorded H6 fail-open posture
  on a read error but now logs it at WARN. Both read failures count
  `talos_llm_budget_read_failures_total{budget}`.
- **I-3.** `talos_db::try_named_advisory_lock` / `NamedAdvisoryLock`: a session
  advisory lock on a connection of its own, keyed by name; released, or
  detached on drop so a lock can never ride a pooled connection. Graph
  backfill (`graph_backfill:<actor>`) and the teacher audit
  (`teacher_audit:<model>`) take it with no wait and answer "already running";
  a distill flow holds `ml_flow:<model>` across its shadow and append, waiting
  up to 60 s, and drops its envelope rather than run unserialised. The
  process-local guards stay in front of it.
- **I-4.** `EmbeddingConfig::tier1_permitted`: a tier-1 actor's text is
  embedded only when the operator attests the embedder is on-host
  (`TALOS_EMBEDDING_TIER1_LOCAL_OK`, default false) AND the URL is not
  obviously public. Plumbed through compose, the chart
  (`embedding.tier1LocalOk`) and the configuration reference.
- **I-5.** An ntfy access token (`tk_` + 29 letters and digits) is redacted, by
  its own exact-length pattern so prose like `tk_items` is not.
- **I-7.** `talos_graph_rag::MAX_GRAPH_QUERY_HOPS` / `MAX_GRAPH_QUERY_NODES`
  (3 / 50) are what the service clamps to and what the `graph_query` tool now
  refuses past, matching its schema.
- **I-8.** A memory read grant counts a read only when its document exists: the
  grant is looked up without counting, the document read, and only then
  counted by `claim_read` (still the one enforcing statement; both use one
  `live_grant!` predicate). A terminated actor's grants answer nothing.

## Behaviour changes an operator must act on

- **Set `TALOS_EMBEDDING_TIER1_LOCAL_OK=true` on this deployment before
  deploying**, if its embedder is the host's Ollama (it is). Without it:
  every tier-1 actor's new memory is stored with no vector, so semantic recall
  for those actors falls back to keyword and recency; and — wider than the
  review says — EVERY new ML example, for every user, is stored with no
  vector, because the dataset path always embeds `local_only` (dataset text
  never leaves the host). A classifier's kNN serving then sees none of its new
  examples until they are re-embedded (`ml_reembed_dataset`).

## Deliberately NOT done

- **No default `actor_budget_policies` row on actor creation** (the review's
  second I-2 suggestion). A row brings its columns' defaults with it —
  `max_workflows_per_minute = 10`, `max_compilations_per_hour = 20` and
  `on_budget_exceeded = 'suspend'` — so a new actor would be rate-limited and
  SUSPENDED at the token cap, a far larger change than a spend ceiling. The
  deployment ceiling bounds the shared key instead.
- The distill, backfill and audit CALL SITES of the fleet lock are not driven
  by a two-replica test; the lock itself is (`data_plane_bounds_tests`).
- The platform ceiling's fail-closed read path has no test: it needs a
  database error mid-check.

## Test notes

- `controller/tests/ml_reembed_tests` fails on this machine before and after
  this package, identically: its fake 1024-dimension vectors meet the host
  Ollama's 768-dimension embedder, which the process picks up. Environmental;
  CI has no local embedder.
- `embedding_gate_*` (talos-memory) and the two ML binaries that serve a mock
  embedder now attest the mock as on-host, as an operator would.

## Mutation proof

See the PR body.

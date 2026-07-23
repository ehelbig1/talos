use std::env;
use std::sync::LazyLock;

/// Read an env var, returning `default` when the var is unset OR set to
/// an empty string.
///
/// MCP-615 (2026-05-12): pre-fix the helper used
/// `env::var(var).unwrap_or_else(|_| default.to_string())` which returns
/// `""` (not the default) when the operator sets the var to an empty
/// string. Helm `values.yaml` placeholders (`rustEnv: ""`,
/// `executionRetentionDays: ""`) routinely produce this shape and
/// silently shadowed every downstream default — same empty-env-var
/// class as MCP-590/591/597/598/599/611. Same fix shape:
/// `.ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())`.
///
/// Callers that need to distinguish "unset" from "empty value" should
/// reach for `env::var` directly. Most config-style helpers want
/// "use the default when no value is provided," for which this is the
/// correct shape.
pub fn get_env(var: &str, default: &str) -> String {
    env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Read a secret from an environment variable or from a file whose path is
/// given by the `<VAR>_FILE` variant (Docker secrets pattern).
///
/// Precedence: `<VAR>` direct value > `<VAR>_FILE` file contents > `None`.
/// Trailing newlines are stripped from file contents. **Empty values are
/// treated as missing on BOTH paths** so the env-vs-file precedence is
/// consistent: `<VAR>=""` no longer takes precedence over a populated
/// `<VAR>_FILE`, and downstream callers don't need to defensively
/// re-check for empty.
///
/// MCP-597 (2026-05-12): pre-fix the env path returned `Some("")` for
/// `<VAR>=""` while the file path returned `None` for an empty file.
/// Same operational input (empty value), opposite behaviour. Result: a
/// Docker secrets mount providing `JWT_PRIVATE_KEY_FILE` was silently
/// shadowed by an upstream `JWT_PRIVATE_KEY=""` from a misconfigured
/// values.yaml or env_file. The downstream JWT parser caught the
/// empty PEM with an "invalid key" error so the deploy didn't go past
/// the JWT load step — but the operator-facing error was misleading
/// ("Invalid RSA private key PEM" instead of "JWT_PRIVATE_KEY env var
/// is set but empty — likely a values.yaml placeholder; either fill
/// it in or unset and rely on JWT_PRIVATE_KEY_FILE"). Sibling
/// hardening class to MCP-590/591/592 (empty-string ct_eq bypass);
/// here the failure mode is misleading-error rather than auth bypass,
/// but the symmetry between the two paths is worth preserving.
pub fn read_env_or_file(var: &str) -> Option<String> {
    if let Ok(val) = env::var(var) {
        if !val.is_empty() {
            return Some(val);
        }
        // Empty env var — let the file path take its turn rather than
        // shadowing it. Log so the operator sees that the env was set
        // (presumably unintentionally) and the file path is being used
        // instead.
        tracing::warn!(
            "{} env var is set to empty — treating as missing; falling back to {}_FILE",
            var,
            var
        );
    }
    let file_var = format!("{}_FILE", var);
    if let Ok(path) = env::var(&file_var) {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trimmed = contents
                    .trim_end_matches('\n')
                    .trim_end_matches('\r')
                    .to_string();
                if trimmed.is_empty() {
                    tracing::warn!("{}_FILE at '{}' is empty — treating as missing", var, path);
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(e) => {
                tracing::error!("Failed to read {}_FILE at '{}': {}", var, path, e);
                None
            }
        }
    } else {
        None
    }
}

pub fn is_production() -> bool {
    get_env("RUST_ENV", "development") == "production"
}

pub fn is_development() -> bool {
    !is_production()
}

/// MCP-1081 (2026-05-16): canonical validator for shared-secret auth
/// tokens at startup. Three sibling sites in `controller/main.rs`
/// (ADMIN_SECRET_KEY, PROMETHEUS_SCRAPE_TOKEN, REGISTRY_PUBLISH_TOKEN)
/// had identical shape pre-fix:
///
/// ```text
/// let token = std::env::var(VAR).ok().filter(|v| !v.is_empty());
/// if let Some(token) = token {
///     if token.len() < 32 {
///         return Err(anyhow::anyhow!("VAR is too short ..."));
///     }
/// }
/// ```
///
/// Same N-inline-copies drift class as the canonical resolvers
/// (admin_ops_enabled, edge_routing_enabled, dev_csrf_bypass_enabled,
/// MCP-1064/1065/1066). Future tuning of the threshold (e.g., raise
/// to 48 chars for stronger entropy) lands in one place. Future new
/// shared-secret tokens get strength validation for free.
///
/// Empty-string handling matches the workspace-wide pattern (MCP-590/591):
/// `=""` is treated as "unset" so an operator who explicitly clears
/// the env var gets the unset behaviour, not a vacuous validation error.
///
/// `required = true` → unset/empty is an ERROR. Used for tokens that
/// MUST be set for a feature to be active (e.g., ADMIN_SECRET_KEY
/// when `ENABLE_ADMIN_OPS=true`).
///
/// `required = false` → unset/empty is OK (the request-time gate
/// fail-closes in production per MCP-590/591). Used for optional
/// tokens like PROMETHEUS_SCRAPE_TOKEN and REGISTRY_PUBLISH_TOKEN.
pub fn validate_shared_secret_token(
    env_var: &str,
    min_len: usize,
    required: bool,
    rationale: &str,
) -> std::result::Result<(), String> {
    let value = env::var(env_var).ok().filter(|v| !v.is_empty());
    match value {
        Some(token) if token.len() >= min_len => Ok(()),
        Some(token) => Err(format!(
            "{env_var} is too short ({} chars; must be >= {min_len}). \
             Generate with: openssl rand -hex 32. {rationale}",
            token.len()
        )),
        None if required => Err(format!(
            "{env_var} must be set (must be >= {min_len} chars). \
             Generate with: openssl rand -hex 32. {rationale}"
        )),
        None => Ok(()),
    }
}

/// MCP-1066 (2026-05-15): canonical resolver for the
/// `ALLOW_DEV_UNSAFE_CSRF_BYPASS` flag — the dev-mode escape hatch
/// that disables CSRF on `/graphql`. Two callers previously inlined
/// the parse with `== "true"` case-sensitive exact match:
///   - `controller/main.rs` startup-time guard: panics if
///     `is_production() && ... == "true"`.
///   - `talos-csrf::lib::csrf_protection_graphql` request-time gate:
///     bypasses CSRF if `!is_production() && ... == "true"`.
///
/// Failure mode pre-fix: an operator who accidentally sets
/// `=1` / `=yes` / `=on` / `=TRUE` (capital T) in production would
/// NOT trigger the startup panic (`=1 != "true"`), and the request-
/// time gate would ALSO not activate (same predicate). Currently
/// safe by chance — both sites use the same case-sensitive
/// predicate. BUT if a future site routes the same env var
/// through `bool_env_or_default`, it would accept `=1` as truthy
/// while the production-startup guard stays inert → live CSRF
/// bypass in production with no panic.
///
/// Routing both sites through this canonical resolver closes the
/// drift hazard: any truthy token (true | 1 | yes | on,
/// case-insensitive) in production now triggers the fail-closed
/// panic.
pub fn dev_csrf_bypass_enabled() -> bool {
    bool_env_or_default("ALLOW_DEV_UNSAFE_CSRF_BYPASS", false)
}

/// MCP-1065 (2026-05-15): canonical resolver for the `ENABLE_EDGE_ROUTING`
/// flag that chooses between per-user NATS topic `talos.jobs.{user_id}`
/// and the shared `talos.jobs` topic for module dispatch.
///
/// Pre-fix four callers inlined the parse with `== "true"`
/// case-sensitive exact-match: `talos-gmail::dispatch`,
/// `talos-google-calendar::handlers`, and TWO sites in
/// `talos-webhooks::lib` (request-reply dispatch + DLQ replay).
/// Operator setting `=1` / `=yes` / `=on` / `=TRUE` (capital T)
/// would get the FALSE branch at all four sites — but a single
/// future site that uses `eq_ignore_ascii_case("true")` (the
/// admin-gate predicate that drifted in MCP-1064) would diverge.
///
/// Threat is operational/correctness not auth: if some dispatch
/// sites honour edge routing and others don't, jobs get scattered
/// between two topics and consumers don't see the expected traffic
/// pattern → silent misbehaviour. Canonical helper makes the
/// accepted-tokens set `true | 1 | yes | on` uniform across every
/// site.
pub fn edge_routing_enabled() -> bool {
    bool_env_or_default("ENABLE_EDGE_ROUTING", false)
}

/// MCP-1064 (2026-05-15): canonical resolver for the `ENABLE_ADMIN_OPS`
/// "big red button" gate. Three callers previously inlined the gate
/// predicate with subtle drift:
///   - `talos-gmail::admin::authorize` accepted `"1" | "true"` (case-insensitive).
///   - `talos-google-calendar::admin::authorize` accepted `"1" | "true"` (case-insensitive).
///   - `controller/main.rs` admin-secrets endpoint accepted ONLY the literal `"1"`.
///
/// Same env var, different behaviour across crates — pure drift
/// hazard. An operator setting `ENABLE_ADMIN_OPS=true` would enable
/// gmail/gcal admin but NOT controller secrets admin, with no
/// visible signal. Routing all three callers through this single
/// resolver collapses the predicate to one place AND widens the
/// accepted-tokens set to the canonical `true | 1 | yes | on`
/// (matches `bool_env_or_default`'s contract).
///
/// Security posture unchanged: default-off, admin endpoints require
/// BOTH this gate AND a constant-time `X-Admin-Secret` compare
/// against `ADMIN_SECRET_KEY` (MCP-983 hardening).
pub fn admin_ops_enabled() -> bool {
    bool_env_or_default("ENABLE_ADMIN_OPS", false)
}

/// Canonical resolver for the smart actor-memory-context builder feature
/// flag (`ENABLE_SMART_MEMORY_CONTEXT`). Default OFF.
///
/// When OFF, `__actor_context__` assembly and per-node injection are
/// byte-identical to the legacy path: the count-capped, unfiltered,
/// `min_score = 0.0` retriever runs and every node receives the context.
/// When ON, the retriever kind-filters synthetic self-outputs, applies a
/// similarity floor ([`smart_memory_context_min_score`]), packs candidates
/// under a byte budget ([`smart_memory_context_byte_budget`] /
/// [`smart_memory_context_per_memory_cap`]), and the engine injects the
/// context only into nodes that declare `needs_memory = true` (the
/// default, so no consumer silently loses context).
///
/// Accepted truthy tokens match every other flag: `true | 1 | yes | on`
/// (case-insensitive) — see [`bool_env_or_default`].
pub fn smart_memory_context_enabled() -> bool {
    bool_env_or_default("ENABLE_SMART_MEMORY_CONTEXT", false)
}

/// Route the EXPLICIT semantic-recall path (the worker `agent_memory::search`
/// RPC + the MCP `actor_recall_semantic` / `actor_recall_hyde` handlers)
/// through the smart-context fused ranker instead of raw pgvector-cosine order.
/// When ON, recall overfetches then re-orders by the same relevance + recency +
/// importance + access-frequency blend the `__actor_context__` grounding path
/// uses — and by the learned PER-ACTOR weights when [`adaptive_rank_enabled`]
/// is also on. Default OFF ⇒ recall is byte-identical to today (plain cosine).
///
/// This is the "grounding any time memory is needed" switch: it makes every
/// workflow that recalls memory benefit from the adaptive-memory arc with no
/// per-workflow change. Independent of [`smart_memory_context_enabled`] (which
/// governs the auto-injected grounding payload, a different path).
pub fn ranked_recall_enabled() -> bool {
    bool_env_or_default("ENABLE_RANKED_RECALL", false)
}

/// Total byte budget for the assembled `__actor_context__` payload when
/// [`smart_memory_context_enabled`] is ON. Default 12_000 bytes (~3k
/// tokens by the bytes/4 estimate). Overridable via
/// `SMART_MEMORY_CONTEXT_BYTE_BUDGET`; `=0`/negative falls back to the
/// default (destructive-zero guard, see [`positive_env_or_default`]).
///
/// The packer ([`crate`]-external `talos_memory::actor_context::pack_within_budget`])
/// walks candidates in relevance order and stops before the serialized
/// payload would exceed this bound, so the injected context can never
/// balloon a node's parse-fuel regardless of how large individual
/// memories are.
pub fn smart_memory_context_byte_budget() -> usize {
    // Floor well above the empty `{actor_id, memories:[]}` wrapper (~65 B)
    // so the packer's `<= byte_budget` bound is always meaningful — a
    // sub-1 KB actor context is useless anyway.
    positive_env_or_default::<usize>("SMART_MEMORY_CONTEXT_BYTE_BUDGET", 12_000).max(1_024)
}

/// Per-memory serialized-value byte cap when
/// [`smart_memory_context_enabled`] is ON. Default 3_000 bytes. A single
/// memory whose serialized value exceeds this cap has its content
/// truncated at a UTF-8 char boundary (never mid-codepoint) and marked,
/// so one 15KB `daily_brief`/`ask_thread` value can't dominate the whole
/// budget. Overridable via `SMART_MEMORY_CONTEXT_PER_MEMORY_CAP`;
/// `=0`/negative falls back to the default.
pub fn smart_memory_context_per_memory_cap() -> usize {
    // Floor comfortably above the truncation marker (~14 B) so per-memory
    // truncation always has room to leave meaningful content and the cap is
    // honoured for any configured value.
    positive_env_or_default::<usize>("SMART_MEMORY_CONTEXT_PER_MEMORY_CAP", 3_000).max(256)
}

/// Cosine-similarity floor for semantic recall when
/// [`smart_memory_context_enabled`] is ON. Default 0.25 (the legacy path
/// uses 0.0, i.e. no floor). Clamped to `[0.0, 1.0]`. Overridable via
/// `SMART_MEMORY_CONTEXT_MIN_SCORE`; `=0`/negative or unparseable falls
/// back to the default (use a small positive value like `0.05` to
/// approximate "no floor" without losing the destructive-zero guard).
pub fn smart_memory_context_min_score() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_MIN_SCORE", 0.25).clamp(0.0, 1.0)
}

// ── Phase 2: fused multi-signal ranking weights ─────────────────────────────
//
// When [`smart_memory_context_enabled`] is ON, the smart retriever blends
// three signals per candidate into one fused score
// (`talos_memory::actor_context::fused_score`):
//
//   fused = W_RELEVANCE * relevance
//         + W_RECENCY   * recency_decay(now - updated_at)
//         + W_IMPORTANCE * importance(memory_type, importance_hint)
//
// and packs candidates in fused-score-descending order. All three weights
// route through `positive_env_or_default` so a `=0`/negative misconfig
// substitutes the default + WARN (a `0` weight would silently drop a whole
// signal — the destructive-zero guard treats that as a misconfiguration; use
// a small positive value like `0.01` to de-weight a signal intentionally).

/// Upper clamp on the fused-rank weight knobs. `positive_env_or_default`
/// rejects `NaN` and `≤0` but ACCEPTS `+Inf` (`"inf".parse::<f64>()` succeeds,
/// `Inf > 0.0`). An `Inf` weight makes every `fused_score` `Inf`, so all
/// candidates compare `Equal` and the ranking collapses to input order. Cap the
/// weights at a large-but-finite value — far above any sane weight ratio — so a
/// stray `=inf` env can't degenerate the ranking. Keeps every knob finite.
///
/// `pub` so the Phase-2 learned-ranker (`talos-memory-ranking`) clamps its
/// mapped per-actor weights to the SAME bound rather than hand-mirroring the
/// literal (which would silently drift if this constant is retuned).
pub const SMART_MEMORY_WEIGHT_MAX: f64 = 1_000_000.0;

/// Weight on the cosine-relevance signal in the fused rank. Default 1.0.
/// Override via `SMART_MEMORY_CONTEXT_W_RELEVANCE`.
pub fn smart_memory_context_w_relevance() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_W_RELEVANCE", 1.0)
        .min(SMART_MEMORY_WEIGHT_MAX)
}

/// Weight on the recency-decay signal in the fused rank. Default 0.3.
/// Override via `SMART_MEMORY_CONTEXT_W_RECENCY`.
pub fn smart_memory_context_w_recency() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_W_RECENCY", 0.3)
        .min(SMART_MEMORY_WEIGHT_MAX)
}

/// Weight on the importance signal (memory-type base blended with an optional
/// `metadata.importance` hint) in the fused rank. Default 0.5. Override via
/// `SMART_MEMORY_CONTEXT_W_IMPORTANCE`.
pub fn smart_memory_context_w_importance() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_W_IMPORTANCE", 0.5)
        .min(SMART_MEMORY_WEIGHT_MAX)
}

/// Exponential recency half-life in DAYS: a memory `half_life` days old
/// contributes half the recency weight of a brand-new one
/// (`recency_decay(age) = 0.5^(age_days / half_life_days)`). Default 7.0.
/// Override via `SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS`; `=0`/negative
/// (which would divide-by-zero / invert the decay) falls back to the default.
pub fn smart_memory_context_recency_halflife_days() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_RECENCY_HALFLIFE_DAYS", 7.0)
}

/// Baseline relevance assigned to the graph-RAG entity-context candidate
/// (which carries no cosine score). Default 0.6; clamped to `[0.0, 1.0]`.
/// Override via `SMART_MEMORY_CONTEXT_GRAPH_BASELINE`.
pub fn smart_memory_context_graph_baseline() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_GRAPH_BASELINE", 0.6).clamp(0.0, 1.0)
}

/// Baseline relevance assigned to recency-layer candidates (which carry no
/// cosine score — they were selected by `updated_at`, not similarity).
/// Default 0.4; clamped to `[0.0, 1.0]`. Kept below the graph baseline so a
/// bare recency row doesn't outrank an entity-graph hit on relevance alone.
/// Override via `SMART_MEMORY_CONTEXT_RECENCY_BASELINE`.
pub fn smart_memory_context_recency_baseline() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_RECENCY_BASELINE", 0.4).clamp(0.0, 1.0)
}

/// Phase 3a: weight on the durable access-frequency boost folded INTO the
/// importance signal (NOT a separate fused term — `fused_score` stays 3-term).
/// A memory the actor keeps pulling into context is nudged up by
/// `access_weight * normalized_access_count`. Default 0.15 — small, so access
/// frequency refines but never dominates the base/hint importance. Clamped to
/// `[0.0, 1.0]`. Override via `SMART_MEMORY_CONTEXT_ACCESS_WEIGHT`; `=0`/negative
/// or unparseable falls back to the default (destructive-zero guard — a `0`
/// would silently disable the whole access signal; the additive+clamped blend
/// keeps importance in `[0, 1]` for any value in range).
pub fn smart_memory_context_access_weight() -> f64 {
    positive_env_or_default::<f64>("SMART_MEMORY_CONTEXT_ACCESS_WEIGHT", 0.15).clamp(0.0, 1.0)
}

/// Canonical resolver for the HyDE (Hypothetical Document Embeddings) toggle
/// on the smart actor-context semantic layer (`ENABLE_SMART_MEMORY_HYDE`).
/// Default OFF.
///
/// When ON (and [`smart_memory_context_enabled`] is also ON), the semantic
/// layer embeds a HyDE-rewritten query
/// (`SearchMethod::HyDE` — "An answer to the question '…' would be: ") instead
/// of the raw context hint (`SearchMethod::Direct`). Same `min_score` +
/// `exclude_kinds` filters apply either way, and HyDE still embeds — so the
/// tier-1 local-only embed gate inside `recall_semantic_filtered` applies
/// unchanged.
///
/// Accepted truthy tokens: `true | 1 | yes | on` (case-insensitive) — see
/// [`bool_env_or_default`].
pub fn smart_memory_hyde_enabled() -> bool {
    bool_env_or_default("ENABLE_SMART_MEMORY_HYDE", false)
}

// ── Phase 3b: autonomous memory consolidation ───────────────────────────────
//
// A default-OFF background loop that summarizes an actor's older, low-importance
// episodic memories via a TIER-GATED LLM (tier-1 → local Ollama ONLY or SKIP;
// tier-2 → external allowed) and consolidates them into ONE durable semantic
// summary (atomic persist-summary + forget-sources). All knobs route through the
// destructive-zero guards so a `=0`/negative misconfig substitutes the default
// + WARN rather than producing a runaway or degenerate scan.

/// Master switch for the autonomous consolidation loop
/// (`ENABLE_MEMORY_CONSOLIDATION`). Default OFF — when unset the scheduler is
/// not even spawned (zero background overhead). Truthy tokens per
/// [`bool_env_or_default`].
pub fn memory_consolidation_enabled() -> bool {
    bool_env_or_default("ENABLE_MEMORY_CONSOLIDATION", false)
}

/// Operator attestation that `OLLAMA_URL` points at an ON-HOST model, so a
/// TIER-1 actor's private memory may be summarized locally without egress
/// (`MEMORY_CONSOLIDATION_TIER1_LOCAL_OK`). Default FALSE (fail-closed: a
/// tier-1 actor is SKIPPED unless the operator explicitly attests locality).
/// Mirrors graph-RAG's `TALOS_GRAPH_RAG_TIER1_LOCAL_OK`.
pub fn memory_consolidation_tier1_local_ok() -> bool {
    bool_env_or_default("MEMORY_CONSOLIDATION_TIER1_LOCAL_OK", false)
}

/// Wake interval for the consolidation scheduler in seconds
/// (`MEMORY_CONSOLIDATION_INTERVAL_SECS`). Default 3600 (hourly). `=0`/negative
/// falls back to the default.
pub fn memory_consolidation_interval_secs() -> u64 {
    positive_env_or_default::<u64>("MEMORY_CONSOLIDATION_INTERVAL_SECS", 3600)
}

/// Minimum row age in DAYS before an episodic memory is eligible for
/// consolidation (`MEMORY_CONSOLIDATION_MIN_AGE_DAYS`). Default 30.0 — only the
/// long tail is consolidated, never recent memory. `=0`/negative falls back to
/// the default.
pub fn memory_consolidation_min_age_days() -> f64 {
    positive_env_or_default::<f64>("MEMORY_CONSOLIDATION_MIN_AGE_DAYS", 30.0)
}

/// Importance ceiling for consolidation candidates
/// (`MEMORY_CONSOLIDATION_MAX_IMPORTANCE`). Default 0.4, clamped to `[0.0, 1.0]`
/// — only LOW-importance (or unscored NULL) rows are consolidated; high-value
/// memory is never touched. `=0`/negative falls back to the default (0.0 would
/// exclude everything except unscored rows).
pub fn memory_consolidation_max_importance() -> f64 {
    positive_env_or_default::<f64>("MEMORY_CONSOLIDATION_MAX_IMPORTANCE", 0.4).clamp(0.0, 1.0)
}

/// Number of candidate rows summarized per actor per tick
/// (`MEMORY_CONSOLIDATION_BATCH_SIZE`). Default 20, clamped to `[3, 100]`. The
/// floor of 3 means a trivial cluster is never "consolidated" (nothing worth
/// summarizing). `=0`/negative falls back to the default.
pub fn memory_consolidation_batch_size() -> i64 {
    positive_env_or_default::<i64>("MEMORY_CONSOLIDATION_BATCH_SIZE", 20).clamp(3, 100)
}

/// Maximum distinct actors processed per tick
/// (`MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK`). Default 25, clamped to
/// `[1, 500]` so one tick can't stampede the whole fleet. `=0`/negative falls
/// back to the default.
pub fn memory_consolidation_max_actors_per_tick() -> i64 {
    positive_env_or_default::<i64>("MEMORY_CONSOLIDATION_MAX_ACTORS_PER_TICK", 25).clamp(1, 500)
}

/// Ollama model used to generate the consolidation summary on the tier-1
/// LOCAL-only path (`MEMORY_CONSOLIDATION_MODEL`). Default `qwen2.5:7b`.
pub fn memory_consolidation_model() -> String {
    let v = get_env("MEMORY_CONSOLIDATION_MODEL", "qwen2.5:7b");
    if v.trim().is_empty() {
        "qwen2.5:7b".to_string()
    } else {
        v
    }
}

// ── Autonomous memory reflection — Phase 3 ──────────────────────────────────
//
// A scheduled per-actor background loop that reads across an actor's meaningful
// (semantic+episodic) memories and synthesizes HIGHER-ORDER INSIGHTS via a
// TIER-GATED LLM, written back as ONE `reflection`-kind semantic memory WITHOUT
// deleting any sources (reflection AUGMENTS; consolidation retires). Default-OFF
// and tier-gated on the same shared matrix as consolidation, with its OWN
// operator attestation (independent control).

/// Master switch for the autonomous reflection loop (`ENABLE_MEMORY_REFLECTION`).
/// Default OFF — when unset the scheduler is not even spawned (zero background
/// overhead). Truthy tokens per [`bool_env_or_default`].
pub fn memory_reflection_enabled() -> bool {
    bool_env_or_default("ENABLE_MEMORY_REFLECTION", false)
}

/// Operator attestation that `OLLAMA_URL` points at an ON-HOST model, so a
/// TIER-1 actor's private memory may be reflected on locally without egress
/// (`MEMORY_REFLECTION_TIER1_LOCAL_OK`). Default FALSE (fail-closed: a tier-1
/// actor is SKIPPED unless the operator explicitly attests locality). This is a
/// SEPARATE attestation from consolidation's `MEMORY_CONSOLIDATION_TIER1_LOCAL_OK`
/// — the two loops are controlled independently.
pub fn memory_reflection_tier1_local_ok() -> bool {
    bool_env_or_default("MEMORY_REFLECTION_TIER1_LOCAL_OK", false)
}

/// Wake interval for the reflection scheduler in seconds
/// (`MEMORY_REFLECTION_INTERVAL_SECS`). Default 86400 (daily) — a slower cadence
/// than consolidation, since higher-order insights change slowly. `=0`/negative
/// falls back to the default.
pub fn memory_reflection_interval_secs() -> u64 {
    positive_env_or_default::<u64>("MEMORY_REFLECTION_INTERVAL_SECS", 86_400)
}

/// Maximum number of an actor's memories fed to the reflection LLM per cycle
/// (`MEMORY_REFLECTION_INPUT_CAP`). Default 40, clamped to `[5, 200]` so a
/// pathological actor can't blow the model's context. `=0`/negative falls back
/// to the default.
pub fn memory_reflection_input_cap() -> i64 {
    positive_env_or_default::<i64>("MEMORY_REFLECTION_INPUT_CAP", 40).clamp(5, 200)
}

/// Minimum number of meaningful memories an actor must hold before reflection
/// runs (`MEMORY_REFLECTION_MIN_MEMORIES`). Default 8, clamped to `[3, 100]`.
/// Below this floor there is too little to synthesize — the actor is skipped
/// (no LLM, no write). `=0`/negative falls back to the default.
pub fn memory_reflection_min_memories() -> i64 {
    positive_env_or_default::<i64>("MEMORY_REFLECTION_MIN_MEMORIES", 8).clamp(3, 100)
}

/// Maximum distinct actors processed per tick
/// (`MEMORY_REFLECTION_MAX_ACTORS_PER_TICK`). Default 25, clamped to `[1, 500]`
/// so one tick can't stampede the whole fleet. `=0`/negative falls back to the
/// default.
pub fn memory_reflection_max_actors_per_tick() -> i64 {
    positive_env_or_default::<i64>("MEMORY_REFLECTION_MAX_ACTORS_PER_TICK", 25).clamp(1, 500)
}

/// Ollama model used to generate the reflection on the tier-1 LOCAL-only path
/// (`MEMORY_REFLECTION_MODEL`). Default matches consolidation's default model.
pub fn memory_reflection_model() -> String {
    let v = get_env("MEMORY_REFLECTION_MODEL", "qwen2.5:7b");
    if v.trim().is_empty() {
        "qwen2.5:7b".to_string()
    } else {
        v
    }
}

// ── Adaptive per-actor memory ranking — Phase 1 (provenance) ────────────────
//
// Records, for each actor-bound execution that injected `__actor_context__`,
// WHICH memory keys were in that context + their per-memory ranking-feature
// snapshot, so a later phase can learn which memories lead to good outcomes.
// Default-OFF: when the flag is unset the injection path is byte-identical to
// today and no provenance rows are written.
//
// HARD DEPENDENCY: provenance is recorded ONLY on the smart-context path
// (`get_relevant_actor_context_smart`), because the per-memory feature snapshot
// (relevance/recency/importance/fused_score) exists only there — the legacy
// path has no fused signals to record. So `ENABLE_MEMORY_RANK_PROVENANCE=1`
// records NOTHING unless `ENABLE_SMART_MEMORY_CONTEXT=1` is ALSO set. The
// controller logs a WARN at startup if provenance is on while smart-context is
// off, and `provenance_recording_effective()` below encodes the dependency.

/// Master switch for memory-rank provenance recording
/// (`ENABLE_MEMORY_RANK_PROVENANCE`). Default OFF. **Provenance only actually
/// records when [`smart_memory_context_enabled`] is ALSO on** — see
/// [`provenance_recording_effective`]. Truthy tokens per [`bool_env_or_default`].
pub fn memory_rank_provenance_enabled() -> bool {
    bool_env_or_default("ENABLE_MEMORY_RANK_PROVENANCE", false)
}

/// Whether memory-rank provenance will ACTUALLY record — the AND of the
/// provenance flag and the smart-context flag it depends on (provenance is
/// captured only on the smart-context path). Use this for the startup
/// dependency check; `memory_rank_provenance_enabled` alone is misleading
/// (it's on but inert when smart-context is off).
pub fn provenance_recording_effective() -> bool {
    memory_rank_provenance_enabled() && smart_memory_context_enabled()
}

/// Retention window (DAYS) for `execution_memory_context` rows, swept
/// periodically (`MEMORY_RANK_PROVENANCE_RETENTION_DAYS`). Default 90, clamped
/// to `[1, 3650]`. `=0`/negative falls back to the default (destructive-zero
/// guard: bound directly into `now() - make_interval(days => $1)`, a `=0` sweep
/// would delete every row).
pub fn memory_rank_provenance_retention_days() -> i64 {
    positive_env_or_default::<i64>("MEMORY_RANK_PROVENANCE_RETENTION_DAYS", 90).clamp(1, 3650)
}

// ── Adaptive per-actor memory ranking — Phase 2 (learned ranker) ────────────
//
// Phase 2 LEARNS per-actor fused-ranking weights from the Phase-1 provenance
// corpus (`execution_memory_context` joined to execution outcomes). A tiny
// per-actor logistic regression over the recorded features
// `[relevance, recency, importance, access_boost]` predicts the outcome label;
// its coefficients ARE the adaptive per-actor blend weights. Learned weights
// are stored in `actors.metadata.rank_weights` and injected at the ranker seam
// in place of the global `SMART_MEMORY_CONTEXT_W_*` constants.
//
// TWO independent default-OFF flags: `ENABLE_ADAPTIVE_RANK_TRAINING` gates the
// scheduled fit job (which writes weights); `ENABLE_ADAPTIVE_RANK` gates
// SERVING (whether the ranker consults learned weights when present). Both off
// ⇒ byte-identical ranking to today and no training task spawned. The training
// fit is a PURE numeric computation over Phase-1 numeric signals only — no LLM,
// no memory VALUES, zero data egress — so unlike consolidation/reflection it
// needs no tier gate.

/// SERVING switch (`ENABLE_ADAPTIVE_RANK`). Default OFF. When on, the smart
/// ranker consults `actors.metadata.rank_weights` and — when present, parseable,
/// and backed by enough examples — uses the learned per-actor weights instead of
/// the global `SMART_MEMORY_CONTEXT_W_*` constants. Off / missing / unparseable
/// ⇒ exact current (global-weight) behaviour. Truthy tokens per
/// [`bool_env_or_default`].
pub fn adaptive_rank_enabled() -> bool {
    bool_env_or_default("ENABLE_ADAPTIVE_RANK", false)
}

/// TRAINING switch (`ENABLE_ADAPTIVE_RANK_TRAINING`) for the scheduled per-actor
/// fit job. Default OFF — when unset the training scheduler is not even spawned
/// (zero background overhead). Independent of [`adaptive_rank_enabled`]: an
/// operator can accrue learned weights (training on) before flipping serving on.
/// Truthy tokens per [`bool_env_or_default`].
pub fn adaptive_rank_training_enabled() -> bool {
    bool_env_or_default("ENABLE_ADAPTIVE_RANK_TRAINING", false)
}

/// Minimum usable labeled examples an actor must have before a learned model is
/// fit / trusted (`ADAPTIVE_RANK_MIN_EXAMPLES`). Default 50, clamped to
/// `[10, 100000]`. Below this the fit returns `None` (cold-start → global
/// defaults) and serving falls back to global weights even if a stale row
/// exists. `=0`/negative falls back to the default.
pub fn adaptive_rank_min_examples() -> i64 {
    positive_env_or_default::<i64>("ADAPTIVE_RANK_MIN_EXAMPLES", 50).clamp(10, 100_000)
}

/// Wake interval for the training scheduler in seconds
/// (`ADAPTIVE_RANK_TRAINING_INTERVAL_SECS`). Default 21600 (6h), clamped to
/// `[300, 604800]`. `=0`/negative falls back to the default.
pub fn adaptive_rank_training_interval_secs() -> u64 {
    positive_env_or_default::<u64>("ADAPTIVE_RANK_TRAINING_INTERVAL_SECS", 21_600)
        .clamp(300, 604_800)
}

/// Training lookback window in DAYS (`ADAPTIVE_RANK_LOOKBACK_DAYS`). The fit only
/// consumes provenance rows newer than `now - lookback_days`, so weights adapt
/// to recent outcomes and a poisoned old batch ages out. Default 30, clamped to
/// `[1, 3650]`. `=0`/negative falls back to the default.
pub fn adaptive_rank_lookback_days() -> i64 {
    positive_env_or_default::<i64>("ADAPTIVE_RANK_LOOKBACK_DAYS", 30).clamp(1, 3650)
}

/// Maximum distinct actors fit per training tick
/// (`ADAPTIVE_RANK_MAX_ACTORS_PER_TICK`). Default 50, clamped to `[1, 500]` so
/// one tick can't stampede the whole fleet. `=0`/negative falls back to the
/// default.
pub fn adaptive_rank_max_actors_per_tick() -> i64 {
    positive_env_or_default::<i64>("ADAPTIVE_RANK_MAX_ACTORS_PER_TICK", 50).clamp(1, 500)
}

/// Validated allowed origins, computed once at startup.
/// Production panics happen at init time, not on every request.
static ALLOWED_ORIGINS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let default = if is_production() {
        "" // ALLOWED_ORIGIN must be explicitly set in production
    } else {
        "http://localhost:3000,http://localhost:3001,http://localhost:3002"
    };

    let origins_str = get_env("ALLOWED_ORIGIN", default);
    let origins: Vec<String> = origins_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if is_production() {
        if origins.is_empty() {
            panic!(
                "ALLOWED_ORIGIN must be set in production. \
                 Example: ALLOWED_ORIGIN=https://app.example.com"
            );
        }
        for origin in &origins {
            if origin == "*" || origin == "null" {
                panic!(
                    "ALLOWED_ORIGIN contains '{}' which is not permitted in production",
                    origin
                );
            }
            if !origin.starts_with("http://") && !origin.starts_with("https://") {
                panic!(
                    "ALLOWED_ORIGIN '{}' must start with http:// or https://",
                    origin
                );
            }
        }
        // SECURITY: Credentials are sent to all allowed origins. Each origin
        // added expands the attack surface — a compromised origin can steal
        // session cookies. Log when multiple origins are configured.
        if origins.len() > 1 {
            eprintln!(
                "SECURITY WARNING: {} CORS origins configured with credentials. \
                 Each origin can receive session cookies. Verify all are trusted: {:?}",
                origins.len(),
                origins
            );
        }
    }

    origins
});

pub fn get_allowed_origins() -> Vec<String> {
    ALLOWED_ORIGINS.clone()
}

pub fn is_allowed_origin(origin: &str) -> bool {
    ALLOWED_ORIGINS.iter().any(|o| o == origin)
}

/// MCP-1000 (2026-05-15): defense-in-depth against open-redirect via
/// a misconfigured `FRONTEND_URL`. Pre-fix `get_frontend_url()` was a
/// thin wrapper around `get_env(...)` with zero validation, while two
/// of four callers (`talos-atlassian::callback_handler`,
/// `talos-gmail::gmail_callback_handler`) maintained their own inline
/// validation that rejected any path-separator after the scheme. The
/// other two callers (`talos-slack::slack_callback_handler` and
/// `controller::oauth_callback_handler`) had no validation at all and
/// would happily `format!("{}/settings?...", frontend_url, ...)` into
/// a path-injected URL.
///
/// Threat: if an operator (or env-injection bug) sets
/// `FRONTEND_URL=https://attacker.com/redirect?to=`, the OAuth-callback
/// redirect becomes `https://attacker.com/redirect?to=/settings?...`
/// and the browser navigates to attacker.com — a classic open redirect.
/// The fix returns the localhost default + WARN log when the configured
/// value contains a `/` after the `://`. Matches the inline validation
/// in atlassian/gmail exactly (same predicate `!after.contains('/')`),
/// so behaviour for those two callers is unchanged and slack/oauth-
/// callback gain the protection for free.
///
/// Trailing slashes (`https://app.example.com/`) and any
/// scheme-mismatched (no `http://`/`https://`) values are also rejected
/// — operators typically set `https://host` exactly per the helm chart
/// docs. Misconfig surfaces as a single WARN at startup; valid setups
/// pay nothing.
pub fn get_frontend_url() -> String {
    let raw = get_env("FRONTEND_URL", "http://localhost:3000");
    if is_valid_frontend_url(&raw) {
        return raw;
    }
    tracing::warn!(
        frontend_url = %raw,
        "FRONTEND_URL failed validation (must be http(s)://host with no path); falling back to http://localhost:3000"
    );
    "http://localhost:3000".to_string()
}

/// MCP-1155 (2026-05-16): canonical `BASE_URL` resolver. Sibling of
/// [`get_frontend_url`].
///
/// Pre-fix `BASE_URL` was read inline at 10+ sites
/// (`talos-mcp-handlers::webhooks` ×3, `talos-mcp-handlers::advanced`
/// ×4, `talos-api::schema::webhooks` ×2, `talos-api::schema::modules`,
/// `talos-actor-policies::evaluator`, `talos-google-calendar` ×2)
/// each calling `talos_config::get_env("BASE_URL", "http://localhost:8000")`
/// or the equivalent inline `std::env::var(...).filter(!is_empty)`
/// shape. None of those sites validated the value before formatting
/// it into a webhook URL via
/// `format!("{}/webhooks/{}", base_url, id)`.
///
/// Same open-redirect-via-misconfig threat as the MCP-1000
/// FRONTEND_URL fix: an operator (or env-injection bug) setting
/// `BASE_URL=https://attacker.com/redirect?to=` produces webhook
/// URLs that point external services at attacker.com on every
/// inbound delivery. The mis-rendering is also operator-confusing —
/// "I set BASE_URL but my webhook URLs have garbage" tells the
/// operator nothing about WHY.
///
/// Same predicate (`is_valid_frontend_url`) — the rules are
/// identical: scheme + host(+port), no path / query / fragment.
/// Misconfig falls back to the canonical localhost default + a
/// single startup WARN.
///
/// New callers should use this instead of
/// `talos_config::get_env("BASE_URL", ...)` directly. The eight
/// existing `talos-mcp-handlers` callsites + two `talos-api` callsites
/// route through this helper post-MCP-1155.
pub fn get_base_url() -> String {
    let raw = get_env("BASE_URL", "http://localhost:8000");
    if is_valid_frontend_url(&raw) {
        return raw;
    }
    tracing::warn!(
        base_url = %raw,
        "BASE_URL failed validation (must be http(s)://host with no path); falling back to http://localhost:8000"
    );
    "http://localhost:8000".to_string()
}

/// Returns true if `raw` is `http(s)://host(:port)` with no path,
/// query, or fragment. Mirrors the inline validation in
/// `talos-atlassian::callback_handler` and
/// `talos-gmail::gmail_callback_handler` so all four OAuth-callback
/// paths share one contract.
///
/// `pub` since 2026-07-17: `talos-public-url` applies the SAME origin
/// contract to `TALOS_PUBLIC_BASE_URL` and ngrok-discovered tunnel
/// URLs — one predicate, four env vars, no drift.
pub fn is_valid_frontend_url(raw: &str) -> bool {
    let after_scheme = match raw.strip_prefix("https://") {
        Some(s) => s,
        None => match raw.strip_prefix("http://") {
            Some(s) => s,
            None => return false,
        },
    };
    // Reject empty host AND any path/query/fragment indicators. The
    // path check (`/`) is the canonical inline-implementation
    // predicate; query (`?`) and fragment (`#`) checks are
    // strictly-more-defensive — neither produces an open redirect on
    // their own but both produce broken concatenated URLs that we
    // don't want to silently emit.
    //
    // MCP-1169 (2026-05-17): also reject `@` (userinfo) and
    // whitespace / control chars. Pre-fix `https://attacker.com@victim.com`
    // (URL with userinfo `attacker.com` and host `victim.com`)
    // passed the validator — `strip_prefix("https://")` returned
    // `attacker.com@victim.com`, which contains none of `/`,`?`,`#`.
    // The browser parses that URL as a navigation to victim.com,
    // benign in that order. But the INVERSE shape — `https://victim.com@attacker.com`
    // — produces an open redirect: operator's
    // `FRONTEND_URL` would format URLs like `{frontend}/settings?...`
    // → `https://victim.com@attacker.com/settings?...` → browser
    // navigates to attacker.com with userinfo `victim.com`. Same
    // open-redirect class as MCP-1000 originally closed for path
    // shapes, sibling to MCP-1157 which rejects `@` in OKTA_DOMAIN
    // for the same reason. Whitespace + control chars are
    // additional canonical hostname-invalid shapes that can produce
    // HTTP header smuggling when the URL is interpolated into a
    // `Location:` header.
    !after_scheme.is_empty()
        && !after_scheme.contains('/')
        && !after_scheme.contains('?')
        && !after_scheme.contains('#')
        && !after_scheme.contains('@')
        && !after_scheme
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// MCP-1094 (2026-05-16): canonical OAuth-callback `error` sanitiser.
///
/// All four OAuth-callback handlers (talos-slack, talos-gmail,
/// talos-atlassian, controller `oauth_callback_handler`) take the
/// provider-supplied `error` query param and urlencode it directly into
/// a redirect URL aimed at the dashboard:
///
/// ```text
/// {frontend_url}/settings?gmail_error={error}
/// ```
///
/// Pre-fix the `error` value was passed through with no length cap or
/// charset validation. Per RFC 6749 §4.1.2.1 the OAuth `error` field is
/// a fixed enum (`invalid_request`, `access_denied`, …) — at most ~30
/// chars of `[a-z_]`. But the parameter is attacker-controllable: a
/// phishing link of the form
///
/// ```text
/// https://api.example.com/auth/slack/callback?error=Your+account+suspended+contact+support%40attacker.com
/// ```
///
/// produced a same-host server redirect whose query string carried the
/// attacker's social-engineering payload to the dashboard. The frontend
/// renders the value as if it were a legitimate Slack/Google/Atlassian
/// error — and the URL persists in browser history, proxy logs, and
/// Referer headers, so the payload spreads beyond the page render.
///
/// This helper validates: 1–64 chars, ASCII `[a-z0-9_-]` only (covers
/// every RFC 6749 OAuth error AND every provider extension currently in
/// use: Google's `interaction_required`/`login_required`/
/// `consent_required`/`account_selection_required`, Microsoft's
/// `invalid_grant`/`invalid_client`/`invalid_token`, GitHub's
/// `application_suspended`, Slack's `invalid_team_for_non_distributed_app`).
/// Anything else returns the generic `"oauth_error"` sentinel — the
/// frontend can map that to a "something went wrong, please try again"
/// message without trusting attacker-supplied text.
///
/// Returns a borrowed `&str` so the common (valid) case is allocation-free.
#[must_use]
pub fn sanitize_oauth_error_code(raw: &str) -> &str {
    const MAX_OAUTH_ERROR_LEN: usize = 64;
    const FALLBACK: &str = "oauth_error";
    if raw.is_empty() || raw.len() > MAX_OAUTH_ERROR_LEN {
        return FALLBACK;
    }
    let all_ok = raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if all_ok {
        raw
    } else {
        FALLBACK
    }
}

/// Number of days to retain workflow executions before cleanup. Default: 30.
///
/// MCP-1063 (2026-05-15): route through `positive_env_or_default` so
/// `EXECUTION_RETENTION_DAYS=0` (Helm placeholder) and negative values
/// substitute the default + WARN instead of becoming destructive. The
/// consumer in `controller/main.rs::execution_retention_cleanup_loop`
/// binds this directly into
/// `started_at < NOW() - INTERVAL '1 day' * $1` — with `=0` the
/// predicate becomes `started_at < NOW()` (matches every past
/// execution); with a negative value, `< NOW() + INTERVAL` (matches
/// every execution). Either is total purge of the workflow_executions
/// table on first sweep. Same `=0`/negative footgun class as
/// MCP-638/643/661/663/664/665/703/758/1055 (worker semaphores /
/// retention envs / embedding dimensions). Companion of MCP-1062's
/// function-boundary defense-in-depth — fixing the env-helper closes
/// the env-config attack vector at the source while the function
/// guards close other callers.
pub fn execution_retention_days() -> i32 {
    positive_env_or_default::<i32>("EXECUTION_RETENTION_DAYS", 30)
}

/// Maximum number of workflow execution rows to keep. Default: 100000.
///
/// MCP-1063 (2026-05-15): same `positive_env_or_default` routing as
/// `execution_retention_days`. `=0` would mean "evict every execution
/// on cap-enforcement sweep" — sibling destructive failure mode. No
/// production callers today, but the public API should default-fail
/// safely.
pub fn execution_max_rows() -> i64 {
    positive_env_or_default::<i64>("EXECUTION_MAX_ROWS", 100_000)
}

/// MCP-1060 (2026-05-15): read a boolean env var with a canonical set
/// of truthy / falsy tokens. Accepts `true | 1 | yes | on` (truthy) and
/// `false | 0 | no | off` (falsy), case-insensitive, leading/trailing
/// whitespace tolerant. Unset, empty, or unrecognised → `default`.
///
/// Pre-1060 three sites had inline copies of the same predicate:
/// `talos-auth::verify_token` (`JWT_REQUIRE_AUD`),
/// `talos-workflow-signing::strict_mode` (`TALOS_WORKFLOW_SIGNING_STRICT`),
/// `worker::host_impl::ALLOW_PRIVATE_HOST_TARGETS`. Slight predicate
/// drift across them: the worker accepted `"on"`, the other two didn't.
/// The auth site is the per-request hot path — `verify_token` is called
/// on every authenticated request, and the inline `env::var` read takes
/// the process-wide environ lock + allocates a String each time.
/// Operators routing through this helper PLUS wrapping in `LazyLock`
/// remove the per-request env-read entirely.
///
/// Unrecognised values (`=foo`, `=enable`, etc.) WARN with
/// `event_kind=env_bool_unrecognised_substituted` so misconfiguration
/// is visible without flipping behaviour silently.
///
/// Sibling of `positive_env_or_default` (MCP-643).
pub fn bool_env_or_default(var: &str, default: bool) -> bool {
    let raw = match env::var(var) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default;
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => {
            tracing::warn!(
                target: "talos_config",
                event_kind = "env_bool_unrecognised_substituted",
                var = var,
                configured = %raw,
                default = default,
                "{var}={raw:?} is not a recognised boolean token; using default {default}"
            );
            default
        }
    }
}

/// MCP-643 (2026-05-13): read a positive-integer env var, treating
/// missing, invalid, AND `=0` as "use default". Many retention /
/// cleanup / cap config envs in the controller (ARCHIVE_AFTER_DAYS,
/// AUDIT_LOG_RETENTION_DAYS, WASM_CACHE_*) have a destructive failure
/// mode when set to 0 — `retention_days=0` deletes every row older
/// than now (i.e., everything), `max_size_mb=0` evicts every cached
/// entry on the next sweep, etc.
///
/// Operators typically intend `=0` to mean "unlimited" / "disabled"
/// (common UNIX convention) but the SQL `< NOW() - interval '0 days'`
/// or `> 0 modules` cap gives the opposite. Substitute the default +
/// WARN so misconfiguration is visible without producing silent data
/// loss. Sibling to MCP-639 / MCP-640 / MCP-642 (worker / reporter
/// equivalents).
///
/// Generic over `T: FromStr + PartialOrd + Display + Copy` so callers
/// can use `i32`, `i64`, `u64`, etc. The `> zero` check uses
/// `T::default()` which is 0 for all primitive integers.
pub fn positive_env_or_default<T>(var: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Display + Default + PartialOrd + Copy,
{
    let parsed = env::var(var).ok().and_then(|v| v.parse::<T>().ok());
    match parsed {
        Some(n) if n > T::default() => n,
        Some(n) => {
            tracing::warn!(
                target: "talos_config",
                event_kind = "env_nonpositive_substituted",
                var = var,
                configured = %n,
                default = %default,
                "{var}={n} is a misconfiguration (would produce destructive zero/negative behaviour); using default {default}"
            );
            default
        }
        None => default,
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

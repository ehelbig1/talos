//! Search service: owns the embedding pipeline (config + provider
//! health + rate-limited single/batch embed) AND the semantic-search
//! fallback chain (caller-supplied embedding → auto-generate via
//! provider → vector search → trigram search → ILIKE search) that
//! previously lived inline in
//! `talos-mcp-handlers/src/search.rs::handle_search_workflows_semantic`.
//!
//! Architectural pattern: matches `talos-execution-orchestration`
//! (r295), `talos-workflow-manifest` (r302), `talos-replay-service`
//! (r303), and `talos-inline-compile-service` (r304). Arc-injected
//! dependencies, `thiserror` enum mapped to JSON-RPC codes via
//! `jsonrpc_code()`, typed input + outcome structs, and a
//! `user_facing_message()` accessor that collapses internal errors
//! to a generic message so the protocol response cannot leak schema
//! or query detail.
//!
//! The embedding primitives (config, generator, batch generator,
//! health probe, rate limiter) are exported as free functions / module
//! statics — they are stateless from the caller's POV (env-driven
//! config + global rate limiter + global health cache) and are used
//! across many call sites (auto-embed-on-publish, scheduled backfill,
//! ad-hoc semantic queries). The `SearchService` composes them with
//! `WorkflowRepository` SQL helpers to produce the canonical
//! semantic-search shape.
//!
//! Security posture (preserved from the inline handler verbatim):
//! - User_id scoped at the SQL layer — every search call binds the
//!   caller's user_id so cross-tenant leakage is impossible.
//! - Query length capped (≤ 500 chars) by the caller; service treats
//!   shorter inputs as fine.
//! - `min_score` clamped to `[0, 1]` so a misconfigured caller can't
//!   accidentally pass a wild value.
//! - Provider HTTP error bodies truncated to 512 chars before logging
//!   so a provider HTML error page can't blow up controller logs.
//! - Embed rate limiter shared process-wide so one chatty caller
//!   (auto-heal) can't starve another (semantic search).

#![forbid(unsafe_code)]

mod embedding;
mod provider_health;
mod sql_helpers;

pub use embedding::{
    auto_embed_workflow, generate_embedding, generate_embeddings_batch, provider_is_external,
    vec_to_pgvector_literal, workflow_embedding_text, EmbeddingConfig, EmbeddingError,
    EMBED_BATCH_MAX,
};
pub use provider_health::{
    embedding_provider_available, embedding_provider_status, refresh_embedding_provider_health,
    sanitize_provider_error_for_caller, ProviderHealth, PROVIDER_PROBE_INTERVAL,
};
pub use sql_helpers::escape_like;

use std::sync::Arc;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use talos_workflow_repository::WorkflowRepository;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Service-level errors. The `jsonrpc_code()` helper maps each variant
/// to a stable JSON-RPC error code so the MCP handler wrapper stays
/// trivial. Error messages match the pre-extraction handler shape
/// byte-for-byte.
#[derive(Debug, Error)]
pub enum SearchError {
    /// Caller-supplied argument failed structural validation
    /// (missing query, query too long, etc.). Maps to `-32602`.
    #[error("{0}")]
    InvalidArg(String),

    /// Required-path repository call returned an error. The detail is
    /// logged at `error!` level by the service; callers receive the
    /// generic mapped message. Maps to `-32000`.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl SearchError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArg(_) => -32602,
            Self::Internal(_) => -32000,
        }
    }

    /// Generic, callable-safe message for the protocol response.
    /// `Internal` collapses to `"Failed to search workflows"` so the
    /// response does not leak schema, query, or runtime-trap detail.
    /// Pre-extraction string preserved verbatim — operators recognise
    /// it from production logs.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidArg(msg) => msg.clone(),
            Self::Internal(_) => "Failed to search workflows".to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Inputs / outcome
// -----------------------------------------------------------------------------

/// Caller input for [`SearchService::search_semantic`]. The handler
/// is responsible for protocol-level argument parsing (length caps,
/// presence checks) before constructing this — the service's
/// validation surface is intentionally narrow.
pub struct SemanticSearchInput<'a> {
    pub user_id: Uuid,
    /// Pre-validated by caller (≤ 500 chars, non-empty).
    pub query: &'a str,
    /// Pre-validated by caller (clamped to `[1, 50]`).
    pub limit: i32,
    /// Optional tag filter (`≤ 100` chars when present).
    pub tag_filter: Option<&'a str>,
    /// When `true`, archived workflows are included in the result set.
    pub include_archived: bool,
    /// Minimum cosine similarity threshold for vector-search results.
    /// Pre-clamped by caller to `[0, 1]`. Applied AFTER vector search
    /// so rows below the floor are filtered out (and we do NOT fall
    /// through to trigram for those — strict-threshold callers want
    /// "no confident match," not "keyword noise").
    pub min_score: f64,
    /// Caller-supplied pre-computed embedding. When present, skips
    /// the auto-generate step. Used by callers that have already
    /// computed an embedding (e.g. dispatch hooks).
    pub caller_embedding: Option<Vec<f64>>,
    /// Expected dimension count for embeddings (must match the
    /// pgvector column size). Pre-resolved by caller from
    /// `EMBEDDING_DIMENSIONS`. Service uses this to dimension-check
    /// both caller_embedding AND auto-generated embeddings.
    pub expected_dims: usize,
}

/// Outcome of [`SearchService::search_semantic`].
///
/// M-G (2026-05-06): the outcome carries `match_method` and
/// `min_score_applied` at the envelope level so the metadata stays
/// visible even when `results` is empty. Pre-fix, an empty result
/// set serialised as a bare `[]` and the operator could not tell
/// whether the threshold filtered everything out, the embedding
/// provider was unreachable, or the query simply matched nothing.
/// Per-row fields preserve `match_score` (genuinely per-row).
///
/// MCP-5 (2026-05-07): per-row `min_score_applied` removed. It was
/// preserved as a BC shim earlier but is pure redundancy — the same
/// value as the envelope on every row. For 1000-result calls that's
/// 1000 redundant copies. Per-row `match_method` is still preserved
/// because the fallback chain CAN return a mix (e.g. vector + trigram
/// rows) where each row's method is genuinely per-row.
#[derive(Debug, Default, Serialize)]
pub struct SemanticSearchOutcome {
    pub results: Vec<SemanticSearchRow>,
    /// Which fallback rung produced these rows: vector / trigram /
    /// keyword. `None` when no path was attempted (e.g. invalid
    /// query). Always `Some(_)` once a search runs to completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_method: Option<MatchMethod>,
    /// Cosine-similarity threshold applied for vector matches.
    /// `None` when the path that ran wasn't vector (trigram /
    /// keyword) — there's no threshold to surface in those cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score_applied: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct SemanticSearchRow {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    /// Readiness score is `Option<i32>` because the underlying
    /// SQL column is nullable (workflows that haven't been scored yet).
    /// Null serialises as JSON `null`, matching pre-extraction behaviour.
    pub readiness_score: Option<i32>,
    pub match_score: serde_json::Value,
    pub match_method: MatchMethod,
    // MCP-5: per-row `min_score_applied` removed (closed 2026-05-07).
    // The envelope-level `min_score_applied` is the single source of truth
    // for the threshold; per-row was always the same value across every
    // row of the same response. Read it off the envelope.
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMethod {
    Vector,
    Trigram,
    Keyword,
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Search service. Holds Arc-wrapped dependencies; safe to clone
/// (cheap reference-count bumps). Constructed once at controller
/// boot and shared across the MCP handler tree (and any future
/// GraphQL surface).
pub struct SearchService {
    workflow_repo: Arc<WorkflowRepository>,
}

impl SearchService {
    pub fn new(workflow_repo: Arc<WorkflowRepository>) -> Self {
        Self { workflow_repo }
    }

    /// Run the semantic-search fallback chain:
    ///
    /// 1. Resolve the query embedding — caller-supplied wins, otherwise
    ///    auto-generate via the provider. Auto-generation failures fall
    ///    through to keyword search rather than aborting (semantic
    ///    search is best-effort).
    /// 2. If an embedding was resolved AND it matches `expected_dims`,
    ///    run pgvector cosine-similarity search. Apply `min_score`
    ///    threshold. If any rows survive, return them as `Vector` matches
    ///    — even if 0 rows survive thresholding, do NOT fall through;
    ///    the vector path ran successfully and produced no confident
    ///    matches.
    /// 3. Otherwise fall through to pg_trgm trigram search.
    /// 4. If pg_trgm is unavailable (extension not installed), fall
    ///    further through to ILIKE on the first ≥2-char word.
    ///
    /// Words are extracted from the query for the keyword-fallback
    /// match-score helper; queries with no ≥2-char word return
    /// `InvalidArg`.
    pub async fn search_semantic(
        &self,
        input: SemanticSearchInput<'_>,
    ) -> Result<SemanticSearchOutcome, SearchError> {
        // N T5-N2: archive filter is now a typed boolean threaded
        // through to the SQL via a bind parameter. Pre-fix this branch
        // produced a SQL fragment that was interpolated into the query
        // via `format!()` — safe because the branch was static, but a
        // future refactor that forwarded user input would have tripped
        // a SQL-fragment injection footgun. The bool eliminates the
        // surface entirely.
        let include_archived = input.include_archived;

        // 1. Resolve query embedding.
        //
        // MCP-445: short-circuit when the cached provider-health probe
        // reports the provider is down. Pre-fix every semantic search
        // during a sustained outage waited up to the 30-second per-call
        // timeout (see `generate_embeddings_batch`); concurrent calls
        // stacked up and starved the request budget for the rest of
        // the controller. The cached health is at worst
        // `PROVIDER_PROBE_INTERVAL` (5 min) stale — well-traded against
        // 30s per-request during a real outage. Caller-supplied
        // embeddings bypass this gate (the caller already computed
        // them; nothing to skip).
        let auto_embedding: Option<Vec<f64>> = if input.caller_embedding.is_none() {
            if !embedding_provider_available() {
                tracing::debug!(
                    "semantic search: embedding provider marked unavailable by health probe; \
                     skipping auto-embed and falling back to keyword"
                );
                None
            } else {
                match generate_embedding(input.query).await {
                    Ok(v) => Some(v.into_iter().map(|f| f as f64).collect()),
                    Err(e) => {
                        tracing::debug!(
                            kind = e.kind(),
                            "semantic search query embed failed; falling back to keyword"
                        );
                        None
                    }
                }
            }
        } else {
            None
        };
        let embedding_vec: Option<Vec<f64>> = input.caller_embedding.or(auto_embedding);

        // 2. Vector search (when embedding resolves and dims match).
        if let Some(ref emb) = embedding_vec {
            if emb.len() == input.expected_dims {
                let emb_str = talos_workflow_repository::format_pgvector_literal(emb);
                let rows_res = self
                    .workflow_repo
                    .search_workflows_by_embedding(
                        input.user_id,
                        &emb_str,
                        input.tag_filter,
                        include_archived,
                        input.limit,
                    )
                    .await;

                if let Ok(rows) = rows_res {
                    if !rows.is_empty() {
                        let results: Vec<SemanticSearchRow> = rows
                            .into_iter()
                            .filter_map(|r| {
                                if r.match_score < input.min_score {
                                    return None;
                                }
                                Some(SemanticSearchRow {
                                    id: r.id,
                                    name: r.name,
                                    description: r.description,
                                    capabilities: r.capabilities,
                                    readiness_score: r.readiness_score,
                                    match_score: serde_json::json!(r.match_score),
                                    match_method: MatchMethod::Vector,
                                })
                            })
                            .collect();
                        // Even when filter empties the list, return — the
                        // vector path ran successfully and produced no
                        // confident matches. Falling through would surface
                        // keyword noise that a strict-threshold caller
                        // just rejected. M-G: stamp envelope metadata so
                        // an empty results array still tells the operator
                        // which path ran and what threshold was applied.
                        return Ok(SemanticSearchOutcome {
                            results,
                            match_method: Some(MatchMethod::Vector),
                            min_score_applied: Some(input.min_score),
                        });
                    }
                }
                // Fall through to trigram on vector error or empty rows.
            }
        }

        // 3. Trigram / 4. ILIKE fallback.
        let words = extract_query_ilike_words(input.query);

        if words.is_empty() {
            return Err(SearchError::InvalidArg(
                "Query must contain at least one word with 2+ characters".to_string(),
            ));
        }

        let ilike_pattern = format!("%{}%", escape_like(input.query));
        let trgm_result = self
            .workflow_repo
            .search_workflows_trgm(
                input.user_id,
                input.query,
                &ilike_pattern,
                input.tag_filter,
                include_archived,
                input.limit,
            )
            .await;

        let rows = match trgm_result {
            Ok(rows) => rows,
            Err(_) => {
                let base_pattern = &words[0];
                self.workflow_repo
                    .search_workflows_ilike_fallback(
                        input.user_id,
                        base_pattern,
                        input.tag_filter,
                        include_archived,
                        input.limit,
                    )
                    .await
                    .map_err(|e| {
                        tracing::error!("search_workflows_ilike_fallback failed: {:#}", e);
                        SearchError::Internal(anyhow::Error::from(e))
                    })?
            }
        };

        // The repo distinguishes via Option<f64>: Some = trigram path,
        // None = ILIKE fallback. Compute keyword-match score for the
        // ILIKE branch via the shared pure helper.
        let has_trgm_score = rows.iter().any(|r| r.match_score.is_some());
        let mut results: Vec<SemanticSearchRow> = rows
            .into_iter()
            .map(|r| {
                if let Some(score) = r.match_score {
                    SemanticSearchRow {
                        id: r.id,
                        name: r.name,
                        description: r.description,
                        capabilities: r.capabilities,
                        readiness_score: r.readiness_score,
                        match_score: serde_json::json!(score),
                        match_method: MatchMethod::Trigram,
                    }
                } else {
                    let score = talos_workflow_repository::compute_keyword_match_score(
                        &r.name,
                        r.description.as_deref(),
                        &r.capabilities,
                        r.intent.as_ref(),
                        &words,
                    );
                    SemanticSearchRow {
                        id: r.id,
                        name: r.name,
                        description: r.description,
                        capabilities: r.capabilities,
                        readiness_score: r.readiness_score,
                        match_score: serde_json::json!(score),
                        match_method: MatchMethod::Keyword,
                    }
                }
            })
            .collect();

        // ILIKE-fallback rows come back unsorted; sort by score desc
        // so the response always presents most-relevant first.
        if !has_trgm_score {
            results.sort_by(|a, b| {
                let sa = a.match_score.as_i64().unwrap_or(0);
                let sb = b.match_score.as_i64().unwrap_or(0);
                sb.cmp(&sa)
            });
        }

        // M-G: stamp envelope metadata so an empty results array still
        // tells the operator which path ran. min_score_applied stays
        // None for non-vector paths — there's no threshold to surface.
        let envelope_method = if has_trgm_score {
            MatchMethod::Trigram
        } else {
            MatchMethod::Keyword
        };
        Ok(SemanticSearchOutcome {
            results,
            match_method: Some(envelope_method),
            min_score_applied: None,
        })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

/// Split the raw query into ILIKE-ready word patterns for the
/// trigram / keyword fallback rungs.
///
/// MCP-493: word-length gate uses `chars().count()` (codepoints)
/// not `len()` (bytes). `len()` let single CJK / emoji
/// characters slip past the "2+ characters" floor because a
/// single multi-byte codepoint has byte-length ≥ 2 — the
/// error message AND the intent of the filter are both
/// character-count, so the byte form was inconsistent. CJK
/// queries also hit the keyword-ILIKE rung specifically (pg_trgm
/// n-grams don't index non-Latin scripts well), so a single-char
/// CJK query would scan the whole workflow table with
/// `ILIKE '%X%'` — a small DoS-flavored perf footgun.
///
/// Each accepted word is lowercased, LIKE-escaped, and wrapped
/// with `%...%`. Empty result = caller's query had no usable
/// words.
fn extract_query_ilike_words(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .filter(|w| w.chars().count() > 1)
        .map(|w| format!("%{}%", escape_like(&w.to_lowercase())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_codes_are_stable() {
        assert_eq!(SearchError::InvalidArg("x".into()).jsonrpc_code(), -32602);
        assert_eq!(
            SearchError::Internal(anyhow::anyhow!("boom")).jsonrpc_code(),
            -32000,
        );
    }

    #[test]
    fn internal_user_message_does_not_leak_detail() {
        let err = SearchError::Internal(anyhow::anyhow!(
            "ERROR: relation \"workflows_embedding_idx\" does not exist"
        ));
        assert_eq!(err.user_facing_message(), "Failed to search workflows");
    }

    #[test]
    fn invalid_arg_user_message_passes_through() {
        let err = SearchError::InvalidArg("Query must contain at least one word".into());
        assert_eq!(
            err.user_facing_message(),
            "Query must contain at least one word",
        );
    }

    #[test]
    fn match_method_serialises_lowercase() {
        let v = serde_json::to_value(MatchMethod::Vector).unwrap();
        assert_eq!(v, serde_json::json!("vector"));
        let t = serde_json::to_value(MatchMethod::Trigram).unwrap();
        assert_eq!(t, serde_json::json!("trigram"));
        let k = serde_json::to_value(MatchMethod::Keyword).unwrap();
        assert_eq!(k, serde_json::json!("keyword"));
    }

    /// MCP-5 (closed): per-row min_score_applied was always identical to the
    /// envelope value. Strip it from rows; the envelope is the single source.
    #[test]
    fn semantic_search_row_does_not_emit_per_row_min_score() {
        let row = SemanticSearchRow {
            id: Uuid::nil(),
            name: "x".into(),
            description: None,
            capabilities: vec![],
            readiness_score: Some(0),
            match_score: serde_json::json!(0.5),
            match_method: MatchMethod::Trigram,
        };
        let s = serde_json::to_value(row).unwrap();
        assert!(
            s.get("min_score_applied").is_none(),
            "MCP-5: per-row min_score_applied removed; envelope-level only"
        );
        assert!(s.get("description").is_none());
    }

    #[test]
    fn semantic_search_row_vector_omits_per_row_min_score_too() {
        let row = SemanticSearchRow {
            id: Uuid::nil(),
            name: "x".into(),
            description: Some("d".into()),
            capabilities: vec!["c".into()],
            readiness_score: Some(5),
            match_score: serde_json::json!(0.85),
            match_method: MatchMethod::Vector,
        };
        let s = serde_json::to_value(row).unwrap();
        assert!(
            s.get("min_score_applied").is_none(),
            "MCP-5: per-row min_score_applied removed across all match_methods"
        );
        assert_eq!(s["match_method"], serde_json::json!("vector"));
    }

    #[test]
    fn extract_query_ilike_words_filters_single_ascii_char() {
        // ASCII single-char must be filtered out (matches the existing
        // contract). This is unchanged by MCP-493.
        let words = extract_query_ilike_words("a hello world");
        assert_eq!(words, vec!["%hello%".to_string(), "%world%".to_string()]);
    }

    #[test]
    fn extract_query_ilike_words_filters_single_cjk_char() {
        // MCP-493: pre-fix `"你"` (one CJK character, 3 bytes) passed
        // `w.len() > 1` and reached the ILIKE rung as a single-char
        // wildcard search — expensive against any non-trivial workflow
        // table. With `chars().count() > 1`, a single codepoint is
        // correctly rejected just like single ASCII chars.
        let words = extract_query_ilike_words("你");
        assert!(
            words.is_empty(),
            "single CJK codepoint must be filtered, got {:?}",
            words
        );
    }

    #[test]
    fn extract_query_ilike_words_filters_single_emoji() {
        // Emoji are 4+ bytes. Same regression class as CJK — pre-fix
        // `"🙂"` (4 bytes) passed the gate; post-fix it's correctly
        // rejected as a single codepoint.
        let words = extract_query_ilike_words("🙂");
        assert!(
            words.is_empty(),
            "single emoji must be filtered, got {:?}",
            words
        );
    }

    #[test]
    fn extract_query_ilike_words_accepts_multi_char_cjk() {
        // Two-codepoint CJK term is a legitimate search; must be
        // accepted and lowercased + LIKE-escaped per the contract.
        let words = extract_query_ilike_words("北京");
        assert_eq!(words.len(), 1);
        assert!(words[0].contains("北京"));
    }

    #[test]
    fn extract_query_ilike_words_escapes_like_metas() {
        // The escape_like wrapper protects against `%` / `_` in the
        // search term being interpreted as ILIKE wildcards. Without
        // it, an attacker passing `query: "%%"` would match every
        // row in the table.
        let words = extract_query_ilike_words("a%b");
        assert_eq!(words, vec![r"%a\%b%".to_string()]);
    }

    /// MCP-5: envelope keeps min_score_applied (single source of truth).
    #[test]
    fn outcome_envelope_emits_min_score() {
        let outcome = SemanticSearchOutcome {
            results: vec![],
            match_method: Some(MatchMethod::Vector),
            min_score_applied: Some(0.4),
        };
        let s = serde_json::to_value(outcome).unwrap();
        assert_eq!(s["min_score_applied"], serde_json::json!(0.4));
        assert_eq!(s["match_method"], serde_json::json!("vector"));
    }
}

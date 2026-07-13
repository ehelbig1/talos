//! RFC 0011 P1 — datasets + model registry + pluggable inference backends.
//!
//! The ML-lifecycle substrate: workflows (or MCP) append labeled examples
//! to org-scoped datasets; the registry versions models over those
//! datasets; the eval harness selects a backend empirically (vs. the LLM
//! baseline); the promoted version serves predictions. P1 backends are
//! the lazy pair (`knn-pgvector`, `llm`) — parametric backends
//! (`classical`, `statistical`, `onnx`) slot into the same registry in
//! P2/P3 without schema changes.
//!
//! Tenancy: all queries take a caller-supplied executor so request paths
//! run them on tenant-scoped transactions (RLS fail-closed on all four
//! tables). Feature payloads are encrypted per-org (AEAD v4-or-global,
//! actor_memory discipline); embeddings are computed with the LOCAL
//! embedding pipeline only — dataset content never leaves the host.

pub mod correction;
pub mod dataset;
pub mod delete;
pub mod digest;
pub mod distill;
pub mod eval;
pub mod knn;
pub mod lifecycle;
pub mod lifecycle_job;
pub mod linear;
pub mod provision;
pub mod registry;
pub mod serve;

pub use correction::{resolve_disagreement, ResolveError, ResolveOutcome};
pub use dataset::{
    AppendExample, DatasetService, DatasetStats, DatasetTenancy, ExampleSource, HoldoutExample,
    PreparedExample, SampledExample,
};
pub use delete::{delete_model, DeleteError, DeleteOutcome};
pub use digest::{run_digest_tick, spawn_disagreement_digest};
pub use distill::{spawn_distill_from_output, DistillContext, DISTILL_CONTEXT};
pub use eval::{
    coverage_curve, evaluate_predictions, macro_f1, macro_recall, run_backend_selection_eval,
    run_knn_eval, stratified_holdout, BackendCandidate, ClassMetrics, CoveragePoint, EvalReport,
    MIN_CLASS_FOR_HOLDOUT,
};
pub use knn::{knn_vote, knn_vote_balanced, KnnPrediction, Neighbor};
pub use lifecycle::{
    can_transition, confidence_band, evaluate_policy, validate_llm_locality, LifecycleService,
    LifecycleState, PolicyDecision, PolicyInputs, PolicyJson,
};
pub use lifecycle_job::{run_policy_tick, spawn_policy_evaluator};
pub use linear::{FitOpts, LinearModel, LinearPrediction};
pub use provision::{provision_classifier, ProvisionError, ProvisionInput, ProvisionOutcome};
pub use registry::{ModelRegistry, ModelReviewSummary, ModelVersionRow, ResolvedModel};
pub use serve::{
    invalidate_serving_cache, serve_predict_batch, ServeError, ServeReply, ServedPrediction,
    ServingMode,
};

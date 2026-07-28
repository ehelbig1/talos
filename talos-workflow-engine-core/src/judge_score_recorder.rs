//! Write-side port for observe-only judge verdicts. When a `Judge` /
//! `InlineJudge` system node attaches `__judge_score__` / `__judge_passed__`
//! to its parent output, the engine records the (score, passed) pair
//! through this port so the weekly `assistant_report` node can aggregate
//! it WITHOUT reading the encrypted node outputs it lives in.
//!
//! Same plugged-adapter architecture as [`crate::AssistantReportReader`]
//! and [`crate::OpsAlertsReader`]: the node executes CONTROLLER-side, the
//! Postgres impl lives in `talos-engine`. `None` (out-of-tree consumers /
//! tests without a store) simply skips recording.
//!
//! DLP: impls persist scores and the pass boolean ONLY — never the judge
//! reasoning/feedback text, which can quote email-derived content.

use async_trait::async_trait;
use uuid::Uuid;

/// Record one judge verdict. **Best-effort**: impls MUST swallow their
/// own errors (log-and-drop) — a failed record must never fail the
/// workflow. The engine additionally calls this off the hot path via
/// `tokio::spawn`, so `record` may block on I/O without stalling dispatch.
#[async_trait]
pub trait JudgeScoreRecorder: Send + Sync {
    /// Persist one `(workflow_id, node_id, execution_id, score, passed,
    /// not_applicable)` verdict row. Impls MUST NOT return errors — swallow
    /// and log them.
    ///
    /// `not_applicable = true` marks an ABSTENTION: the judge declared this
    /// run had nothing to judge. The row IS written (so the abstention rate
    /// is recoverable — "ran 17×, abstained 12×" must not look like "ran
    /// 5×"), but every quality aggregate excludes it structurally via
    /// `FILTER (WHERE NOT not_applicable)`. `score`/`passed` are stored
    /// as-authored and are meaningless for such a row.
    async fn record(
        &self,
        workflow_id: Uuid,
        node_id: Uuid,
        execution_id: Uuid,
        score: f64,
        passed: bool,
        not_applicable: bool,
    );
}

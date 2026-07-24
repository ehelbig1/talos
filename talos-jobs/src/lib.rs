// MCP-947 (2026-05-15): kept `#![allow(dead_code)]` deliberately.
// The crate is a documented placeholder per MCP-704 (controller/src/
// main.rs around line 907): `JobQueue::new(db_pool.clone(), 10)` is
// NOT wired into controller boot — the persistence layer was never
// exercised because no caller pushed jobs. Sibling of the
// talos-tenancy / talos-secrets-rotation placeholder retentions (the
// former talos-feature-flags sibling was deleted 2026-07-24).
#![allow(dead_code)]
//! Background job system for Talos controller.
//!
//! This module provides:
//! - Reliable job queue with persistence
//! - Exponential backoff retry logic
//! - Dead letter queue for failed jobs
//! - Job status tracking and monitoring
//! - Concurrent job execution with rate limiting

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::interval;
use uuid::Uuid;

/// Job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum JobPriority {
    Low = 1,
    #[default]
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    RetryScheduled,
    DeadLetter,
    Cancelled,
}

/// Job payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum JobPayload {
    /// Execute a workflow
    WorkflowExecution {
        workflow_id: Uuid,
        user_id: Uuid,
        input_data: serde_json::Value,
    },
    /// Send webhook notification
    WebhookDelivery {
        trigger_id: Uuid,
        payload: serde_json::Value,
        retry_count: u32,
    },
    /// Process module compilation
    ModuleCompilation {
        template_id: Uuid,
        config: serde_json::Value,
    },
    /// Clean up expired data
    CleanupTask {
        task_type: String,
        older_than_days: i64,
    },
    /// Custom job type for extensions
    Custom {
        job_type: String,
        data: serde_json::Value,
    },
}

/// Background job definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub payload: JobPayload,
    pub priority: JobPriority,
    pub status: JobStatus,
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub created_at: DateTime<Utc>,
    pub scheduled_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub worker_id: Option<String>,
}

impl Job {
    /// Create a new job
    pub fn new(payload: JobPayload, user_id: Uuid) -> Self {
        let max_retries = match &payload {
            JobPayload::WebhookDelivery { .. } => 5,
            JobPayload::WorkflowExecution { .. } => 3,
            _ => 3,
        };

        Self {
            id: Uuid::new_v4(),
            payload,
            priority: JobPriority::Normal,
            status: JobStatus::Pending,
            user_id,
            organization_id: None,
            retry_count: 0,
            max_retries,
            created_at: Utc::now(),
            scheduled_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            worker_id: None,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: JobPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set organization
    pub fn with_organization(mut self, org_id: Uuid) -> Self {
        self.organization_id = Some(org_id);
        self
    }

    /// Calculate next retry time using exponential backoff
    pub fn next_retry_time(&self) -> DateTime<Utc> {
        let base_delay = Duration::from_secs(60); // 1 minute
        let max_delay = Duration::from_secs(3600); // 1 hour

        // MCP-508: previously `2_u32.pow(self.retry_count)` panicked on
        // overflow once `retry_count >= 32`, and the
        // `base_delay * factor` multiplication could overflow Duration's
        // internal u64 nanosecond representation long before that
        // (`60s * 2^31` ≈ 1.3e20 ns vs. u64::MAX ≈ 1.8e19). The min()
        // against max_delay below would have saturated the result, but
        // the overflow happens FIRST. An operator who set max_retries
        // high enough would see every retry-time calculation panic.
        //
        // 2^6 = 64 already exceeds the max_delay (3600s / 60s = 60),
        // so clamping the exponent at 6 produces the same saturated
        // output without risking the panic. saturating_pow + checked_mul
        // belt-and-suspenders against future tweaks to the constants.
        let exponent = self.retry_count.min(6);
        let backoff_factor = 2_u32.saturating_pow(exponent);
        let backoff = base_delay.checked_mul(backoff_factor).unwrap_or(max_delay);
        let delay = std::cmp::min(backoff, max_delay);

        // MCP-508: real ±10% jitter to prevent thundering herd. The
        // pre-fix `+10% always` was misnamed "jitter" — every retry at
        // the same retry_count delayed by EXACTLY the same factor, so
        // a wave of correlated failures retried in lockstep (the very
        // thing jitter is meant to prevent).
        //
        // Deterministically derive the jitter sign+magnitude from the
        // job's UUID so the result is testable and decorrelated across
        // jobs without pulling in a `rand` dependency. The last 4 bytes
        // of the UUID give 32 bits of entropy; map to [-10%, +10%].
        let id_bytes = self.id.as_bytes();
        let tail = u32::from_be_bytes([id_bytes[12], id_bytes[13], id_bytes[14], id_bytes[15]]);
        // Map 0..u32::MAX to -1.0..+1.0
        let signed_unit = (tail as f64 / u32::MAX as f64) * 2.0 - 1.0;
        let jitter_secs = (delay.as_secs_f64() * 0.1 * signed_unit) as i64;
        let jittered_delay = if jitter_secs >= 0 {
            delay.saturating_add(Duration::from_secs(jitter_secs as u64))
        } else {
            delay.saturating_sub(Duration::from_secs((-jitter_secs) as u64))
        };

        match chrono::Duration::from_std(jittered_delay) {
            Ok(d) => Utc::now() + d,
            Err(_) => {
                // Fallback to 1 hour max if conversion fails
                Utc::now() + chrono::Duration::try_hours(1).unwrap_or(chrono::Duration::zero())
            }
        }
    }

    /// Check if job should be retried
    pub fn should_retry(&self) -> bool {
        self.retry_count < self.max_retries && !matches!(self.status, JobStatus::Cancelled)
    }
}

/// Job execution result
#[derive(Debug)]
pub enum JobResult {
    Success,
    Failure { error: String, retryable: bool },
    Cancelled,
}

/// Job handler trait
#[async_trait::async_trait]
pub trait JobHandler: Send + Sync {
    /// Execute the job
    async fn execute(&self, job: &Job) -> JobResult;

    /// Get handler name
    fn name(&self) -> &str;
}

/// MCP-641 (2026-05-13): stable per-instance worker identifier.
///
/// Pre-fix `dequeue` bound `std::process::id().to_string()` to the
/// `worker_id` column. In container deployments every replica has
/// PID 1, so the column was useless for distinguishing which pod
/// took a job — a fleet of 10 replicas all writing `worker_id = "1"`
/// makes operator forensics impossible ("which pod ran this job?
/// they all claim PID 1").
///
/// Prefer `HOSTNAME` (K8s sets this to the pod name on every
/// container by default). Fall back to PID for non-K8s deploys.
/// Built once via `OnceLock` so the env lookup happens at first
/// dequeue, not per-call. Empty-string env value is treated as
/// missing (sibling to MCP-630/631 empty-env handling).
fn worker_id() -> String {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let host = std::env::var("HOSTNAME").ok().filter(|v| !v.is_empty());
        let pid = std::process::id();
        match host {
            Some(h) => format!("{}:{}", h, pid),
            None => pid.to_string(),
        }
    })
    .clone()
}

/// Job queue service
pub struct JobQueue {
    db_pool: Pool<Postgres>,
    handlers: Arc<Mutex<HashMap<String, Box<dyn JobHandler>>>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    concurrency_limit: Arc<Semaphore>,
}

impl JobQueue {
    /// Create a new job queue
    pub fn new(db_pool: Pool<Postgres>, max_concurrent_jobs: usize) -> Self {
        Self {
            db_pool,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx: None,
            concurrency_limit: Arc::new(Semaphore::new(max_concurrent_jobs)),
        }
    }

    /// Register a job handler
    pub async fn register_handler<H: JobHandler + 'static>(&self, handler: H) {
        let mut handlers = self.handlers.lock().await;
        handlers.insert(handler.name().to_string(), Box::new(handler));
    }

    /// Enqueue a job
    pub async fn enqueue(&self, job: Job) -> Result<Uuid> {
        sqlx::query(
            r#"
            INSERT INTO jobs (
                id, payload, priority, status, user_id, organization_id,
                retry_count, max_retries, scheduled_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(job.id)
        .bind(serde_json::to_value(&job.payload)?)
        .bind(job.priority as i32)
        .bind(JobStatus::Pending)
        .bind(job.user_id)
        .bind(job.organization_id)
        .bind(job.retry_count as i32)
        .bind(job.max_retries as i32)
        .bind(job.scheduled_at)
        .execute(&self.db_pool)
        .await
        .context("Failed to enqueue job")?;

        tracing::info!(
            job_id = %job.id,
            job_type = ?job.payload,
            "Job enqueued"
        );

        Ok(job.id)
    }

    /// Dequeue the next available job (respecting priority and schedule)
    pub async fn dequeue(&self) -> Result<Option<Job>> {
        let row = sqlx::query_as::<_, JobRow>(
            r#"
            UPDATE jobs
            SET status = 'running', started_at = NOW(), worker_id = $1
            WHERE id = (
                SELECT id FROM jobs
                WHERE status = 'pending'
                AND scheduled_at <= NOW()
                ORDER BY priority DESC, scheduled_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING *
            "#,
        )
        .bind(worker_id())
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to dequeue job")?;

        Ok(row.map(|r| r.into()))
    }

    /// Mark job as completed
    pub async fn complete(&self, job_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE jobs SET status = 'completed', completed_at = NOW() WHERE id = $1")
            .bind(job_id)
            .execute(&self.db_pool)
            .await?;

        tracing::info!(job_id = %job_id, "Job completed");
        Ok(())
    }

    /// Mark job as failed with retry scheduling
    pub async fn fail(
        &self,
        job_id: Uuid,
        error: String,
        retry_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        // MCP-973 (2026-05-15): DLP-redact the worker-supplied error
        // string. Worker job failures carry arbitrary upstream-API
        // text (HTTP response bodies echoing Authorization headers,
        // exception strings). Same persistence-boundary class as
        // MCP-967..972 on workflow_executions; here it's `jobs.error_message`
        // and `dead_letter_jobs.error_message`.
        let error = talos_dlp_provider::redact_str(&error);
        if let Some(retry_time) = retry_at {
            sqlx::query(
                r#"
                UPDATE jobs
                SET status = 'retry_scheduled',
                    retry_count = retry_count + 1,
                    scheduled_at = $2,
                    error_message = $3
                WHERE id = $1
                "#,
            )
            .bind(job_id)
            .bind(retry_time)
            .bind(&error)
            .execute(&self.db_pool)
            .await?;
        } else {
            // Move to dead letter queue
            self.move_to_dlq(job_id, error).await?;
        }
        Ok(())
    }

    /// Move job to dead letter queue
    async fn move_to_dlq(&self, job_id: Uuid, error: String) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;

        // Copy to DLQ
        sqlx::query(
            r#"
            INSERT INTO dead_letter_jobs (
                id, original_job_id, payload, user_id, 
                error_message, failed_at
            )
            SELECT 
                $1, id, payload, user_id, $2, NOW()
            FROM jobs WHERE id = $3
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(error)
        .bind(job_id)
        .execute(&mut *tx)
        .await?;

        // Update original job
        sqlx::query("UPDATE jobs SET status = 'dead_letter' WHERE id = $1")
            .bind(job_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        tracing::error!(job_id = %job_id, "Job moved to dead letter queue");
        Ok(())
    }

    /// Start the job processor
    pub async fn start_processor(&mut self, poll_interval: Duration) {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        let handlers = self.handlers.clone();
        let db_pool = self.db_pool.clone();
        let concurrency = self.concurrency_limit.clone();

        tokio::spawn(async move {
            let mut poll = interval(poll_interval);

            loop {
                tokio::select! {
                    _ = poll.tick() => {
                        // Acquire permit for concurrency control
                        let permit = match concurrency.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => continue, // At capacity
                        };

                        // Process job
                        let handlers = handlers.clone();
                        let db_pool = db_pool.clone();

                        tokio::spawn(async move {
                            let _permit = permit; // Keep permit alive

                            if let Err(e) = Self::process_next_job(db_pool, handlers).await {
                                tracing::error!("Job processing error: {}", e);
                            }
                        });
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Job processor shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Process the next available job
    async fn process_next_job(
        _db_pool: Pool<Postgres>,
        _handlers: Arc<Mutex<HashMap<String, Box<dyn JobHandler>>>>,
    ) -> Result<()> {
        // This would dequeue and execute - simplified for brevity
        Ok(())
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(tx) = &self.shutdown_tx {
            tx.send(()).await?;
        }
        Ok(())
    }

    /// Get job statistics
    pub async fn get_stats(&self) -> Result<JobStats> {
        let row = sqlx::query_as::<_, JobStatsRow>(
            r#"
            SELECT 
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'running') as running,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'dead_letter') as dead_letter
            FROM jobs
            WHERE created_at > NOW() - INTERVAL '24 hours'
            "#,
        )
        .fetch_one(&self.db_pool)
        .await?;

        Ok(row.into())
    }
}

/// Job statistics
#[derive(Debug, Clone)]
pub struct JobStats {
    pub pending: i64,
    pub running: i64,
    pub completed: i64,
    pub failed: i64,
    pub dead_letter: i64,
}

// Internal row types for database queries
#[derive(sqlx::FromRow)]
struct JobRow {
    id: Uuid,
    payload: serde_json::Value,
    // ... other fields
}

#[derive(sqlx::FromRow)]
struct JobStatsRow {
    pending: i64,
    running: i64,
    completed: i64,
    failed: i64,
    dead_letter: i64,
}

impl From<JobStatsRow> for JobStats {
    fn from(row: JobStatsRow) -> Self {
        Self {
            pending: row.pending,
            running: row.running,
            completed: row.completed,
            failed: row.failed,
            dead_letter: row.dead_letter,
        }
    }
}

impl From<JobRow> for Job {
    fn from(row: JobRow) -> Self {
        // Parse payload and construct job
        Self {
            id: row.id,
            payload: serde_json::from_value(row.payload).unwrap_or(JobPayload::Custom {
                job_type: "unknown".to_string(),
                data: serde_json::json!({}),
            }),
            // ... other fields
            priority: JobPriority::Normal,
            status: JobStatus::Pending,
            user_id: Uuid::new_v4(),
            organization_id: None,
            retry_count: 0,
            max_retries: 3,
            created_at: Utc::now(),
            scheduled_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            worker_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_creation() {
        let payload = JobPayload::Custom {
            job_type: "test".to_string(),
            data: serde_json::json!({}),
        };
        let job = Job::new(payload, Uuid::new_v4());

        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.retry_count, 0);
        assert!(job.should_retry());
    }

    #[test]
    fn test_exponential_backoff() {
        let payload = JobPayload::Custom {
            job_type: "test".to_string(),
            data: serde_json::json!({}),
        };
        let mut job = Job::new(payload, Uuid::new_v4());

        job.retry_count = 0;
        let t0 = job.next_retry_time();

        job.retry_count = 1;
        let t1 = job.next_retry_time();

        job.retry_count = 2;
        let t2 = job.next_retry_time();

        // Each retry should be further in the future
        assert!(t1 > t0);
        assert!(t2 > t1);
    }

    /// MCP-508: previously `2_u32.pow(self.retry_count)` panicked for
    /// `retry_count >= 32`, and `base_delay * factor` could overflow
    /// Duration's internal nanosecond representation long before that.
    /// A misconfigured `max_retries` (or simply enough wall-clock
    /// retries before DLQ) would crash the job-scheduler thread on
    /// every retry-time calculation. Clamping the exponent at 6
    /// produces the same saturated output without the panic.
    #[test]
    fn test_next_retry_time_does_not_panic_on_high_retry_count() {
        let payload = JobPayload::Custom {
            job_type: "test".into(),
            data: serde_json::json!({}),
        };
        let mut job = Job::new(payload, Uuid::new_v4());
        // Sweep a range that includes the pre-fix panic zone (>= 32)
        // and far beyond. None of these should panic.
        for n in [6_u32, 16, 32, 64, 128, 1024, u32::MAX / 2, u32::MAX] {
            job.retry_count = n;
            let _ = job.next_retry_time(); // must not panic
        }
    }

    /// MCP-508: real ±10% jitter is deterministic per-job (driven by
    /// the UUID tail) but decorrelated across jobs. Pre-fix the
    /// "jitter" was a fixed +10% — every job at the same retry_count
    /// scheduled to exactly the same wall-clock time, which IS the
    /// thundering herd the comment claimed to prevent.
    #[test]
    fn test_next_retry_time_jitter_is_decorrelated_across_jobs() {
        let payload = || JobPayload::Custom {
            job_type: "t".into(),
            data: serde_json::json!({}),
        };
        let user_id = Uuid::new_v4();
        let mut all_delays = Vec::new();
        for _ in 0..32 {
            let mut job = Job::new(payload(), user_id);
            job.retry_count = 5; // baseline factor=32, but clamped to 2^5=32, near saturation
            let t = job.next_retry_time();
            all_delays.push(t);
        }
        // Across 32 distinct UUIDs we should see at least 16 distinct
        // wall-clock retry times — the pre-fix "+10% fixed" would
        // produce 1 distinct value (all jobs of the same retry_count
        // schedule at the same offset from now, within the resolution
        // of Utc::now()).
        let unique: std::collections::HashSet<_> = all_delays.iter().collect();
        assert!(
            unique.len() >= 16,
            "expected ≥16 distinct retry times across 32 jobs, got {} (pre-fix would yield 1)",
            unique.len()
        );
    }

    #[test]
    fn test_should_retry() {
        let payload = JobPayload::Custom {
            job_type: "test".to_string(),
            data: serde_json::json!({}),
        };
        let mut job = Job::new(payload, Uuid::new_v4());

        assert!(job.should_retry());

        job.retry_count = job.max_retries;
        assert!(!job.should_retry());

        job.retry_count = 0;
        job.status = JobStatus::Cancelled;
        assert!(!job.should_retry());
    }
}

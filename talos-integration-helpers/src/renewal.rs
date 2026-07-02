//! Generic watch-channel renewal scheduler.
//!
//! Captures the loop shape both reference integrations converged on
//! (`talos-gmail::scheduler` / `talos-google-calendar::scheduler`) so
//! integration 3 implements the trait instead of copy-adapting the
//! loop:
//!
//! * hourly tick (`tick_seconds`, default 3600 — Google watch
//!   channels expire in 7 days, so 24h-lookahead × hourly retries
//!   gives ≥24 attempts before expiry, and the 14-day
//!   `integration_state` TTL grace gives ~336 more after);
//! * shutdown-aware `tokio::select!` on a `watch::Receiver<bool>`
//!   (MCP-1156 — SIGTERM produces an operator-greppable clean
//!   shutdown event instead of a mid-iteration abort);
//! * per-row renew with **keep-row-on-failure** semantics: a failed
//!   renewal logs + audits and moves on; the row stays visible to the
//!   next cycle via the TTL grace. Never delete on single failures.
//!
//! # Why the logging/audit surface is trait hooks
//!
//! The two reference implementations diverge in every literal: log
//! message text ("gmail watch" vs "gcal watch channel"), structured
//! field names (`new_expiration_ms` vs `new_expiration`, gcal's extra
//! `calendar` field), audit `event_type`s and metadata shapes. Those
//! literals must stay byte-for-byte (operators grep for them; the
//! watch-channel summary service joins on the metadata keys), and
//! `tracing` targets/field names must be provider-side call sites to
//! keep the `talos_gmail::scheduler` / `talos_google_calendar::
//! scheduler` targets. So the kernel owns CONTROL FLOW ONLY and every
//! observable emission goes through the trait.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use uuid::Uuid;

/// Provider-specific surface of the renewal scheduler. See the
/// reference impls on `GmailWatchService` and `GoogleCalendarService`
/// for exactly what each hook should emit.
#[async_trait]
pub trait RenewableIntegration: Send + Sync + 'static {
    /// The `(user_id, row)` unit the scheduler iterates. Typically the
    /// integration's stored watch-row type.
    type Row: Send + Sync;
    /// What a successful renewal returns (the fresh row / channel).
    type Renewed: Send + Sync;

    /// Renewal cadence in seconds. Both reference integrations tick
    /// hourly; override only if the upstream's expiry model demands it.
    fn tick_seconds(&self) -> u64 {
        3600
    }

    /// List `(user_id, row)` pairs expiring inside the renewal window
    /// (24h lookahead in both reference impls, via the indexed
    /// `idx_ts_1` slot). Tenancy note: rows MUST be enumerated
    /// per-user through the user-scoped `integration_state` layer —
    /// never a cross-user scan.
    async fn list_needing_renewal(&self) -> anyhow::Result<Vec<(Uuid, Self::Row)>>;

    /// Renew one row (stop/replace upstream + rotate the stored row,
    /// preserving the sync cursor). MUST route through the
    /// integration's `create_fresh_*_locked` path, NOT the public
    /// fast-path create — see the "zero-channel bug" in
    /// `docs/integration-pattern.md`.
    async fn renew(&self, user_id: Uuid, row: &Self::Row) -> anyhow::Result<Self::Renewed>;

    /// Clean-shutdown audit line (`target: "talos_audit"`, an
    /// `event_kind = "<integ>_renewal_task_shutdown"` field).
    fn log_shutdown(&self);
    /// Start-of-cycle info line.
    fn log_cycle_start(&self);
    /// Debug line when nothing needs renewal this cycle.
    fn log_no_rows(&self);
    /// Info line with the count of rows needing renewal.
    fn log_row_count(&self, count: usize);
    /// Per-row "renewing…" info line.
    fn log_renewing(&self, user_id: Uuid, row: &Self::Row);
    /// Success: log + write the `<integ>_channel_renewed` audit row
    /// (use `audit::insert_channel_audit`).
    async fn on_renewed(&self, user_id: Uuid, old: &Self::Row, new: &Self::Renewed);
    /// Failure: log + write the `<integ>_channel_renewal_failed` audit
    /// row with `audit::truncate_and_redact_error(&error.to_string())`
    /// as the error_message (MCP-980/MCP-1181). Do NOT delete the row.
    async fn on_renewal_failed(&self, user_id: Uuid, old: &Self::Row, error: &anyhow::Error);
    /// Error line when the list query itself failed (cycle skipped).
    fn log_list_failed(&self, error: &anyhow::Error);
}

/// Run the renewal loop until the shutdown channel fires. Spawn once,
/// forever: `tokio::spawn(run_renewal_scheduler(service, shutdown_rx))`
/// (or wrap in an integration-named `pub async fn` as gmail/gcal do to
/// keep their `main.rs` wiring stable).
///
/// Note `tokio::time::interval`'s first tick completes immediately, so
/// the first cycle runs at startup — same as the pre-extraction loops.
pub async fn run_renewal_scheduler<P: RenewableIntegration>(
    provider: Arc<P>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = interval(Duration::from_secs(provider.tick_seconds()));

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                provider.log_shutdown();
                return;
            }
            _ = tick.tick() => {}
        }

        provider.log_cycle_start();

        match provider.list_needing_renewal().await {
            Ok(rows) => {
                if rows.is_empty() {
                    provider.log_no_rows();
                    continue;
                }
                provider.log_row_count(rows.len());

                for (user_id, row) in rows {
                    provider.log_renewing(user_id, &row);
                    match provider.renew(user_id, &row).await {
                        Ok(new) => provider.on_renewed(user_id, &row, &new).await,
                        Err(e) => provider.on_renewal_failed(user_id, &row, &e).await,
                    }
                }
            }
            Err(e) => provider.log_list_failed(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeIntegration {
        cycles: AtomicUsize,
        renewed: AtomicUsize,
        failed: AtomicUsize,
        shutdowns: AtomicUsize,
    }

    #[async_trait]
    impl RenewableIntegration for FakeIntegration {
        type Row = &'static str;
        type Renewed = ();

        fn tick_seconds(&self) -> u64 {
            1
        }
        async fn list_needing_renewal(&self) -> anyhow::Result<Vec<(Uuid, Self::Row)>> {
            self.cycles.fetch_add(1, Ordering::SeqCst);
            Ok(vec![
                (Uuid::new_v4(), "ok"),
                (Uuid::new_v4(), "boom"),
                (Uuid::new_v4(), "ok"),
            ])
        }
        async fn renew(&self, _user_id: Uuid, row: &Self::Row) -> anyhow::Result<()> {
            if *row == "boom" {
                anyhow::bail!("simulated renewal failure");
            }
            Ok(())
        }
        fn log_shutdown(&self) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
        fn log_cycle_start(&self) {}
        fn log_no_rows(&self) {}
        fn log_row_count(&self, _count: usize) {}
        fn log_renewing(&self, _user_id: Uuid, _row: &Self::Row) {}
        async fn on_renewed(&self, _user_id: Uuid, _old: &Self::Row, _new: &()) {
            self.renewed.fetch_add(1, Ordering::SeqCst);
        }
        async fn on_renewal_failed(
            &self,
            _user_id: Uuid,
            _old: &Self::Row,
            _error: &anyhow::Error,
        ) {
            self.failed.fetch_add(1, Ordering::SeqCst);
        }
        fn log_list_failed(&self, _error: &anyhow::Error) {}
    }

    /// One failing row must not abort the batch (keep-row-on-failure),
    /// and the shutdown channel must terminate the loop cleanly.
    #[tokio::test(start_paused = true)]
    async fn failure_continues_batch_and_shutdown_terminates() {
        let fake = Arc::new(FakeIntegration::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(run_renewal_scheduler(fake.clone(), shutdown_rx));

        // Paused clock: advance past the first (immediate) tick and let
        // the cycle run.
        tokio::time::sleep(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        assert!(
            fake.cycles.load(Ordering::SeqCst) >= 1,
            "at least one cycle ran"
        );
        let cycles = fake.cycles.load(Ordering::SeqCst);
        assert_eq!(fake.renewed.load(Ordering::SeqCst), 2 * cycles);
        assert_eq!(fake.failed.load(Ordering::SeqCst), cycles);
        assert_eq!(fake.shutdowns.load(Ordering::SeqCst), 1);
    }
}

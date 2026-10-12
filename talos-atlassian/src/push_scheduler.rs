//! The hourly task that keeps Jira webhooks alive.
//!
//! A dynamic webhook expires 30 days after it is created or refreshed. Each
//! hour this refreshes every registration within
//! [`REFRESH_WINDOW_DAYS`](crate::push::REFRESH_WINDOW_DAYS) of expiring, so a
//! registration gets about twenty days of hourly attempts before it is lost.
//!
//! The loop's control flow is `talos_integration_helpers::renewal`'s (tick,
//! shutdown, keep-the-row-on-failure). The durable record of each attempt —
//! the new expiry, or the failure on the registration's own row and in the
//! shared audit log — is written by
//! [`AtlassianIntegrationService::refresh_push_channel`], so a refresh made
//! from anywhere else is recorded the same way; the hooks here only log.
//!
//! **Every controller replica runs this.** That is safe without a lease: a
//! refresh REPLACES the webhook's expiry at Atlassian, it does not add a
//! webhook, so two replicas refreshing the same one in the same hour make one
//! call too many and change nothing. (Registration, which does add something,
//! takes a fleet lock in `crate::push`.)
//!
//! The same tick forgets handled delivery ids past their retention and drops
//! idle registration locks, so neither grows without bound.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use talos_integration_helpers::renewal::{run_renewal_scheduler, RenewableIntegration};
use talos_task_supervision::TaskExit;
use uuid::Uuid;

use crate::integration::AtlassianIntegrationService;
use crate::push::JiraPushRegistration;

struct JiraRefresher(Arc<AtlassianIntegrationService>);

#[async_trait]
impl RenewableIntegration for JiraRefresher {
    type Row = JiraPushRegistration;
    type Renewed = DateTime<Utc>;

    async fn list_needing_renewal(&self) -> anyhow::Result<Vec<(Uuid, JiraPushRegistration)>> {
        // Housekeeping first, and never a reason to skip the refreshes.
        match self.0.sweep_handled_deliveries().await {
            Ok(0) => {}
            Ok(removed) => tracing::debug!(removed, "forgot handled Jira delivery ids"),
            Err(e) => tracing::warn!(error = %e, "handled Jira delivery ids could not be swept"),
        }
        self.0.cleanup_push_locks();

        Ok(self
            .0
            .registrations_needing_refresh()
            .await?
            .into_iter()
            .map(|row| (row.user_id, row))
            .collect())
    }

    async fn renew(
        &self,
        user_id: Uuid,
        row: &JiraPushRegistration,
    ) -> anyhow::Result<DateTime<Utc>> {
        Ok(self.0.refresh_push_channel(user_id, row.id).await?)
    }

    fn log_shutdown(&self) {
        tracing::info!(
            target: "talos_audit",
            event_kind = "jira_webhook_refresh_task_shutdown",
            "Jira webhook refresh task shutting down (clean)"
        );
    }

    fn log_cycle_start(&self) {
        tracing::debug!("running the Jira webhook refresh task");
    }

    fn log_no_rows(&self) {
        tracing::debug!("no Jira webhook needs refreshing");
    }

    fn log_row_count(&self, count: usize) {
        tracing::info!(count, "Jira webhooks needing a refresh");
    }

    fn log_renewing(&self, user_id: Uuid, row: &JiraPushRegistration) {
        tracing::info!(registration = %row.id, %user_id, "refreshing a Jira webhook");
    }

    async fn on_renewed(&self, _user_id: Uuid, row: &JiraPushRegistration, new: &DateTime<Utc>) {
        tracing::info!(registration = %row.id, expires_at = %new, "Jira webhook refreshed");
    }

    async fn on_renewal_failed(
        &self,
        user_id: Uuid,
        row: &JiraPushRegistration,
        error: &anyhow::Error,
    ) {
        // The row and the audit log already hold this failure (see the module
        // docs). ERROR, because a webhook that cannot be refreshed stops
        // delivering when it expires and nothing else will say so.
        tracing::error!(
            target: "talos_audit",
            event_kind = "jira_webhook_refresh_failed",
            registration = %row.id,
            %user_id,
            expires_at = ?row.expires_at,
            error = %error,
            "Jira webhook refresh failed; it will be tried again next hour"
        );
    }

    fn log_list_failed(&self, error: &anyhow::Error) {
        tracing::error!(error = %error, "Jira webhooks needing a refresh could not be listed");
    }
}

/// Run the refresh loop until the shutdown channel fires.
pub async fn webhook_refresh_task(
    service: Arc<AtlassianIntegrationService>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> TaskExit {
    run_renewal_scheduler(Arc::new(JiraRefresher(service)), shutdown_rx).await
}

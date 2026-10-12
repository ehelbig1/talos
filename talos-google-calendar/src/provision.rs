//! Creating and stopping a watch channel at its owner's request, without
//! the settings page (2026-10-12).
//!
//! Until then a watch channel was made by a session-authenticated REST route
//! only, so an agent wiring a workflow to a calendar had to ask a person to
//! click. [`GcalPushProvisioner`] puts the same create behind the
//! push-channel set the MCP tools hold.
//!
//! What this adds to [`GoogleCalendarService::create_watch_channel`] is the
//! part a caller without a browser needs said to them: WHICH connection (the
//! caller's own, and the only one when none is named), a refusal in words the
//! caller can act on, and an existing channel returned as it is. The REST
//! create re-points an existing channel's MODULE at whatever it was handed
//! (nothing, from the settings page); this path returns the channel untouched.

use super::watch::{webhook_url_is_deliverable, GCAL_INTEGRATION_NAME};
use super::{GoogleCalendarService, WatchChannel};
use std::sync::Arc;
use talos_push_channel_inventory::{
    ProvisionRefusal, ProvisionRefusalKind, ProvisionedChannel, PushChannelProvisioner,
};
use uuid::Uuid;

/// The calendar a channel watches when the caller names none.
pub const DEFAULT_CALENDAR_ID: &str = "primary";

/// At most this many of the caller's own connection ids are named in a
/// "which one?" refusal.
const MAX_CONNECTIONS_NAMED: usize = 10;

/// Why a watch channel was not created or stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    /// The user has no active Google Calendar connection.
    NoConnection,
    /// The user has several and named none. Carries the caller's OWN
    /// connection ids (at most [`MAX_CONNECTIONS_NAMED`]).
    SeveralConnections(Vec<Uuid>),
    /// The connection named is not an active one of this user's ("not yours"
    /// is the same answer).
    ConnectionNotFound,
    /// The connection or calendar named is not an id.
    InvalidTarget(&'static str),
    /// This deployment has no public https address Google can deliver to.
    NotDeliverable,
    /// Google refused the connection's credentials.
    NeedsReconnect,
    /// No such channel for this user.
    ChannelNotFound,
    /// Google or the database did not answer. Nothing is known to have changed.
    Unavailable,
}

impl ProvisionError {
    #[must_use]
    pub fn refusal_kind(&self) -> ProvisionRefusalKind {
        match self {
            Self::NoConnection
            | Self::SeveralConnections(_)
            | Self::InvalidTarget(_)
            | Self::NotDeliverable
            | Self::NeedsReconnect => ProvisionRefusalKind::Refused,
            Self::ConnectionNotFound | Self::ChannelNotFound => ProvisionRefusalKind::NotFound,
            Self::Unavailable => ProvisionRefusalKind::Unavailable,
        }
    }

    /// What the caller is told. Names what to do; never an upstream error
    /// body, a token or a query.
    #[must_use]
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::NoConnection => {
                "You have no Google Calendar connection. Connect one in Settings, then try again."
                    .to_string()
            }
            Self::SeveralConnections(ids) => format!(
                "You have more than one Google Calendar connection; pass integration_id. Yours: {}.",
                ids.iter()
                    .map(Uuid::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::ConnectionNotFound => "No such Google Calendar connection.".to_string(),
            Self::InvalidTarget(what) => format!("Invalid '{what}'."),
            Self::NotDeliverable => {
                "This deployment has no public https address, so Google cannot deliver calendar \
                 changes to it. Its operator sets one (see get_public_url_status)."
                    .to_string()
            }
            Self::NeedsReconnect => {
                "Google refused this connection's credentials. Reconnect Google Calendar in \
                 Settings, then try again."
                    .to_string()
            }
            Self::ChannelNotFound => {
                "No such watch channel. List your channels again: a renewal gives a channel a \
                 new id."
                    .to_string()
            }
            Self::Unavailable => {
                "Google Calendar or the database did not answer, so nothing was changed. Try again."
                    .to_string()
            }
        }
    }
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.user_facing_message())
    }
}
impl std::error::Error for ProvisionError {}

impl From<ProvisionError> for ProvisionRefusal {
    fn from(e: ProvisionError) -> Self {
        Self::new(e.refusal_kind(), e.user_facing_message())
    }
}

/// A calendar id as Google writes one: `primary`, an address, or a group
/// calendar's `…@group.calendar.google.com` (holiday calendars carry a `#`).
/// It goes into a request path, so anything else is refused here.
fn calendar_id_is_plain(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 254
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-#".contains(&b))
}

/// The address Google delivers calendar changes to on this deployment. The
/// one home of it: the REST create and this path build the same URL.
#[must_use]
pub fn default_webhook_url() -> String {
    format!(
        "{}/api/google-calendar/webhook",
        talos_public_url::public_base_url_or(talos_config::get_base_url)
    )
}

impl GoogleCalendarService {
    /// Which of `user_id`'s active connections a channel is to be made on.
    async fn own_connection(
        &self,
        user_id: Uuid,
        named: Option<Uuid>,
    ) -> Result<Uuid, ProvisionError> {
        match named {
            // Owner-scoped: the read carries the user, so another user's
            // connection is "no such connection" and never an id to act on.
            Some(id) => match self.get_integration(user_id, id).await {
                Ok(Some(connection)) if connection.is_active => Ok(connection.id),
                Ok(_) => Err(ProvisionError::ConnectionNotFound),
                Err(e) => {
                    tracing::error!(%user_id, error = %e, "gcal provision: connection read failed");
                    Err(ProvisionError::Unavailable)
                }
            },
            None => match self.list_integrations(user_id).await {
                Ok(connections) => match connections.as_slice() {
                    [] => Err(ProvisionError::NoConnection),
                    [only] => Ok(only.id),
                    several => Err(ProvisionError::SeveralConnections(
                        several
                            .iter()
                            .take(MAX_CONNECTIONS_NAMED)
                            .map(|c| c.id)
                            .collect(),
                    )),
                },
                Err(e) => {
                    tracing::error!(%user_id, error = %e, "gcal provision: connection list failed");
                    Err(ProvisionError::Unavailable)
                }
            },
        }
    }

    /// Create the watch channel for one calendar of one of `user_id`'s own
    /// connections, delivering to this deployment's own address. `Ok((_,
    /// false))` when the channel already existed: it is returned as it is.
    pub async fn provision_watch_channel(
        &self,
        user_id: Uuid,
        connection: Option<Uuid>,
        calendar_id: Option<&str>,
    ) -> Result<(WatchChannel, bool), ProvisionError> {
        self.provision_watch_channel_at(user_id, connection, calendar_id, &default_webhook_url())
            .await
    }

    /// [`Self::provision_watch_channel`] with the delivery address given, so
    /// a test can drive it without this process's public-address settings.
    pub async fn provision_watch_channel_at(
        &self,
        user_id: Uuid,
        connection: Option<Uuid>,
        calendar_id: Option<&str>,
        webhook_url: &str,
    ) -> Result<(WatchChannel, bool), ProvisionError> {
        let calendar_id = calendar_id.unwrap_or(DEFAULT_CALENDAR_ID);
        if !calendar_id_is_plain(calendar_id) {
            return Err(ProvisionError::InvalidTarget("calendar_id"));
        }
        let integration_id = self.own_connection(user_id, connection).await?;

        // Already watched: hand it back untouched. `create_watch_channel`
        // would re-point its module binding at the `None` passed below.
        match self
            .find_channel_by_integration_and_calendar(user_id, integration_id, calendar_id)
            .await
        {
            Ok(Some(existing)) => return Ok((existing.to_watch_channel(user_id), false)),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(%user_id, error = %e, "gcal provision: channel lookup failed");
                return Err(ProvisionError::Unavailable);
            }
        }

        if !webhook_url_is_deliverable(webhook_url) {
            return Err(ProvisionError::NotDeliverable);
        }
        match self
            .create_watch_channel(integration_id, calendar_id, webhook_url, None)
            .await
        {
            Ok(channel) => Ok((channel, true)),
            Err(e) => {
                let detail = format!("{e:#}");
                tracing::warn!(
                    %user_id,
                    %integration_id,
                    error = %detail,
                    "gcal provision: the watch channel was not created"
                );
                if talos_integration_helpers::looks_like_oauth_failure(&detail) {
                    Err(ProvisionError::NeedsReconnect)
                } else {
                    Err(ProvisionError::Unavailable)
                }
            }
        }
    }

    /// Stop one of `user_id`'s own watch channels, at Google and here. A
    /// channel that is not there is said to be not there (the service's own
    /// stop is idempotent and would report success).
    pub async fn remove_watch_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<(), ProvisionError> {
        match self.find_channel_by_id_raw(user_id, channel_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(ProvisionError::ChannelNotFound),
            Err(e) => {
                tracing::error!(%user_id, error = %e, "gcal provision: channel read failed");
                return Err(ProvisionError::Unavailable);
            }
        }
        self.stop_watch_channel(user_id, channel_id)
            .await
            .map_err(|e| {
                tracing::warn!(%user_id, channel = %channel_id, error = %format!("{e:#}"), "gcal provision: the watch channel was not stopped");
                ProvisionError::Unavailable
            })
    }
}

/// Creates and stops Google Calendar watch channels through the push-channel
/// set. Holds the service (its credentials and HTTP client), which is why it
/// is not the pool-only inventory.
pub struct GcalPushProvisioner {
    service: Arc<GoogleCalendarService>,
    /// `None`: this deployment's own address ([`default_webhook_url`]).
    webhook_url: Option<String>,
}

impl GcalPushProvisioner {
    #[must_use]
    pub fn new(service: Arc<GoogleCalendarService>) -> Self {
        Self {
            service,
            webhook_url: None,
        }
    }

    /// Deliver to a fixed address instead of this process's public-address
    /// settings, which a test does not own.
    #[must_use]
    pub fn with_webhook_url_for_tests(mut self, webhook_url: &str) -> Self {
        self.webhook_url = Some(webhook_url.to_string());
        self
    }
}

#[async_trait::async_trait]
impl PushChannelProvisioner for GcalPushProvisioner {
    fn integration_name(&self) -> &'static str {
        GCAL_INTEGRATION_NAME
    }

    /// The connection's primary calendar.
    async fn create_channel(
        &self,
        user_id: Uuid,
        target: Option<&str>,
    ) -> Result<ProvisionedChannel, ProvisionRefusal> {
        self.create_channel_on(user_id, target, None).await
    }

    /// `target` is the connection's id; `resource` is the calendar id.
    async fn create_channel_on(
        &self,
        user_id: Uuid,
        target: Option<&str>,
        resource: Option<&str>,
    ) -> Result<ProvisionedChannel, ProvisionRefusal> {
        let connection = match target {
            None => None,
            Some(id) => Some(
                Uuid::parse_str(id).map_err(|_| ProvisionError::InvalidTarget("integration_id"))?,
            ),
        };
        let (channel, created) = match self.webhook_url.as_deref() {
            None => {
                self.service
                    .provision_watch_channel(user_id, connection, resource)
                    .await?
            }
            Some(webhook_url) => {
                self.service
                    .provision_watch_channel_at(user_id, connection, resource, webhook_url)
                    .await?
            }
        };
        Ok(ProvisionedChannel {
            integration: GCAL_INTEGRATION_NAME,
            channel_id: channel.id,
            display_name: channel.calendar_id,
            expires_at: Some(channel.expiration),
            created,
        })
    }

    async fn delete_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<(), ProvisionRefusal> {
        Ok(self
            .service
            .remove_watch_channel(user_id, channel_id)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_calendar_id_is_one_google_writes() {
        for id in [
            "primary",
            "someone@example.com",
            "abc123def456@group.calendar.google.com",
            "en.usa#holiday@group.v.calendar.google.com",
        ] {
            assert!(calendar_id_is_plain(id), "{id}");
        }
        for id in [
            "",
            "primary/events/watch",
            "a b",
            "primary?alt=json",
            "../x",
        ] {
            assert!(!calendar_id_is_plain(id), "{id}");
        }
        assert!(!calendar_id_is_plain(&"a".repeat(255)));
    }

    /// Each refusal says what to do and has the kind the tool maps to a
    /// protocol code; none says whose a connection is.
    #[test]
    fn a_refusal_names_what_to_do_and_not_whose_anything_is() {
        use ProvisionRefusalKind as K;
        let mine = Uuid::new_v4();
        for (e, kind, says) in [
            (ProvisionError::NoConnection, K::Refused, "Connect one"),
            (
                ProvisionError::SeveralConnections(vec![mine]),
                K::Refused,
                "pass integration_id",
            ),
            (ProvisionError::ConnectionNotFound, K::NotFound, "No such"),
            (
                ProvisionError::InvalidTarget("calendar_id"),
                K::Refused,
                "'calendar_id'",
            ),
            (ProvisionError::NotDeliverable, K::Refused, "public https"),
            (ProvisionError::NeedsReconnect, K::Refused, "Reconnect"),
            (ProvisionError::ChannelNotFound, K::NotFound, "No such"),
            (ProvisionError::Unavailable, K::Unavailable, "Try again"),
        ] {
            let refusal = ProvisionRefusal::from(e.clone());
            assert_eq!(refusal.kind, kind, "{e:?}");
            assert!(refusal.message.contains(says), "{}", refusal.message);
            let m = refusal.message.to_lowercase();
            assert!(
                !m.contains("another user") && !m.contains("permission") && !m.contains("owner"),
                "{m}"
            );
        }
        // "Which one?" names the caller's own connections.
        assert!(ProvisionError::SeveralConnections(vec![mine])
            .user_facing_message()
            .contains(&mine.to_string()));
    }
}

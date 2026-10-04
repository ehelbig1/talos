//! A user's connections, rendered with the `vault://` reference a workflow
//! node uses for each one's credential.
//!
//! Two readers, one rendering: the `list_connections` tool and the
//! `connections` system node. Both answer "what has this user connected, and
//! where is each credential", and an answer that differed between them would
//! send an author to a reference the engine does not agree exists.

use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::provider_config::{IntegrationProviderConfig, PLAID_PROVIDER_ID, PROVIDERS};
use crate::store::{list_user_connections, ConnectionRow, MAX_LISTED_CONNECTIONS};

/// Where one connection's credential is stored, from the builders that store
/// it: `talos_plaid::link::access_token_path` for a bank item,
/// `talos_oauth::access_token_vault_path` under the provider namespace the
/// row's tier selects (`revoke_provider_for`) for everything else.
///
/// # Errors
/// When the row cannot name a credential: no provider key, a tier this build
/// does not know, or an item id the path builder refuses.
pub fn connection_token_path(
    provider: &IntegrationProviderConfig,
    user_id: Uuid,
    provider_key: Option<&str>,
    tier: Option<&str>,
) -> Result<String, String> {
    let key = provider_key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| "this connection records no credential key".to_string())?;
    if provider.id == PLAID_PROVIDER_ID {
        return talos_plaid::link::access_token_path(key);
    }
    let namespace = crate::provider_config::revoke_provider_for(provider, tier)
        .ok_or_else(|| "this connection's access tier is not recognised".to_string())?;
    Ok(talos_oauth::credentials::access_token_vault_path(
        &namespace, user_id, key,
    ))
}

/// One connection as `list_connections` renders it. `stored` is the set of
/// paths found in the vault, or `None` when that read failed — rendered as
/// `null`, never as `false`.
pub fn rendered_connection(
    row: &ConnectionRow,
    user_id: Uuid,
    stored: Option<&std::collections::HashSet<String>>,
) -> serde_json::Value {
    let provider = PROVIDERS.iter().find(|p| p.id == row.provider_id);
    let mut out = serde_json::json!({
        "service": row.provider_id,
        "name": provider.map_or(row.provider_id.as_str(), |p| p.display_name),
        "account": row.identifier,
        "connected_at": row.created_at.to_rfc3339(),
    });
    let path = provider
        .ok_or_else(|| "this service is not in the provider registry".to_string())
        .and_then(|p| {
            connection_token_path(p, user_id, row.provider_key.as_deref(), row.tier.as_deref())
        });
    let path = match path {
        Ok(path) => path,
        Err(why) => {
            out["vault_reference"] = Value::Null;
            out["note"] = Value::String(format!("No reference: {why}."));
            return out;
        }
    };
    out["stored"] = stored.map_or(Value::Null, |s| Value::Bool(s.contains(&path)));
    // Host-reserved credentials (the full Google Cloud consent) are used by
    // the controller only; the worker refuses them to every module.
    if talos_workflow_job_protocol::is_controller_internal_vault_path(&path) {
        out["module_readable"] = Value::Bool(false);
        out["vault_reference"] = Value::Null;
        out["note"] = Value::String(
            "This credential is used by the controller only; no module can read it.".to_string(),
        );
        return out;
    }
    out["module_readable"] = Value::Bool(true);
    out["vault_reference"] = Value::String(format!("vault://{path}"));
    let mut grant = vec![path];
    if row.provider_id == PLAID_PROVIDER_ID {
        // A Plaid request carries the application's own two credentials in
        // its JSON body beside the item's token.
        let app = [
            talos_plaid::link::PLAID_CLIENT_ID_PATH,
            talos_plaid::link::PLAID_SECRET_PATH,
        ];
        out["also_required"] = serde_json::json!(app.map(|p| format!("vault://{p}")));
        grant.extend(app.map(str::to_string));
    }
    out["allowed_secrets"] = serde_json::json!(grant);
    out
}

/// A user's connections as both readers present them.
#[derive(Debug, Clone)]
pub struct ListedConnections {
    /// One entry per connection, in `(service, connected_at)` order.
    pub connections: Vec<Value>,
    /// The listing reached [`MAX_LISTED_CONNECTIONS`]; there may be more.
    pub truncated: bool,
    /// Whether the vault could be asked which credentials are stored. When
    /// it could not, every entry's `stored` is `null`, never `false`.
    pub stored_checked: bool,
}

/// List `user_id`'s connections, rendered. `provider` keeps one service's
/// (`Some("plaid")`); `None` keeps all.
///
/// Tenancy: every branch of the listing statement filters on `user_id`, and
/// the vault existence read is scoped to the same user.
///
/// # Errors
/// When the connection rows cannot be read. A failed vault existence read is
/// not an error: the entries are returned with `stored: null`.
pub async fn list_rendered(
    pool: &PgPool,
    secrets: &talos_secrets_manager::SecretsManager,
    user_id: Uuid,
    provider: Option<&str>,
) -> Result<ListedConnections> {
    let all = list_user_connections(pool, user_id).await?;
    let truncated = i64::try_from(all.len()).is_ok_and(|n| n >= MAX_LISTED_CONNECTIONS);
    let rows: Vec<ConnectionRow> = all
        .into_iter()
        .filter(|row| provider.is_none_or(|p| row.provider_id == p))
        .collect();
    // One batched existence read for every path. A failure leaves `stored`
    // unknown (null) on every row rather than claiming nothing is stored.
    let paths: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let provider = PROVIDERS.iter().find(|p| p.id == row.provider_id)?;
            connection_token_path(
                provider,
                user_id,
                row.provider_key.as_deref(),
                row.tier.as_deref(),
            )
            .ok()
        })
        .collect();
    let stored = match secrets.existing_secret_key_paths(&paths, user_id).await {
        Ok(found) => Some(found),
        Err(e) => {
            // The paths name accounts; the error is logged without them.
            tracing::warn!(error = %e, "connections: the vault existence read failed");
            None
        }
    };
    Ok(ListedConnections {
        connections: rows
            .iter()
            .map(|row| rendered_connection(row, user_id, stored.as_ref()))
            .collect(),
        truncated,
        stored_checked: stored.is_some(),
    })
}

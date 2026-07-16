//! DB reads/writes over the per-provider integration tables, driven by the
//! static `PROVIDERS` registry. Owns the SQL that the GraphQL
//! `serviceIntegrations` / `disconnectServiceIntegration` resolvers used to
//! inline (check-50 extraction).

use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

use crate::provider_config::{IntegrationProviderConfig, PROVIDERS};

/// One connected-integration row from the cross-provider UNION listing.
/// `service_tag` is the provider's `graphql_enum` literal ("GMAIL", …),
/// written into each UNION branch as a constant column.
#[derive(Debug, sqlx::FromRow)]
pub struct ServiceIntegrationRow {
    pub id: Uuid,
    pub identifier: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub service_tag: String,
}

/// List every connected integration for a user across ALL registered
/// providers in ONE round-trip (2026-05-28 audit Perf#2 — the pre-fix
/// per-provider loop issued N serial SELECTs).
///
/// The UNION ALL branches are built from the static `PROVIDERS` registry:
/// table names, identifier columns, join clauses, and the `graphql_enum`
/// tag are compile-time constants, NOT user input — only `user_id` is
/// bound ($1). Branch ordering matches `PROVIDERS`, so the result Vec
/// retains the same ordering as the legacy sequential loop.
pub async fn list_user_service_integrations(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ServiceIntegrationRow>> {
    let union_branches: Vec<String> = PROVIDERS
        .iter()
        .map(|provider| {
            let table_alias = if provider.account_identifier_join.is_some() {
                "g"
            } else {
                "t"
            };
            let join_clause = provider.account_identifier_join.unwrap_or("");
            format!(
                "SELECT {alias}.id, {ident} as identifier, {alias}.created_at, '{enum_tag}' as service_tag \
                 FROM {table} {alias} {join} \
                 WHERE {alias}.user_id = $1 {extra}",
                alias = table_alias,
                ident = provider.account_identifier_column,
                table = provider.db_table,
                join = join_clause,
                extra = provider.extra_where,
                enum_tag = provider.graphql_enum,
            )
        })
        .collect();

    let sql = union_branches.join(" UNION ALL ");
    sqlx::query_as::<_, ServiceIntegrationRow>(&sql)
        .bind(user_id)
        .fetch_all(pool)
        .await
        .context("Failed to list user service integrations")
}

/// Outcome of a disconnect: whether a row was affected, plus the vault
/// provider_key (+ tier discriminator) recovered from that row via
/// `RETURNING` so the caller can revoke the OAuth token and clean up the
/// vault — not merely hide the integration.
#[derive(Debug, Default)]
pub struct DisconnectOutcome {
    /// 1 if a matching, owned row was found and disconnected; 0 otherwise.
    pub rows_affected: u64,
    /// The row's vault provider_key (from `provider_key_column`). `None` when
    /// no row matched or the column was NULL.
    pub provider_key: Option<String>,
    /// The row's tier discriminator (from `tier_column`), for providers whose
    /// OAuth provider string is per-tier (GCP). `None` for single-namespace
    /// providers or when no row matched.
    pub tier: Option<String>,
}

/// Disconnect one integration row for a user. Soft-delete providers get
/// `is_active = false`; the rest are hard-deleted. The table name and the
/// `RETURNING` column names come from the static registry entry (compile-time
/// constants, not user input); only `id` and `user_id` are bound.
///
/// `RETURNING`s the row's provider_key (+ tier) so the caller can revoke the
/// token at the provider and delete it from the vault. For a hard-delete this
/// is the last chance to read the key — the row is gone after this call.
pub async fn disconnect_user_integration(
    pool: &PgPool,
    provider: &IntegrationProviderConfig,
    id: Uuid,
    user_id: Uuid,
) -> Result<DisconnectOutcome> {
    // `::text` normalises Uuid key columns (oauth_account_id, provider_key) and
    // text ones (email_address, team_id, cloud_id) to a single String shape.
    // `tier_column` is optional → project a NULL literal when absent so the row
    // shape is always (provider_key, tier).
    let tier_expr = provider.tier_column.unwrap_or("NULL");
    let returning = format!(
        "RETURNING {}::text AS provider_key, {}::text AS tier",
        provider.provider_key_column, tier_expr
    );
    let sql = if provider.disconnect_is_soft_delete {
        format!(
            "UPDATE {} SET is_active = false, updated_at = now() \
             WHERE id = $1 AND user_id = $2 {}",
            provider.db_table, returning
        )
    } else {
        format!(
            "DELETE FROM {} WHERE id = $1 AND user_id = $2 {}",
            provider.db_table, returning
        )
    };

    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(&sql)
        .bind(id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .context("Failed to disconnect integration")?;

    Ok(match row {
        Some((provider_key, tier)) => DisconnectOutcome {
            rows_affected: 1,
            provider_key,
            tier,
        },
        None => DisconnectOutcome::default(),
    })
}

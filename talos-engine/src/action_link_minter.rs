//! Postgres impl of [`talos_workflow_engine_core::ActionLinkMinter`] — the
//! mint port behind the `action_links` system node.
//!
//! Thin adapter over
//! [`talos_execution_repository::action_links`] (all SQL stays in the domain
//! crate). Tenancy: every row is written for the `user_id` the engine
//! passes in, which is the execution's resolved identity, and the
//! repository's ownership JOIN refuses any workflow that is not that
//! user's.
//!
//! SECURITY: the minted URLs are capability secrets. They are returned to
//! the engine (which writes them into the node's output — that is the
//! node's purpose) and are never logged here.

use async_trait::async_trait;
use sqlx::PgPool;
use talos_execution_repository::action_links::{action_url, ActionLinkRequest};
use talos_execution_repository::ExecutionRepository;
use talos_workflow_engine_core::action_links::ActionLinkSpec;
use uuid::Uuid;

/// The reason every request carries in the node's report when the
/// operator's own address for links ([`talos_config::ACTION_LINKS_BASE_URL_ENV`])
/// is set to something unusable.
pub const LINK_ADDRESS_MISCONFIGURED: &str = "link_address_misconfigured";

/// The address this mint's links carry.
///
/// `own` is the operator's setting as [`talos_config::action_links_base_url`]
/// read it; `public` is the deployment's public address, asked for only when
/// there is no setting. The one rule: a setting that is present but unusable
/// is an error. It is NEVER answered with the public address, because the
/// setting exists to keep links off that address.
fn link_base(
    own: Result<Option<String>, talos_config::ActionLinksBaseError>,
    public: impl FnOnce() -> String,
) -> Result<String, talos_config::ActionLinksBaseError> {
    Ok(own?.unwrap_or_else(public))
}

pub struct PostgresActionLinkMinter {
    repo: ExecutionRepository,
}

impl PostgresActionLinkMinter {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: ExecutionRepository::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::ActionLinkMinter for PostgresActionLinkMinter {
    async fn mint(
        &self,
        user_id: Uuid,
        source_execution_id: Uuid,
        source_node: &str,
        ttl_hours: Option<u32>,
        specs: &[ActionLinkSpec],
    ) -> Result<Vec<Result<String, String>>, talos_workflow_engine_core::BoxError> {
        self.mint_with_setting(
            talos_config::action_links_base_url(),
            user_id,
            source_execution_id,
            source_node,
            ttl_hours,
            specs,
        )
        .await
    }
}

impl PostgresActionLinkMinter {
    /// The mint, with the operator's address setting passed in. `mint` reads
    /// it from the environment and calls this; a test passes it, because the
    /// environment belongs to the whole test process.
    ///
    /// # Errors
    /// When the token rows cannot be written.
    pub async fn mint_with_setting(
        &self,
        setting: Result<Option<String>, talos_config::ActionLinksBaseError>,
        user_id: Uuid,
        source_execution_id: Uuid,
        source_node: &str,
        ttl_hours: Option<u32>,
        specs: &[ActionLinkSpec],
    ) -> Result<Vec<Result<String, String>>, talos_workflow_engine_core::BoxError> {
        // Which address the links carry is decided BEFORE anything is
        // written: a deployment whose own address for links is misconfigured
        // mints no token at all.
        let base_url = match link_base(setting, || {
            // Resolved per call, like the approval links: a public URL that
            // changed since the last message must not be baked into this one.
            talos_public_url::public_base_url_or(talos_config::get_base_url)
        }) {
            Ok(base) => base,
            Err(why) => {
                // The value is not logged; the reason says what is wrong with it.
                tracing::error!(
                    variable = talos_config::ACTION_LINKS_BASE_URL_ENV,
                    reason = why.as_str(),
                    requested = specs.len(),
                    "action links: the configured address for links is not usable; no link minted"
                );
                return Ok(specs
                    .iter()
                    .map(|_| Err(LINK_ADDRESS_MISCONFIGURED.to_string()))
                    .collect());
            }
        };
        let requests: Vec<ActionLinkRequest> = specs
            .iter()
            .map(|spec| ActionLinkRequest {
                workflow_id: spec.workflow_id,
                label: spec.label.clone(),
                payload: spec.payload.clone(),
            })
            .collect();
        let minted = self
            .repo
            .mint_action_tokens(
                user_id,
                Some(source_execution_id),
                Some(source_node),
                ttl_hours.map(i64::from),
                &requests,
            )
            .await?;
        Ok(minted
            .into_iter()
            .map(|outcome| match outcome {
                Ok(raw_token) => Ok(action_url(&base_url, &raw_token)),
                Err(refusal) => Err(refusal.as_str().to_string()),
            })
            .collect())
    }
}

#[cfg(test)]
mod link_base_tests {
    use super::link_base;
    use talos_config::ActionLinksBaseError;

    const PUBLIC: &str = "https://public-tunnel.example";

    #[test]
    fn with_no_setting_links_go_out_on_the_public_address_as_before() {
        assert_eq!(
            link_base(Ok(None), || PUBLIC.to_string()),
            Ok(PUBLIC.to_string())
        );
    }

    #[test]
    fn the_operators_address_wins_and_the_public_one_is_not_even_asked_for() {
        let base = link_base(Ok(Some("https://links.private.example".into())), || {
            panic!("the public address was resolved although the operator set their own")
        });
        assert_eq!(base, Ok("https://links.private.example".to_string()));
    }

    /// The setting exists to keep a link off the public address. A value
    /// that cannot be used must stop the mint, not fall back to it.
    #[test]
    fn an_unusable_setting_is_an_error_and_never_the_public_address() {
        for why in [
            ActionLinksBaseError::NotHttps,
            ActionLinksBaseError::NotAnOrigin,
        ] {
            let base = link_base(Err(why), || {
                panic!("an unusable setting fell back to the public address")
            });
            assert_eq!(base, Err(why));
        }
    }
}

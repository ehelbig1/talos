//! A module run outside a workflow mints what a dispatch would (2026-10-13).
//!
//! `test_module`, `run_sandbox` and a module replay asked the vault directly
//! for a module's secrets. Nothing is stored at a path whose value is MINTED
//! (an impersonated Google Cloud service account, a GitHub App installation),
//! so a module that authenticates with one failed on a missing secret and
//! could not be rehearsed or replayed on its own.
//!
//! They now resolve through the dispatch's own resolver. What is pinned here,
//! with a real `SecretsManager` and providers that record what they were
//! asked:
//!
//! * a mint is made for the CALLER'S user id and no other;
//! * a mint is made only under a grant: a path that is merely wanted (a
//!   `vault://` reference in a test's config) reaches no provider;
//! * with no user identity nothing is minted;
//! * a refused mint is an absent path, not an error.
//!
//! The providers are process-wide and set once, so this file is one test
//! function: its own process, its own providers.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use talos_oauth::resolver::resolve_for_standalone_run;
use talos_workflow_engine_core::{
    BoxError, GcpImpersonationTokenProvider, GithubInstallationTokenProvider, MintReadiness,
};
use uuid::Uuid;

/// What a provider was asked for: (what, connection, user).
type Asked = Arc<Mutex<Vec<(String, Option<Uuid>, Uuid)>>>;

/// Mints for one user and refuses everyone else, as the real providers do
/// for a user with no connection.
struct RecordingGcp {
    connected: Uuid,
    asked: Asked,
}

#[async_trait]
impl GcpImpersonationTokenProvider for RecordingGcp {
    async fn impersonated_token(
        &self,
        service_account_email: &str,
        connection: Option<Uuid>,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError> {
        self.asked
            .lock()
            .unwrap()
            .push((service_account_email.to_string(), connection, user_id));
        Ok((user_id == self.connected).then(|| format!("minted:{service_account_email}")))
    }

    async fn mint_readiness(
        &self,
        _connection: Option<Uuid>,
        user_id: Uuid,
    ) -> Result<MintReadiness, BoxError> {
        Ok(if user_id == self.connected {
            MintReadiness::Ready
        } else {
            MintReadiness::NoConnection
        })
    }
}

struct RecordingGithub {
    connected: Uuid,
    asked: Asked,
}

#[async_trait]
impl GithubInstallationTokenProvider for RecordingGithub {
    async fn installation_token(
        &self,
        owner: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, BoxError> {
        self.asked
            .lock()
            .unwrap()
            .push((owner.to_string(), None, user_id));
        Ok((user_id == self.connected).then(|| format!("minted:{owner}")))
    }

    async fn mint_readiness(&self, _owner: &str, user_id: Uuid) -> Result<MintReadiness, BoxError> {
        Ok(if user_id == self.connected {
            MintReadiness::Ready
        } else {
            MintReadiness::NoConnection
        })
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_string()).collect()
}

#[tokio::test]
async fn a_standalone_run_mints_for_its_caller_only_and_only_under_a_grant() {
    let (pool, _db) = common::isolated_db_pool().await;
    let state = mcp_common::mcp_state(pool).await;
    let sm = state.secrets_manager.clone();

    let (connected, stranger) = (Uuid::from_u128(0xA11CE), Uuid::from_u128(0xB0B));
    let asked: Asked = Arc::default();
    talos_oauth::resolver::set_gcp_impersonation_token_provider(Arc::new(RecordingGcp {
        connected,
        asked: asked.clone(),
    }));
    talos_oauth::resolver::set_github_installation_token_provider(Arc::new(RecordingGithub {
        connected,
        asked: asked.clone(),
    }));
    let take_asked = || std::mem::take(&mut *asked.lock().unwrap());

    const SA: &str = "runner@example-project.iam.gserviceaccount.com";
    let key = Uuid::from_u128(0x0b7b_0f0e_4c1d_4a57_9d2e_3f6a_1c2b_9e10);
    let named = talos_workflow_job_protocol::gcp_impersonated_path(SA, Some(key));
    let github = "github_app:example-org".to_string();
    let wanted = vec![named.clone(), github.clone()];
    let grant = s(&["gcp/impersonated/*", "github_app:example-org"]);

    // Granted, and the caller has a connection: both are minted, for the
    // caller, from the connection the path names.
    let resolved = resolve_for_standalone_run(sm.clone(), &grant, &wanted, Some(connected))
        .await
        .expect("resolve");
    assert_eq!(
        resolved.get(&named).map(String::as_str),
        Some("minted:runner@example-project.iam.gserviceaccount.com")
    );
    assert_eq!(
        resolved.get(&github).map(String::as_str),
        Some("minted:example-org")
    );
    let mut seen = take_asked();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            ("example-org".to_string(), None, connected),
            (SA.to_string(), Some(key), connected),
        ],
        "each provider was asked once, for the caller"
    );

    // Wanted but NOT granted (a reference typed into a test's config): no
    // provider is asked, and nothing comes back.
    let resolved = resolve_for_standalone_run(sm.clone(), &[], &wanted, Some(connected))
        .await
        .expect("resolve");
    assert!(resolved.is_empty(), "a mint was made with no grant");
    assert!(
        take_asked().is_empty(),
        "a provider was asked with no grant"
    );

    // A grant that covers one of the two reaches that one only.
    let resolved = resolve_for_standalone_run(
        sm.clone(),
        &s(&["github_app:example-org"]),
        &wanted,
        Some(connected),
    )
    .await
    .expect("resolve");
    assert_eq!(resolved.len(), 1);
    assert!(resolved.contains_key(&github));
    assert_eq!(
        take_asked(),
        vec![("example-org".to_string(), None, connected)]
    );

    // Another user, with the same grant: the providers are asked about THAT
    // user, refuse, and the paths are simply absent. Not an error, and not
    // the connected user's token.
    let resolved = resolve_for_standalone_run(sm.clone(), &grant, &wanted, Some(stranger))
        .await
        .expect("a refused mint is not an error");
    assert!(resolved.is_empty(), "another user's token was handed out");
    assert!(
        take_asked().iter().all(|(_, _, user)| *user == stranger),
        "a provider was asked about a user other than the caller"
    );

    // No user identity: nothing is minted, and no provider is asked.
    let resolved = resolve_for_standalone_run(sm, &grant, &wanted, None)
        .await
        .expect("resolve");
    assert!(resolved.is_empty());
    assert!(take_asked().is_empty(), "a mint was attempted with no user");
}

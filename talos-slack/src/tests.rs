use super::*;
use serde_json::json;
use crate::integration::SlackIntegrationService;

#[test]
fn test_generate_manifest() {
    let client = SlackApiClient::new();
    let manifest = client.generate_manifest(
        "Test App",
        "Test Description",
        "https://example.com/webhook",
        &["message.channels".to_string(), "reaction_added".to_string()],
    );

    assert_eq!(manifest["display_information"]["name"], "Test App");
    let scopes = manifest["oauth_config"]["scopes"]["bot"].as_array().unwrap();
    let scopes_str: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();

    assert!(scopes_str.contains(&"chat:write"));
    assert!(scopes_str.contains(&"reactions:read"));
    assert_eq!(manifest["settings"]["event_subscriptions"]["request_url"], "https://example.com/webhook");
}

#[test]
fn test_generate_manifest_with_files() {
    let client = SlackApiClient::new();
    let manifest = client.generate_manifest(
        "File App",
        "Desc",
        "https://example.com/webhook",
        &["file_created".to_string()],
    );

    let scopes = manifest["oauth_config"]["scopes"]["bot"].as_array().unwrap();
    let scopes_str: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();

    assert!(scopes_str.contains(&"files:read"));
}

#[tokio::test]
async fn test_resolve_user_mentions_no_mentions() {
    let client = SlackApiClient::new();
    let text = "Hello world";
    let resolved = client.resolve_user_mentions("token", text).await;
    assert_eq!(resolved, "Hello world");
}

#[tokio::test]
async fn test_slack_integration_service_new_validation() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();

    // Requires OAUTH_STATE_SECRET or JWT_SECRET
    std::env::set_var("OAUTH_STATE_SECRET", "test-secret-key-for-hmac-sha256-validation");
    let service = SlackIntegrationService::new(pool);
    assert!(service.is_ok());
}

#[tokio::test]
async fn test_slack_integration_service_is_configured() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();

    std::env::set_var("OAUTH_STATE_SECRET", "test-secret");

    // Set variables before creating service
    std::env::set_var("SLACK_CLIENT_ID", "id");
    std::env::set_var("SLACK_CLIENT_SECRET", "secret");
    std::env::set_var("SLACK_REDIRECT_URI", "https://redirect");

    let service = SlackIntegrationService::new(pool).unwrap();
    assert!(service.is_configured());

    std::env::remove_var("SLACK_CLIENT_ID");
    std::env::remove_var("SLACK_CLIENT_SECRET");
    std::env::remove_var("SLACK_REDIRECT_URI");
}

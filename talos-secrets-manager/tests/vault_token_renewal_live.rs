// ci-ungated: needs a live, unsealed Vault with the transit engine and a token
// allowed to write policies and mint orphan tokens (the dev stack's
// `VAULT_TOKEN=dev-root`). CI runs no Vault, and a test that early-returns
// without one would be a green tick over zero assertions — so it is excluded
// honestly instead. Run it by hand:
//   TALOS_VAULT_LIVE_TEST=1 VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root \
//     cargo test -p talos-secrets-manager --test vault_token_renewal_live -- --nocapture

//! The renewal loop against a REAL Vault, not the mock: the property it exists
//! for is a fact about Vault's behaviour, and the mock can only restate what
//! the author believed. Two identical 4-second periodic tokens under a
//! transit-only policy; the loop renews one, nothing touches the other, and
//! both are exercised through `wrap_dek` the whole time. After 10 seconds the
//! renewed one still wraps and the control is refused — which is the defect
//! (use does not renew) and its fix in one run.

use std::time::Duration;

use serde_json::{json, Value};
use talos_secrets_manager::kek_provider::KekProvider;
use talos_secrets_manager::vault_kek_provider::{RenewalSchedule, VaultTransitProvider};

const POLICY: &str = "talos-token-renewal-live-test";

async fn admin(
    client: &reqwest::Client,
    addr: &str,
    root: &str,
    method: reqwest::Method,
    path: &str,
    body: Value,
) -> Value {
    let resp = client
        .request(method, format!("{addr}/v1/{path}"))
        .header("X-Vault-Token", root)
        .json(&body)
        .send()
        .await
        .expect("vault reachable");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "{path}: HTTP {status}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

#[tokio::test]
async fn renewal_keeps_a_periodic_token_alive_that_use_alone_lets_expire() {
    if std::env::var("TALOS_VAULT_LIVE_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set TALOS_VAULT_LIVE_TEST=1 with a live dev Vault");
        return;
    }
    let addr = std::env::var("VAULT_ADDR").expect("VAULT_ADDR");
    let root = std::env::var("VAULT_TOKEN").expect("VAULT_TOKEN");
    let http = reqwest::Client::new();

    admin(
        &http,
        &addr,
        &root,
        reqwest::Method::PUT,
        &format!("sys/policies/acl/{POLICY}"),
        json!({"policy": "path \"transit/encrypt/talos-kek\" { capabilities = [\"update\"] }\npath \"transit/decrypt/talos-kek\" { capabilities = [\"update\"] }"}),
    )
    .await;
    let mint = || async {
        let v = admin(
            &http,
            &addr,
            &root,
            reqwest::Method::POST,
            "auth/token/create-orphan",
            json!({"policies": [POLICY], "period": "4s", "display_name": "renewal-live-test"}),
        )
        .await;
        v["auth"]["client_token"]
            .as_str()
            .expect("token")
            .to_string()
    };
    let renewed_token = mint().await;
    let control_token = mint().await;

    let renewed =
        VaultTransitProvider::new(&addr, renewed_token.clone(), "transit", "talos-kek").unwrap();
    let control =
        VaultTransitProvider::new(&addr, control_token.clone(), "transit", "talos-kek").unwrap();
    let metrics = talos_metrics::TalosMetrics::new().unwrap();

    let schedule = RenewalSchedule {
        min: Duration::from_millis(200),
        max: Duration::from_secs(1),
        retry_max: Duration::from_millis(500),
    };
    // Both tokens are USED every 500 ms for 10 s; only one is renewed.
    let usage = async {
        let dek = [7u8; 32];
        let mut control_refused_at = None;
        for i in 0..20 {
            renewed
                .wrap_dek(&dek)
                .await
                .expect("the renewed token must keep working");
            if control.wrap_dek(&dek).await.is_err() && control_refused_at.is_none() {
                control_refused_at = Some(i);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        control_refused_at
    };
    let control_refused_at = tokio::select! {
        r = usage => r,
        stop = renewed.run_token_renewal(schedule, Some(&metrics)) => {
            panic!("a periodic token's renewal loop must not return: {stop:?}")
        }
    };

    for t in [&renewed_token, &control_token] {
        let _ = http
            .post(format!("{addr}/v1/auth/token/revoke"))
            .header("X-Vault-Token", &root)
            .json(&json!({"token": t}))
            .send()
            .await;
    }
    let _ = http
        .delete(format!("{addr}/v1/sys/policies/acl/{POLICY}"))
        .header("X-Vault-Token", &root)
        .send()
        .await;

    let refused = control_refused_at.expect("the unrenewed control token must expire despite use");
    assert!(
        refused >= 6,
        "control expired too early to be the TTL: iteration {refused}"
    );
    let renewals = metrics
        .vault_token_renewals_total
        .with_label_values(&["renewed"])
        .get();
    assert!(renewals >= 10.0, "renewed {renewals} times in 10 s");
    eprintln!("control refused at iteration {refused}; renewed {renewals} times");
}

//! Token-lifetime classification, the production boot refusal, and the
//! renewal loop — the pure halves by table, the loop and the health check
//! against a mock Vault that answers the SAME shapes the dev Vault 1.18 was
//! measured returning on 2026-09-14 (`period` absent on a non-periodic token,
//! `auth.lease_duration` below the requested increment when capped, a 400
//! `lease is not renewable` for a non-renewable token).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use talos_metrics::{TalosMetrics, VaultTokenLifetimeLabel, VaultTokenRenewalOutcome};

use super::*;

// ── Pure: classification ────────────────────────────────────────────────────

#[test]
fn classify_matches_the_measured_vault_shapes() {
    // The dev controller's dev-root: periodic 768h, no explicit max.
    assert_eq!(
        TokenLifetime::classify(2_511_485, true, Some(2_764_800), 0, 2_764_800),
        TokenLifetime::Periodic {
            ttl_secs: 2_511_485,
            period_secs: 2_764_800
        }
    );
    // `ttl=300s`, renewable, no period: bounded by the mount max; ask for its
    // own creation TTL back.
    assert_eq!(
        TokenLifetime::classify(299, true, None, 0, 300),
        TokenLifetime::RenewableBounded {
            ttl_secs: 299,
            increment_secs: 300
        }
    );
    // Periodic WITH an explicit max TTL is bounded, not indefinitely renewable.
    assert_eq!(
        TokenLifetime::classify(119, true, Some(120), 320, 120),
        TokenLifetime::RenewableBounded {
            ttl_secs: 119,
            increment_secs: 120
        }
    );
    // `renewable=false`.
    assert_eq!(
        TokenLifetime::classify(299, false, None, 0, 300),
        TokenLifetime::Expiring { ttl_secs: 299 }
    );
    // A root token: ttl 0.
    assert_eq!(
        TokenLifetime::classify(0, false, None, 0, 0),
        TokenLifetime::NonExpiring
    );
    // A negative TTL is not "no TTL".
    assert_eq!(
        TokenLifetime::classify(-1, true, Some(60), 0, 60),
        TokenLifetime::Expiring { ttl_secs: 0 }
    );
    // A zero period is not periodic.
    assert!(matches!(
        TokenLifetime::classify(50, true, Some(0), 0, 60),
        TokenLifetime::RenewableBounded { .. }
    ));
}

#[test]
fn only_renewable_lifetimes_request_an_increment() {
    assert_eq!(
        TokenLifetime::Periodic {
            ttl_secs: 1,
            period_secs: 90
        }
        .renew_increment_secs(),
        Some(90)
    );
    assert_eq!(
        TokenLifetime::RenewableBounded {
            ttl_secs: 1,
            increment_secs: 30
        }
        .renew_increment_secs(),
        Some(30)
    );
    assert_eq!(TokenLifetime::NonExpiring.renew_increment_secs(), None);
    assert_eq!(
        TokenLifetime::Expiring { ttl_secs: 5 }.renew_increment_secs(),
        None
    );
}

// ── Pure: posture, renewal outcome, schedule ────────────────────────────────

#[test]
fn production_refuses_only_a_finite_non_renewable_token() {
    let expiring = TokenLifetime::Expiring { ttl_secs: 3600 };
    let err = token_lifetime_posture(expiring, true).expect_err("must refuse");
    let msg = err.to_string();
    assert!(msg.contains("NOT renewable"), "{msg}");
    assert!(msg.contains("3600 s left"), "{msg}");
    assert!(msg.contains("-period=768h"), "{msg}");
    // Outside production it is admitted (a WARN at the call site).
    assert!(token_lifetime_posture(expiring, false).is_ok());
    for admitted in [
        TokenLifetime::NonExpiring,
        TokenLifetime::Periodic {
            ttl_secs: 10,
            period_secs: 10,
        },
        TokenLifetime::RenewableBounded {
            ttl_secs: 10,
            increment_secs: 10,
        },
    ] {
        assert!(
            token_lifetime_posture(admitted, true).is_ok(),
            "{admitted:?}"
        );
    }
}

#[test]
fn renewal_is_renewed_only_when_vault_grants_the_full_increment() {
    use VaultTokenRenewalOutcome as O;
    assert_eq!(classify_renewal(600, 600, true), O::Renewed);
    assert_eq!(classify_renewal(600, 700, true), O::Renewed);
    // The measured cap: explicit_max_ttl 320, increment 600 → lease 320.
    assert_eq!(classify_renewal(600, 320, true), O::Capped);
    assert_eq!(classify_renewal(600, 600, false), O::Capped);
}

#[test]
fn schedule_renews_at_a_third_of_the_ttl_within_its_bounds() {
    let s = RenewalSchedule::DEFAULT;
    // A 768h period renews hourly, not every ~10 days.
    assert_eq!(s.after_success(2_764_800), Duration::from_secs(3600));
    assert_eq!(s.after_success(90), Duration::from_secs(30));
    // Never tighter than the floor, even for a nearly-expired token.
    assert_eq!(s.after_success(3), Duration::from_secs(5));
    assert_eq!(s.after_failure(2_764_800), Duration::from_secs(60));
    assert_eq!(s.after_failure(30), Duration::from_secs(10));
    assert_eq!(s.after_failure(0), Duration::from_secs(5));
}

// ── Mock Vault ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum RenewMode {
    /// Grant the requested increment.
    Grant,
    /// Grant at most this many seconds.
    Cap(u64),
    /// Grant, but report the token as no longer renewable.
    StopRenewable,
    /// 403.
    Fail,
    /// 400 "lease is not renewable" (what Vault answers a non-renewable token).
    NotRenewable,
}

struct MockToken {
    ttl: i64,
    renewable: bool,
    period: Option<i64>,
    explicit_max_ttl: i64,
    creation_ttl: i64,
    mode: RenewMode,
    renew_increments: Vec<String>,
    lookups: usize,
}

type Shared = Arc<Mutex<MockToken>>;

const TOKEN: &str = "test-token";

fn authed(headers: &HeaderMap) -> bool {
    headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) == Some(TOKEN)
}

async fn lookup(State(st): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if !authed(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"errors": ["permission denied"]})),
        );
    }
    let mut t = st.lock().unwrap();
    t.lookups += 1;
    let mut data = json!({
        "ttl": t.ttl, "renewable": t.renewable,
        "explicit_max_ttl": t.explicit_max_ttl, "creation_ttl": t.creation_ttl,
    });
    if let Some(p) = t.period {
        data["period"] = json!(p);
    }
    // Vault also carries a top-level `renewable: false` / `lease_duration: 0`
    // for the RESPONSE; the reader must take the one under `data`.
    (
        StatusCode::OK,
        Json(json!({"renewable": false, "lease_duration": 0, "data": data})),
    )
}

async fn renew(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authed(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"errors": ["permission denied"]})),
        );
    }
    let mut t = st.lock().unwrap();
    let inc = body["increment"].as_str().unwrap_or_default().to_string();
    t.renew_increments.push(inc.clone());
    let requested: u64 = inc.trim_end_matches('s').parse().unwrap_or(0);
    let (lease, renewable) = match t.mode {
        RenewMode::Grant => (requested, true),
        RenewMode::Cap(c) => (requested.min(c), true),
        RenewMode::StopRenewable => (requested, false),
        RenewMode::Fail => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"errors": ["permission denied"]})),
            )
        }
        RenewMode::NotRenewable => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"errors": ["lease is not renewable"]})),
            )
        }
    };
    t.ttl = i64::try_from(lease).unwrap();
    (
        StatusCode::OK,
        Json(json!({"renewable": false, "lease_duration": 0,
                    "auth": {"lease_duration": lease, "renewable": renewable}})),
    )
}

/// Transit echo: `vault:v1:<plaintext b64>` and back. Enough for the health
/// check's round-trip probe.
async fn encrypt(Json(body): Json<Value>) -> Json<Value> {
    let pt = body["plaintext"].as_str().unwrap_or_default();
    Json(json!({"data": {"ciphertext": format!("vault:v1:{pt}")}}))
}

async fn decrypt(Json(body): Json<Value>) -> Json<Value> {
    let ct = body["ciphertext"].as_str().unwrap_or_default();
    Json(json!({"data": {"plaintext": ct.trim_start_matches("vault:v1:")}}))
}

async fn mock_vault(token: MockToken) -> (VaultTransitProvider, Shared) {
    let shared: Shared = Arc::new(Mutex::new(token));
    let app = Router::new()
        .route("/v1/auth/token/lookup-self", get(lookup))
        .route("/v1/auth/token/renew-self", post(renew))
        .route("/v1/transit/encrypt/talos-kek", post(encrypt))
        .route("/v1/transit/decrypt/talos-kek", post(decrypt))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider =
        VaultTransitProvider::new(format!("http://{addr}"), TOKEN, "transit", "talos-kek").unwrap();
    (provider, shared)
}

fn token(ttl: i64, renewable: bool, period: Option<i64>, mode: RenewMode) -> MockToken {
    MockToken {
        ttl,
        renewable,
        period,
        explicit_max_ttl: 0,
        creation_ttl: period.unwrap_or(ttl),
        mode,
        renew_increments: Vec::new(),
        lookups: 0,
    }
}

const FAST: RenewalSchedule = RenewalSchedule {
    min: Duration::from_millis(20),
    max: Duration::from_millis(60),
    retry_max: Duration::from_millis(40),
};

fn count(m: &TalosMetrics, outcome: VaultTokenRenewalOutcome) -> f64 {
    m.vault_token_renewals_total
        .with_label_values(&[outcome.as_str()])
        .get()
}

fn ttl_gauge(m: &TalosMetrics, label: VaultTokenLifetimeLabel) -> Option<i64> {
    let body = m.render_prometheus().unwrap();
    let needle = format!(
        "talos_vault_token_ttl_seconds{{lifetime=\"{}\"}} ",
        label.as_str()
    );
    body.lines()
        .find_map(|l| l.strip_prefix(&needle))
        .map(|v| v.trim().parse().unwrap())
}

/// Run the loop for `dur` and hand back whatever it returned (None = still
/// running, which is the healthy state for a renewable token).
async fn run_for(
    p: &VaultTransitProvider,
    m: &TalosMetrics,
    dur: Duration,
) -> Option<TokenRenewalStop> {
    tokio::time::timeout(dur, p.run_token_renewal(FAST, Some(m)))
        .await
        .ok()
}

// ── Health check: the production refusal through the REAL check ─────────────

#[tokio::test]
async fn production_health_check_refuses_a_non_renewable_token_before_probing() {
    let (p, _) = mock_vault(token(3600, false, None, RenewMode::NotRenewable)).await;
    let err = p
        .health_check_in(true)
        .await
        .expect_err("production must refuse");
    assert!(err.to_string().contains("NOT renewable"), "{err}");
    // Outside production the same token passes the check.
    p.health_check_in(false).await.expect("dev admits it");
}

#[tokio::test]
async fn production_health_check_admits_a_periodic_token() {
    let (p, _) = mock_vault(token(2_764_000, true, Some(2_764_800), RenewMode::Grant)).await;
    p.health_check_in(true)
        .await
        .expect("periodic is the intended shape");
}

#[tokio::test]
async fn health_check_refuses_a_lookup_missing_the_lifetime_fields() {
    // A body without `ttl` must not read as "no TTL".
    // Everything a lookup carries EXCEPT `ttl`: with `ttl` defaulted this
    // would classify as non-expiring and pass.
    async fn bare() -> Json<Value> {
        Json(json!({"data": {"renewable": true, "explicit_max_ttl": 0, "creation_ttl": 60}}))
    }
    // The transit echo is served, so the ONLY thing that can fail is the
    // lookup parse — a defaulted `ttl` would pass this check.
    let app = Router::new()
        .route("/v1/auth/token/lookup-self", get(bare))
        .route("/v1/transit/encrypt/talos-kek", post(encrypt))
        .route("/v1/transit/decrypt/talos-kek", post(decrypt));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let p =
        VaultTransitProvider::new(format!("http://{addr}"), TOKEN, "transit", "talos-kek").unwrap();
    assert!(p.health_check_in(false).await.is_err());
}

// ── The renewal loop ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_periodic_token_is_renewed_at_once_and_repeatedly() {
    let (p, st) = mock_vault(token(10, true, Some(120), RenewMode::Grant)).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(
        run_for(&p, &m, Duration::from_millis(400)).await,
        None,
        "never returns"
    );

    let t = st.lock().unwrap();
    assert!(
        t.renew_increments.len() >= 3,
        "renewed {} times in 400 ms at a 60 ms cadence",
        t.renew_increments.len()
    );
    // The FIRST renewal is immediate — it does not wait out a third of the
    // boot TTL — and asks for the period.
    assert_eq!(t.renew_increments[0], "120s");
    drop(t);
    assert!(count(&m, VaultTokenRenewalOutcome::Renewed) >= 3.0);
    assert_eq!(count(&m, VaultTokenRenewalOutcome::Failed), 0.0);
    assert_eq!(count(&m, VaultTokenRenewalOutcome::Capped), 0.0);
    // The gauge carries the renewed lease, not the boot TTL of 10.
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::Periodic), Some(120));
}

#[tokio::test]
async fn the_first_renewal_does_not_wait_out_a_third_of_the_boot_ttl() {
    // A token booted late in its period has little left; waiting ttl/3 before
    // the first renewal would spend a third of what remains. With a wide
    // schedule, exactly ONE renewal must happen at once and no second one.
    let (p, st) = mock_vault(token(3000, true, Some(3600), RenewMode::Grant)).await;
    let m = TalosMetrics::new().unwrap();
    let wide = RenewalSchedule {
        min: Duration::from_secs(5),
        max: Duration::from_secs(3600),
        retry_max: Duration::from_secs(60),
    };
    let _ = tokio::time::timeout(
        Duration::from_millis(300),
        p.run_token_renewal(wide, Some(&m)),
    )
    .await;
    assert_eq!(
        st.lock().unwrap().renew_increments,
        vec!["3600s".to_string()]
    );
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::Periodic), Some(3600));
}

#[tokio::test]
async fn a_capped_renewal_is_counted_as_capped_and_the_loop_continues() {
    let mut t = token(300, true, None, RenewMode::Cap(40));
    t.creation_ttl = 300;
    let (p, st) = mock_vault(t).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(run_for(&p, &m, Duration::from_millis(300)).await, None);
    assert_eq!(st.lock().unwrap().renew_increments[0], "300s");
    assert!(count(&m, VaultTokenRenewalOutcome::Capped) >= 2.0);
    assert_eq!(count(&m, VaultTokenRenewalOutcome::Renewed), 0.0);
    assert_eq!(
        ttl_gauge(&m, VaultTokenLifetimeLabel::RenewableBounded),
        Some(40)
    );
}

#[tokio::test]
async fn a_failing_vault_is_counted_and_retried_not_abandoned() {
    let (p, st) = mock_vault(token(600, true, Some(600), RenewMode::Fail)).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(run_for(&p, &m, Duration::from_millis(300)).await, None);
    let failed = count(&m, VaultTokenRenewalOutcome::Failed);
    assert!(
        failed >= 3.0,
        "retried at the 40 ms failure cadence: {failed}"
    );
    assert_eq!(count(&m, VaultTokenRenewalOutcome::Renewed), 0.0);
    // Recovery: the next attempt after Vault answers is a success.
    st.lock().unwrap().mode = RenewMode::Grant;
    let m2 = TalosMetrics::new().unwrap();
    assert_eq!(run_for(&p, &m2, Duration::from_millis(150)).await, None);
    assert!(count(&m2, VaultTokenRenewalOutcome::Renewed) >= 1.0);
}

#[tokio::test]
async fn a_token_that_stops_being_renewable_ends_the_loop() {
    let (p, st) = mock_vault(token(600, true, Some(600), RenewMode::StopRenewable)).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(
        run_for(&p, &m, Duration::from_millis(500)).await,
        Some(TokenRenewalStop::NoLongerRenewable)
    );
    assert_eq!(st.lock().unwrap().renew_increments.len(), 1);
    assert_eq!(count(&m, VaultTokenRenewalOutcome::Capped), 1.0);
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::Expiring), Some(600));
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::Periodic), None);
}

#[tokio::test]
async fn non_renewable_and_non_expiring_tokens_return_without_renewing() {
    let (p, st) = mock_vault(token(300, false, None, RenewMode::NotRenewable)).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(
        run_for(&p, &m, Duration::from_millis(500)).await,
        Some(TokenRenewalStop::NotRenewable)
    );
    assert!(st.lock().unwrap().renew_increments.is_empty());
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::Expiring), Some(300));
    // SEEDED by the loop — read from the render, because `count()` would
    // create the series itself — and nothing moved.
    let body = m.render_prometheus().unwrap();
    for o in VaultTokenRenewalOutcome::ALL {
        assert!(
            body.contains(&format!(
                "talos_vault_token_renewals_total{{outcome=\"{}\"}} 0",
                o.as_str()
            )),
            "the loop must seed {o:?}"
        );
    }

    let (p, st) = mock_vault(token(0, false, None, RenewMode::NotRenewable)).await;
    let m = TalosMetrics::new().unwrap();
    assert_eq!(
        run_for(&p, &m, Duration::from_millis(500)).await,
        Some(TokenRenewalStop::NotNeeded)
    );
    assert!(st.lock().unwrap().renew_increments.is_empty());
    assert_eq!(ttl_gauge(&m, VaultTokenLifetimeLabel::NonExpiring), Some(0));
}

#[tokio::test]
async fn an_unreachable_vault_at_start_is_retried_and_counted() {
    // Nothing listens here; the lookup fails and the loop keeps trying.
    let p = VaultTransitProvider::new("http://127.0.0.1:1", TOKEN, "transit", "talos-kek").unwrap();
    let m = TalosMetrics::new().unwrap();
    assert_eq!(run_for(&p, &m, Duration::from_millis(200)).await, None);
    assert!(count(&m, VaultTokenRenewalOutcome::Failed) >= 2.0);
}

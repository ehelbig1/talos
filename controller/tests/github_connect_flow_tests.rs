//! The GitHub App connect flow cannot be used to take over someone else's
//! installation (2026-09-25).
//!
//! Before the fix, `/api/github/setup` consumed a state token that proved only
//! that SOME user had started a connect, trusted the `installation_id` on the
//! redirect (GitHub documents that it can be spoofed), fetched it with the App
//! JWT — which works for every installation of the App — and upserted it with
//! `ON CONFLICT (installation_id) DO UPDATE SET user_id = EXCLUDED.user_id`.
//! So user B could mint their own state and open
//! `/api/github/setup?installation_id=<A's>&state=<B's>`: A's installation, and
//! `github_app:<owner>` token minting for A's repositories, moved to B.
//!
//! These tests drive the REAL `GithubConnectService` against the REAL database
//! and a loopback stand-in for github.com / api.github.com, through all three
//! hops, and assert on ROWS — never on a reply alone:
//!
//! * the attack itself is refused and A's row does not move;
//! * a GitHub user who CAN see the installation still cannot take it from an
//!   active owner;
//! * the setup step writes nothing (the spoofable id is only carried forward);
//! * a URL minted in one browser cannot be completed in another;
//! * the ordinary connect works and is recorded in `admin_event_log`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderValue};
use talos_github::{AppSigningKey, GithubAppClient, GithubUserAuthClient, GithubUserAuthConfig};
use talos_github_connect::{AuthorizedOutcome, ClaimRefusal, GithubConnectService};
use talos_github_repository::{GithubAppInstallationRepository, NewInstallationClaim};
use talos_oauth::{BrowserBinding, CONNECT_BINDING_COOKIE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

/// A stand-in for github.com + api.github.com on one loopback port.
///
/// * `POST /login/oauth/access_token` — `code` → user token (`codes`); an
///   unknown code gets GitHub's 200-with-`error` body.
/// * `GET /user/installations` — bearer token → installation ids (`visible`).
/// * `GET /app/installations/{id}` — account metadata.
///
/// Records whether every exchange carried a PKCE `code_verifier`.
struct FakeGithub {
    base: String,
    exchanges_without_verifier: Arc<Mutex<u32>>,
}

async fn fake_github(codes: &[(&str, &str)], visible: &[(&str, &[i64])]) -> FakeGithub {
    let codes: HashMap<String, String> = codes
        .iter()
        .map(|(c, t)| (c.to_string(), t.to_string()))
        .collect();
    let visible: HashMap<String, Vec<i64>> = visible
        .iter()
        .map(|(t, ids)| (t.to_string(), ids.to_vec()))
        .collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let no_verifier = Arc::new(Mutex::new(0u32));
    let no_verifier_srv = no_verifier.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let codes = codes.clone();
            let visible = visible.clone();
            let no_verifier = no_verifier_srv.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read the head, then Content-Length bytes of body.
                let (head, mut body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_string();
                        break (head, buf[i + 4..].to_vec());
                    }
                };
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while body.len() < len {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let path = request_line
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let bearer = head.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("authorization")
                        .then(|| v.trim().trim_start_matches("Bearer ").to_string())
                });
                let json = if path.starts_with("/login/oauth/access_token") {
                    let form: HashMap<String, String> = String::from_utf8_lossy(&body)
                        .split('&')
                        .filter_map(|p| {
                            let (k, v) = p.split_once('=')?;
                            Some((k.to_string(), v.to_string()))
                        })
                        .collect();
                    if !form.contains_key("code_verifier") {
                        *no_verifier.lock().unwrap() += 1;
                    }
                    match form.get("code").and_then(|c| codes.get(c)) {
                        Some(token) => {
                            format!(
                                r#"{{"access_token":"{token}","token_type":"bearer","scope":""}}"#
                            )
                        }
                        None => r#"{"error":"bad_verification_code"}"#.to_string(),
                    }
                } else if path.starts_with("/user/installations") {
                    let ids = bearer
                        .as_deref()
                        .and_then(|t| visible.get(t))
                        .cloned()
                        .unwrap_or_default();
                    let items: Vec<String> =
                        ids.iter().map(|id| format!(r#"{{"id":{id}}}"#)).collect();
                    format!(
                        r#"{{"total_count":{},"installations":[{}]}}"#,
                        ids.len(),
                        items.join(",")
                    )
                } else if let Some(id) = path.strip_prefix("/app/installations/") {
                    format!(
                        r#"{{"id":{id},"account":{{"login":"acct-{id}","type":"Organization"}},"repository_selection":"all","permissions":{{"contents":"read"}}}}"#
                    )
                } else {
                    "{}".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    FakeGithub {
        base,
        exchanges_without_verifier: no_verifier,
    }
}

fn service(pool: &sqlx::PgPool, gh: &FakeGithub) -> GithubConnectService {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let signing = AppSigningKey::from_pem(pem.as_str()).unwrap();
    let app = GithubAppClient::with_base(signing, "4242", &gh.base).unwrap();
    let user_auth = GithubUserAuthClient::with_bases(
        GithubUserAuthConfig::from_values(
            "Iv1.test".into(),
            "client-secret".into(),
            "https://talos.example/api/github/authorized".into(),
        )
        .unwrap(),
        &gh.base,
        &gh.base,
    )
    .unwrap();
    GithubConnectService::with_clients(pool.clone(), app, "talos-test".into(), user_auth)
}

/// The Cookie header a browser holding `binding` sends.
fn browser(binding: &BrowserBinding) -> HeaderMap {
    // The Set-Cookie value's first segment IS `name=value`.
    let set_cookie = binding.set_cookie_header();
    let pair = set_cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_str(&pair).unwrap(),
    );
    h
}

fn presented(h: &HeaderMap) -> Option<String> {
    talos_oauth::presented_connect_binding(h)
}

fn state_param(url: &str) -> String {
    url.split(['?', '&'])
        .find_map(|p| p.strip_prefix("state="))
        .expect("url carries a state")
        .to_string()
}

/// One browser's walk through connect → setup, returning the state for the
/// user-authorization callback.
async fn connect_and_setup(
    svc: &GithubConnectService,
    user: Uuid,
    binding: &BrowserBinding,
    installation_id: &str,
) -> String {
    let h = browser(binding);
    let install = svc
        .begin_install(user, binding)
        .await
        .expect("begin_install");
    let s1 = state_param(&install);
    let authorize = svc
        .handle_setup(
            Some(installation_id),
            Some("install"),
            &s1,
            binding,
            presented(&h).as_deref(),
        )
        .await
        .expect("handle_setup");
    assert!(
        authorize.contains("/login/oauth/authorize?"),
        "setup must hand off to GitHub user authorization, got {authorize}"
    );
    assert!(authorize.contains("code_challenge_method=S256"));
    state_param(&authorize)
}

async fn owner_of(pool: &sqlx::PgPool, installation_id: i64) -> Option<(Uuid, bool)> {
    sqlx::query_as(
        "SELECT user_id, is_active FROM github_app_installations WHERE installation_id = $1",
    )
    .bind(installation_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn claim_events(pool: &sqlx::PgPool) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT user_id, details FROM admin_event_log \
         WHERE event_type = 'github_installation_claimed' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_spoofed_installation_id_cannot_move_another_users_installation() {
    let (pool, _db) = common::isolated_db_pool().await;
    let victim = Uuid::new_v4();
    let attacker = Uuid::new_v4();
    seed_user(&pool, victim, "victim@github-connect.test").await;
    seed_user(&pool, attacker, "attacker@github-connect.test").await;

    // The victim's installation 111 is already connected.
    let repo = GithubAppInstallationRepository::new(pool.clone());
    let _ = repo
        .claim_recorded(&NewInstallationClaim {
            user_id: victim,
            installation_id: 111,
            account_login: "acct-111",
            account_type: Some("Organization"),
            permissions: None,
            repository_selection: Some("all"),
        })
        .await
        .unwrap();

    // The attacker's GitHub account sees only its own installation 222.
    let gh = fake_github(
        &[("attacker-code", "ghu_attacker")],
        &[("ghu_attacker", &[222])],
    )
    .await;
    let svc = service(&pool, &gh);

    // The attacker mints their OWN state in their OWN browser and names the
    // victim's installation id on the setup redirect — the original exploit.
    let attacker_browser = BrowserBinding::fresh();
    let s2 = connect_and_setup(&svc, attacker, &attacker_browser, "111").await;

    // Setup wrote nothing: the spoofable id was only carried forward.
    assert_eq!(owner_of(&pool, 111).await, Some((victim, true)));

    let out = svc
        .handle_authorized(
            "attacker-code",
            &s2,
            presented(&browser(&attacker_browser)).as_deref(),
        )
        .await
        .expect("authorized callback");
    assert!(
        matches!(out, AuthorizedOutcome::Refused(ClaimRefusal::NotAccessible)),
        "GitHub does not list 111 for the attacker, so the claim must be refused"
    );
    assert_eq!(
        owner_of(&pool, 111).await,
        Some((victim, true)),
        "the victim's installation must not move"
    );
    assert_eq!(
        claim_events(&pool).await.len(),
        1,
        "only the victim's own claim is recorded"
    );
    assert_eq!(
        *gh.exchanges_without_verifier.lock().unwrap(),
        0,
        "every code exchange must carry the PKCE verifier"
    );
}

#[tokio::test]
async fn github_access_alone_does_not_take_an_installation_from_an_active_owner() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = Uuid::new_v4();
    let colleague = Uuid::new_v4();
    seed_user(&pool, owner, "owner@github-connect.test").await;
    seed_user(&pool, colleague, "colleague@github-connect.test").await;

    // A colleague in the same GitHub org CAN see installation 111.
    let gh = fake_github(
        &[
            ("owner-code", "ghu_owner"),
            ("colleague-code", "ghu_colleague"),
        ],
        &[("ghu_owner", &[111]), ("ghu_colleague", &[111])],
    )
    .await;
    let svc = service(&pool, &gh);

    let owner_browser = BrowserBinding::fresh();
    let s = connect_and_setup(&svc, owner, &owner_browser, "111").await;
    let out = svc
        .handle_authorized(
            "owner-code",
            &s,
            presented(&browser(&owner_browser)).as_deref(),
        )
        .await
        .unwrap();
    assert!(matches!(out, AuthorizedOutcome::Connected(ref o) if o.account_login == "acct-111"));
    assert_eq!(owner_of(&pool, 111).await, Some((owner, true)));

    let colleague_browser = BrowserBinding::fresh();
    let s = connect_and_setup(&svc, colleague, &colleague_browser, "111").await;
    let out = svc
        .handle_authorized(
            "colleague-code",
            &s,
            presented(&browser(&colleague_browser)).as_deref(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            out,
            AuthorizedOutcome::Refused(ClaimRefusal::OwnedByAnotherUser)
        ),
        "an ACTIVE installation owned by another Talos user is never reassigned"
    );
    assert_eq!(owner_of(&pool, 111).await, Some((owner, true)));

    let events = claim_events(&pool).await;
    assert_eq!(events.len(), 1, "the refused claim wrote nothing");
    assert_eq!(events[0].0, Some(owner));
    assert_eq!(events[0].1["installation_id"], 111);
    assert_eq!(events[0].1["transition"], "created");
    assert_eq!(
        events[0].1["ownership_verified_by"],
        "github_user_installations"
    );
}

#[tokio::test]
async fn a_connect_url_cannot_be_completed_in_another_browser() {
    let (pool, _db) = common::isolated_db_pool().await;
    let attacker = Uuid::new_v4();
    seed_user(&pool, attacker, "attacker2@github-connect.test").await;
    // The victim's GitHub account can see 555; the attacker hopes the victim
    // completes the attacker's flow so 555 lands on the attacker's account.
    let gh = fake_github(&[("victim-code", "ghu_victim")], &[("ghu_victim", &[555])]).await;
    let svc = service(&pool, &gh);

    let attacker_browser = BrowserBinding::fresh();
    let victim_browser = BrowserBinding::fresh();

    // Hop 1 → 2 in the VICTIM's browser with the attacker's install URL.
    let install = svc
        .begin_install(attacker, &attacker_browser)
        .await
        .unwrap();
    let s1 = state_param(&install);
    let err = svc
        .handle_setup(
            Some("555"),
            Some("install"),
            &s1,
            &victim_browser,
            presented(&browser(&victim_browser)).as_deref(),
        )
        .await;
    assert!(
        err.is_err(),
        "setup must refuse a state started in another browser"
    );

    // Hop 2 → 3 in the victim's browser with the attacker's authorize URL.
    let s2 = connect_and_setup(&svc, attacker, &attacker_browser, "555").await;
    let err = svc
        .handle_authorized(
            "victim-code",
            &s2,
            presented(&browser(&victim_browser)).as_deref(),
        )
        .await;
    assert!(
        err.is_err(),
        "the authorize callback must refuse another browser"
    );
    // …and no cookie at all is no binding.
    let s2 = connect_and_setup(&svc, attacker, &attacker_browser, "555").await;
    assert!(svc
        .handle_authorized("victim-code", &s2, None)
        .await
        .is_err());

    assert_eq!(owner_of(&pool, 555).await, None, "nothing was claimed");
    assert!(claim_events(&pool).await.is_empty());
}

#[tokio::test]
async fn the_setup_redirect_and_cookie_name_line_up() {
    // The binding cookie the connect response sets is the one the callbacks read.
    let b = BrowserBinding::fresh();
    let h = browser(&b);
    assert!(h
        .get(axum::http::header::COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with(&format!("{CONNECT_BINDING_COOKIE}=")));
    assert!(presented(&h).is_some());
}

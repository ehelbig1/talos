//! Which Google Cloud consent a service-account token is minted from, against
//! real rows (2026-10-12).
//!
//! A person can connect more than one Google account for impersonation. Until
//! this change the mint used whichever connection had been updated last, so
//! with two accounts the answer moved whenever a token was refreshed, and a
//! workflow written for one account could run on the other's consent.
//!
//! What is pinned here, on rows and not on a reply:
//!
//! * the list a mint may choose from is the requesting user's own ACTIVE
//!   FULL-tier connections and nothing else: not another user's, not a
//!   disconnected one, not the read or write tier of the same account;
//! * that list does not move when a row is touched, so nothing "latest" can
//!   decide;
//! * with several and none named, nothing is chosen; a name outside the list
//!   is never used.
//!
//! The mint call itself (a request to Google) is not driven here.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use talos_google_cloud::impersonation::{
    active_full_tier_connections, choose_consent, ConsentChoice,
};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'not-a-real-hash', true)")
        .bind(id)
        .bind(format!("gcp-consent-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

async fn connect(pool: &sqlx::PgPool, user: Uuid, key: Uuid, tier: &str, active: bool) {
    sqlx::query(
        "INSERT INTO google_cloud_integrations (user_id, provider_key, account_email, tier, is_active) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user)
    .bind(key)
    .bind(format!("{key}@example.com"))
    .bind(tier)
    .bind(active)
    .execute(pool)
    .await
    .expect("seed connection");
}

#[tokio::test]
async fn a_mint_chooses_only_among_the_users_own_active_full_connections() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (alice, bob) = (seed_user(&pool).await, seed_user(&pool).await);
    let personal = Uuid::from_u128(0x10);
    let work = Uuid::from_u128(0x20);
    let read_only = Uuid::from_u128(0x30);
    let disconnected = Uuid::from_u128(0x40);
    let bobs = Uuid::from_u128(0x50);
    connect(&pool, alice, work, "full", true).await;
    connect(&pool, alice, personal, "full", true).await;
    // The same account's other tiers are not consents to mint from.
    connect(&pool, alice, personal, "read", true).await;
    connect(&pool, alice, read_only, "read", true).await;
    connect(&pool, alice, read_only, "write", true).await;
    connect(&pool, alice, disconnected, "full", false).await;
    connect(&pool, bob, bobs, "full", true).await;

    let mine = active_full_tier_connections(&pool, alice).await.unwrap();
    assert_eq!(
        mine,
        vec![personal, work],
        "own, active, full tier, in key order"
    );
    assert_eq!(
        active_full_tier_connections(&pool, bob).await.unwrap(),
        vec![bobs]
    );
    assert!(active_full_tier_connections(&pool, Uuid::new_v4())
        .await
        .unwrap()
        .is_empty());

    // Two accounts and no name: nothing is chosen.
    assert_eq!(
        choose_consent(&mine, None),
        ConsentChoice::SeveralAndNoneNamed
    );
    // A name is used only when it is one of them.
    assert_eq!(choose_consent(&mine, Some(work)), ConsentChoice::Use(work));
    assert_eq!(
        choose_consent(&mine, Some(personal)),
        ConsentChoice::Use(personal)
    );
    for not_mine in [bobs, disconnected, read_only, Uuid::new_v4()] {
        assert_eq!(
            choose_consent(&mine, Some(not_mine)),
            ConsentChoice::NamedIsNotTheirs,
            "{not_mine}"
        );
    }
    // Bob, with one, needs no name; and cannot name Alice's.
    let his = active_full_tier_connections(&pool, bob).await.unwrap();
    assert_eq!(choose_consent(&his, None), ConsentChoice::Use(bobs));
    assert_eq!(
        choose_consent(&his, Some(work)),
        ConsentChoice::NamedIsNotTheirs
    );
}

#[tokio::test]
async fn touching_a_connection_does_not_change_which_one_is_chosen() {
    let (pool, _db) = common::isolated_db_pool().await;
    let alice = seed_user(&pool).await;
    let (personal, work) = (Uuid::from_u128(0x10), Uuid::from_u128(0x20));
    connect(&pool, alice, personal, "full", true).await;
    connect(&pool, alice, work, "full", true).await;
    let before = active_full_tier_connections(&pool, alice).await.unwrap();

    // What a token refresh does to a row: it becomes the most recently updated.
    for touched in [personal, work, personal] {
        sqlx::query("UPDATE google_cloud_integrations SET token_expires_at = NOW() + interval '1 hour', updated_at = NOW() WHERE user_id = $1 AND provider_key = $2 AND tier = 'full'")
            .bind(alice)
            .bind(touched)
            .execute(&pool)
            .await
            .unwrap();
        let after = active_full_tier_connections(&pool, alice).await.unwrap();
        assert_eq!(after, before, "after touching {touched}");
        assert_eq!(
            choose_consent(&after, None),
            ConsentChoice::SeveralAndNoneNamed
        );
        assert_eq!(choose_consent(&after, Some(work)), ConsentChoice::Use(work));
    }

    // Disconnecting one leaves exactly one, and then no name is needed.
    sqlx::query("UPDATE google_cloud_integrations SET is_active = FALSE WHERE user_id = $1 AND provider_key = $2 AND tier = 'full'")
        .bind(alice)
        .bind(personal)
        .execute(&pool)
        .await
        .unwrap();
    let left = active_full_tier_connections(&pool, alice).await.unwrap();
    assert_eq!(choose_consent(&left, None), ConsentChoice::Use(work));
    // The disconnected one can no longer be named.
    assert_eq!(
        choose_consent(&left, Some(personal)),
        ConsentChoice::NamedIsNotTheirs
    );
}

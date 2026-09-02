//! Can user B resolve user A's private module by NAME?
//!
//! `plan_and_execute_workflow` turns a caller-supplied `module_name` into a
//! `modules.id`, writes it into a generated single-node workflow, publishes
//! that workflow under the CALLER's user id, and hands the caller a
//! `trigger_workflow(...)` next-step. Until 2026-09-02 the two lookups behind
//! that resolution — a strip-normalised exact match and a fuzzy `%a%b%` ILIKE
//! fallback — carried no owner predicate at all, on the bare pool.
//!
//! # What the defect was, and what it was NOT
//!
//! It was **not** cross-tenant execution. Three independent runtime predicates
//! stop that: `ModuleRegistry::get_module` and `get_module_bytes` both select
//! `WHERE id = $1 AND (user_id = $2 OR user_id IS NULL)`, and the stale-name
//! fallback's successor query is scoped the same way. A foreign id embedded in
//! a graph fails at dispatch.
//!
//! It WAS a name-to-id oracle — a caller-supplied string turned into another
//! tenant's `modules.id` (and, through `lookup_template_by_name_ci`, that
//! module's `description` and `allowed_secrets`). That is precisely the harm
//! MCP-956 named when it scoped `find_template_id_by_name_ci`: "the downstream
//! caller would fail to actually use the foreign-tenant UUID, but the existence
//! + UUID disclosure was a cross-tenant info leak." And it was a correctness
//! bug for the honest caller, who got a plan wired to a module their own
//! workflow cannot resolve.
//!
//! # Why these tests need a real Postgres
//!
//! Every property here IS a `WHERE`/`ORDER BY` clause. Nothing but the database
//! can evaluate one. In particular RLS cannot substitute for the predicate:
//! `modules_tenant_isolation` keys on `org_id`, permits unconditionally when
//! `app.current_org_ids` is unset, and the application role carries
//! `rolbypassrls`. This is a USER boundary; RLS enforces an ORG one.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (a MIGRATED database). CI-wired as
//! `talos-module-repository:module_lookup_tenancy:migrated` in
//! `scripts/test-integration.sh`; skips with a printed note when unset.
//!
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://talos:<pw>@localhost:5432/talos"
//! cargo test -p talos-module-repository --test module_lookup_tenancy -- --nocapture
//! ```

use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use talos_module_repository::ModuleRepository;
use uuid::Uuid;

async fn pool_or_skip() -> Option<Pool<Postgres>> {
    let url = match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL to run module_lookup_tenancy");
            return None;
        }
    };
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("TALOS_TEST_DATABASE_URL connect"),
    )
}

async fn seed_user(pool: &Pool<Postgres>, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(format!("mod-tenancy-{tag}-{id}@test.invalid"))
    .bind(format!("mod-tenancy-{tag}"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// `owner = None` seeds a CATALOG row (`user_id IS NULL`) — the shape whose
/// resolvability every one of these tests must preserve.
async fn seed_module(
    pool: &Pool<Postgres>,
    owner: Option<Uuid>,
    name: &str,
    category: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules \
             (id, user_id, name, description, capability_world, kind, wasm_bytes, \
              content_hash, size_bytes, category, created_at, compiled_at) \
         VALUES ($1, $2, $3, $4, 'minimal-node', 'sandbox', '\\x00'::bytea, \
                 $5, 1, $6, NOW(), NOW())",
    )
    .bind(id)
    .bind(owner)
    .bind(name)
    .bind(format!("seeded fixture for {name}"))
    .bind(format!("{:x}", id.as_u128()))
    .bind(category)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

async fn drop_modules(pool: &Pool<Postgres>, ids: &[Uuid]) {
    sqlx::query("DELETE FROM modules WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .expect("cleanup modules");
}

async fn drop_users(pool: &Pool<Postgres>, ids: &[Uuid]) {
    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .expect("cleanup users");
}

/// The headline: A's private module must be invisible to B through the exact
/// resolver `plan_and_execute_workflow` calls — on the exact name, on the
/// underscore/space spellings the strip-normaliser folds, and on the fuzzy
/// substring the ILIKE fallback matches. Pre-fix all four returned A's id.
#[tokio::test]
async fn user_b_cannot_resolve_user_as_private_module_by_name() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "a").await;
    let user_b = seed_user(&pool, "b").await;
    let tag = Uuid::new_v4().simple().to_string();
    let name = format!("zeta-private-{tag}");
    let a_mod = seed_module(&pool, Some(user_a), &name, None).await;

    let repo = ModuleRepository::new(pool.clone());

    // A's own resolution still works — otherwise "B sees nothing" would be
    // satisfied by a lookup that resolves nothing for anyone.
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&name, user_a)
            .await
            .expect("A exact"),
        Some(a_mod),
        "the owner must still resolve their own module"
    );

    // 1. exact name
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&name, user_b)
            .await
            .expect("B exact"),
        None,
        "B resolved A's module by its exact name"
    );

    // 2. the strip-normalised spelling (`-` and `_` are stripped both sides)
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&format!("zeta_private_{tag}"), user_b)
            .await
            .expect("B strip"),
        None,
        "B resolved A's module by an underscore spelling"
    );

    // 3. the fuzzy ILIKE fallback: spaces do NOT strip, so step 1 misses and
    //    step 2 folds this to `%zeta%private%<tag>%`.
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&format!("zeta private {tag}"), user_b)
            .await
            .expect("B fuzzy"),
        None,
        "B resolved A's module through the fuzzy ILIKE fallback"
    );
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&format!("zeta private {tag}"), user_a)
            .await
            .expect("A fuzzy"),
        Some(a_mod),
        "the fuzzy fallback must still reach the owner's own module"
    );

    // 4. the sibling name resolvers on the same class of caller-supplied name
    assert_eq!(
        repo.find_template_id_by_name_normalised(&name, user_b)
            .await
            .expect("B normalised"),
        None,
        "B resolved A's module through find_template_id_by_name_normalised"
    );
    assert_eq!(
        repo.find_template_id_by_name_normalised(&name, user_a)
            .await
            .expect("A normalised"),
        Some(a_mod)
    );
    assert!(
        repo.lookup_template_by_name_ci(&name, user_b)
            .await
            .expect("B ci")
            .is_none(),
        "B read A's module row (id + description + allowed_secrets) by name"
    );
    assert!(repo
        .lookup_template_by_name_ci(&name, user_a)
        .await
        .expect("A ci")
        .is_some());

    drop_modules(&pool, &[a_mod]).await;
    drop_users(&pool, &[user_a, user_b]).await;
}

/// The other half of the contract, and the one a careless fix breaks: a flat
/// `user_id = $n` predicate would make the whole catalog unresolvable and take
/// module installation down platform-wide. Catalog rows are `user_id IS NULL`
/// and must resolve for EVERY user.
#[tokio::test]
async fn catalog_rows_stay_resolvable_for_every_user() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "cat-a").await;
    let user_b = seed_user(&pool, "cat-b").await;
    let tag = Uuid::new_v4().simple().to_string();
    let name = format!("zeta-catalog-{tag}");
    let cat_mod = seed_module(&pool, None, &name, Some("catalog")).await;

    let repo = ModuleRepository::new(pool.clone());
    for (who, uid) in [("A", user_a), ("B", user_b)] {
        assert_eq!(
            repo.resolve_module_id_by_name_for_user(&name, uid)
                .await
                .expect("catalog resolve"),
            Some(cat_mod),
            "{who} could not resolve a catalog module"
        );
        assert_eq!(
            repo.find_template_id_by_name_normalised(&name, uid)
                .await
                .expect("catalog normalised"),
            Some(cat_mod),
            "{who} could not resolve a catalog module by normalised name"
        );
        assert!(
            repo.lookup_template_by_name_ci(&name, uid)
                .await
                .expect("catalog ci")
                .is_some(),
            "{who} could not read a catalog module row"
        );
    }

    drop_modules(&pool, &[cat_mod]).await;
    drop_users(&pool, &[user_a, user_b]).await;
}

/// `LIMIT 1` over a tie is decided by heap order. Installing a catalog module
/// writes a user-owned row of the SAME name (`modules_user_name_uniq` is
/// per-user; `modules_catalog_name_uniq` covers the catalog copy), so this tie
/// is the normal state of a working install — eight such pairs exist on a live
/// database today. The owner's copy must win, every time.
#[tokio::test]
async fn a_name_shared_with_the_catalog_resolves_to_the_owners_copy() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "tie-a").await;
    let user_b = seed_user(&pool, "tie-b").await;
    let tag = Uuid::new_v4().simple().to_string();
    let name = format!("zeta-shared-{tag}");
    // Catalog row inserted FIRST: without the ORDER BY it is what a seq scan
    // returns first, so the assertion below is a live test of the tiebreaker
    // rather than of insertion luck.
    let cat_mod = seed_module(&pool, None, &name, Some("catalog")).await;
    let a_mod = seed_module(&pool, Some(user_a), &name, None).await;

    let repo = ModuleRepository::new(pool.clone());
    for attempt in 0..5 {
        assert_eq!(
            repo.resolve_module_id_by_name_for_user(&name, user_a)
                .await
                .expect("A tie"),
            Some(a_mod),
            "attempt {attempt}: the owner's own copy must shadow the catalog original"
        );
        assert_eq!(
            repo.resolve_module_id_by_name_for_user(&name, user_b)
                .await
                .expect("B tie"),
            Some(cat_mod),
            "attempt {attempt}: a non-owner must get the catalog copy, never A's"
        );
    }

    drop_modules(&pool, &[cat_mod, a_mod]).await;
    drop_users(&pool, &[user_a, user_b]).await;
}

/// The resolver folds `-`, `_` and space to `%` deliberately — that is the
/// fuzz. A literal `%` in the caller's string is not fuzz, it is a wildcard the
/// caller injected: `module_name: "%"` used to resolve to whatever row the
/// planner returned first, from any tenant. Scoping alone does not fix this
/// (it would still hand back an arbitrary accessible row); the escape does.
#[tokio::test]
async fn a_wildcard_in_the_caller_supplied_name_matches_nothing() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "wild-a").await;
    let user_b = seed_user(&pool, "wild-b").await;
    let tag = Uuid::new_v4().simple().to_string();
    let a_mod = seed_module(&pool, Some(user_a), &format!("zeta-wild-{tag}"), None).await;

    let repo = ModuleRepository::new(pool.clone());
    for probe in ["%", "%%", "zeta%"] {
        assert_eq!(
            repo.resolve_module_id_by_name_for_user(probe, user_b)
                .await
                .unwrap_or_else(|e| panic!("wildcard probe {probe:?}: {e}")),
            None,
            "the wildcard {probe:?} resolved to a module"
        );
    }
    // And the owner gets nothing from a bare wildcard either — a `%` is a
    // literal that matches no real module name, not a "pick any of mine".
    assert_eq!(
        repo.resolve_module_id_by_name_for_user("%", user_a)
            .await
            .expect("A wildcard"),
        None
    );

    drop_modules(&pool, &[a_mod]).await;
    drop_users(&pool, &[user_a, user_b]).await;
}

/// The discovery/suggestion lists are the same class one step wider: they take
/// a caller-supplied keyword and answer with names, descriptions and
/// `allowed_secrets`. Their `category IS NOT NULL` filter makes them
/// catalog-only *in effect* on installs where nothing stamps a category on a
/// user-owned row — an accident, not a predicate. This pins the property so it
/// survives the first write that sets one.
#[tokio::test]
async fn capability_and_alternative_searches_do_not_enumerate_another_tenant() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "enum-a").await;
    let user_b = seed_user(&pool, "enum-b").await;
    let tag = Uuid::new_v4().simple().to_string();
    let a_name = format!("zeta-secretive-{tag}");
    // A categorised, user-owned row: the shape the `category IS NOT NULL`
    // filter would otherwise let through.
    let a_mod = seed_module(&pool, Some(user_a), &a_name, Some("sandbox")).await;
    let anchor = seed_module(&pool, None, &format!("zeta-anchor-{tag}"), Some("catalog")).await;

    let repo = ModuleRepository::new(pool.clone());
    let pattern = format!("%zeta-secretive-{tag}%");

    let b_ilike = repo
        .find_templates_by_capability_ilike(&pattern, user_b, 20)
        .await
        .expect("B capability ilike");
    assert!(
        !b_ilike.iter().any(|r| r.id == a_mod),
        "capability search enumerated A's module for B"
    );
    let a_ilike = repo
        .find_templates_by_capability_ilike(&pattern, user_a, 20)
        .await
        .expect("A capability ilike");
    assert!(
        a_ilike.iter().any(|r| r.id == a_mod),
        "capability search stopped finding the caller's OWN module"
    );

    let b_alts = repo
        .find_template_alternatives_by_category(anchor, "sandbox", user_b, 100)
        .await
        .expect("B alternatives");
    assert!(
        !b_alts.iter().any(|r| r.id == a_mod),
        "the alternatives list enumerated A's module for B"
    );

    // The two pg_trgm variants are the PRIMARY paths — the ILIKE ones above
    // only run when the extension is absent — so leaving them uncovered would
    // verify the fallback and not the query that actually serves the tool.
    // Skipped, loudly, where pg_trgm is not installed.
    let has_trgm: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')")
            .fetch_one(&pool)
            .await
            .expect("pg_trgm probe");
    if has_trgm {
        let b_cap = repo
            .find_templates_by_capability_trgm(&a_name, &pattern, user_b, 20)
            .await
            .expect("B capability trgm");
        assert!(
            !b_cap.iter().any(|r| r.id == a_mod),
            "the trigram capability search enumerated A's module for B"
        );
        let a_cap = repo
            .find_templates_by_capability_trgm(&a_name, &pattern, user_a, 20)
            .await
            .expect("A capability trgm");
        assert!(
            a_cap.iter().any(|r| r.id == a_mod),
            "the trigram capability search stopped finding the caller's OWN module"
        );

        let b_alt_trgm = repo
            .find_template_alternatives_trgm(anchor, &a_name, "sandbox", user_b, 20)
            .await
            .expect("B alternatives trgm");
        assert!(
            !b_alt_trgm.iter().any(|r| r.id == a_mod),
            "the trigram alternatives list enumerated A's module for B"
        );
        let a_alt_trgm = repo
            .find_template_alternatives_trgm(anchor, &a_name, "sandbox", user_a, 20)
            .await
            .expect("A alternatives trgm");
        assert!(
            a_alt_trgm.iter().any(|r| r.id == a_mod),
            "the trigram alternatives list stopped finding the caller's OWN module"
        );
    } else {
        eprintln!("NOTE: pg_trgm absent — the two trigram searches were NOT exercised");
    }

    drop_modules(&pool, &[a_mod, anchor]).await;
    drop_users(&pool, &[user_a, user_b]).await;
}

/// A nil `user_id` is what every handler in the tree substitutes when the
/// authenticated identity carries none (`agent.user_id.unwrap_or_else(nil)`),
/// so it is also the shape a call-site mutation would leave behind. It must
/// fail CLOSED — catalog only, never another tenant's row.
#[tokio::test]
async fn a_nil_caller_sees_the_catalog_and_nothing_else() {
    let Some(pool) = pool_or_skip().await else {
        return;
    };
    let user_a = seed_user(&pool, "nil-a").await;
    let tag = Uuid::new_v4().simple().to_string();
    let private = format!("zeta-nilprobe-{tag}");
    let public = format!("zeta-nilcat-{tag}");
    let a_mod = seed_module(&pool, Some(user_a), &private, None).await;
    let cat_mod = seed_module(&pool, None, &public, Some("catalog")).await;

    let repo = ModuleRepository::new(pool.clone());
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&private, Uuid::nil())
            .await
            .expect("nil private"),
        None,
        "a nil caller resolved a user-owned module"
    );
    assert_eq!(
        repo.resolve_module_id_by_name_for_user(&public, Uuid::nil())
            .await
            .expect("nil catalog"),
        Some(cat_mod),
        "a nil caller must still reach the catalog"
    );

    drop_modules(&pool, &[a_mod, cat_mod]).await;
    drop_users(&pool, &[user_a]).await;
}

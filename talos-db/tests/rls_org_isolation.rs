//! Proves the RFC 0004 org-isolation MECHANISM end-to-end against a live
//! Postgres: `begin_org_scoped` + a `SET LOCAL app.current_org_id` GUC +
//! an RLS policy, enforced under a NON-superuser role (the realistic
//! production condition — superusers/`BYPASSRLS` silently skip policies).
//!
//! This validates the approach on a synthetic probe table before the
//! horizontal repository sweep (M3) wires it into hundreds of call sites.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (skips when unset):
//! ```sh
//! export TALOS_TEST_DATABASE_URL="postgres://postgres:talos@localhost:5433/talos"
//! cargo test -p talos-db --test rls_org_isolation -- --nocapture
//! ```
//! The URL must be a SUPERUSER (the test creates a non-superuser role +
//! a probe table). The test cleans both up.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, Pool, Postgres};
use talos_db::{begin_org_scoped, begin_tenant_read_scoped, check_rls_role};
use talos_tenancy::{OrgScope, TenantReadScope};
use uuid::Uuid;

const APP_ROLE: &str = "talos_rls_test_app";
const APP_PW: &str = "rls_test_pw";

fn superuser_url() -> Option<String> {
    match std::env::var("TALOS_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("SKIP: set TALOS_TEST_DATABASE_URL (superuser) to run rls_org_isolation");
            None
        }
    }
}

/// Build the app-role URL by swapping the userinfo of the superuser URL.
fn app_url(superuser: &str) -> String {
    // postgres://USER:PW@host:port/db  →  postgres://APP_ROLE:APP_PW@host:port/db
    let after_at = superuser
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(superuser);
    format!("postgres://{APP_ROLE}:{APP_PW}@{after_at}")
}

async fn connect(url: &str) -> Pool<Postgres> {
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await
        .expect("connect")
}

#[tokio::test]
async fn rls_isolates_rows_by_active_org_under_non_superuser_role() {
    let Some(su_url) = superuser_url() else { return };
    let su = connect(&su_url).await;

    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();

    // ── Setup as superuser: app role, probe table, RLS policy, grants ──
    su.execute(
        format!(
            "DO $$ BEGIN \
               IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{APP_ROLE}') THEN \
                 CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_PW}'; \
               END IF; \
             END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create app role");

    su.execute(
        "DROP TABLE IF EXISTS rls_probe;
         CREATE TABLE rls_probe (id serial PRIMARY KEY, org_id uuid NOT NULL, val text);
         ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY;
         ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY;
         DROP POLICY IF EXISTS rls_probe_iso ON rls_probe;
         CREATE POLICY rls_probe_iso ON rls_probe
           USING (org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);",
    )
    .await
    .expect("probe table + policy");

    su.execute(format!("GRANT SELECT, INSERT ON rls_probe TO {APP_ROLE};").as_str())
        .await
        .expect("grant table");
    su.execute(
        format!("GRANT USAGE, SELECT ON SEQUENCE rls_probe_id_seq TO {APP_ROLE};").as_str(),
    )
    .await
    .expect("grant seq");

    sqlx::query("INSERT INTO rls_probe (org_id, val) VALUES ($1,'A'), ($2,'B')")
        .bind(org_a)
        .bind(org_b)
        .execute(&su)
        .await
        .expect("seed rows");

    // ── Act/assert as the NON-superuser app role ──────────────────────
    let app = connect(&app_url(&su_url)).await;
    let user = Uuid::new_v4();

    // Scoped to org A → sees ONLY org A's row.
    let mut tx = begin_org_scoped(&app, &OrgScope::new(org_a, user))
        .await
        .expect("org-scoped tx A");
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT org_id, val FROM rls_probe")
        .fetch_all(&mut *tx)
        .await
        .expect("select A");
    tx.commit().await.unwrap();
    assert_eq!(rows.len(), 1, "org A scope must see exactly its own row");
    assert_eq!(rows[0].0, org_a);
    assert_eq!(rows[0].1, "A");

    // Scoped to org B → sees ONLY org B's row.
    let mut tx = begin_org_scoped(&app, &OrgScope::new(org_b, user))
        .await
        .expect("org-scoped tx B");
    let rows_b: Vec<(Uuid, String)> = sqlx::query_as("SELECT org_id, val FROM rls_probe")
        .fetch_all(&mut *tx)
        .await
        .expect("select B");
    tx.commit().await.unwrap();
    assert_eq!(rows_b.len(), 1, "org B scope must see exactly its own row");
    assert_eq!(rows_b[0].0, org_b);

    // FAIL-CLOSED: a query with NO active-org GUC set sees ZERO rows.
    // NB the policy uses NULLIF(current_setting(...,true),'')::uuid — a
    // custom GUC resets to '' (not NULL) on a pooled connection after a
    // prior SET LOCAL commits, so the bare `::uuid` cast would ERROR;
    // NULLIF makes both never-set and reset-to-empty resolve to NULL,
    // matching nothing. A non-scoped path leaks nothing — it sees empty.
    let unscoped: i64 = sqlx::query_scalar("SELECT count(*) FROM rls_probe")
        .fetch_one(&app)
        .await
        .expect("unscoped count");
    assert_eq!(unscoped, 0, "without the GUC, RLS must hide every row (fail-closed)");

    // The RLS-role guard correctly classifies both roles: the superuser
    // setup connection bypasses RLS; the plain app role enforces it.
    let su_status = check_rls_role(&su).await.expect("su role status");
    assert!(
        !su_status.rls_enforced(),
        "the superuser test connection must be flagged as RLS-bypassing"
    );
    let app_status = check_rls_role(&app).await.expect("app role status");
    assert!(
        app_status.rls_enforced(),
        "the non-superuser app role must be RLS-enforcing"
    );

    // ── Cleanup ────────────────────────────────────────────────────────
    let _ = su.execute("DROP TABLE IF EXISTS rls_probe;").await;
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {APP_ROLE};").as_str())
        .await;
}

const UNION_ROLE: &str = "talos_rls_union_app";

fn union_app_url(superuser: &str) -> String {
    let after_at = superuser
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(superuser);
    format!("postgres://{UNION_ROLE}:{APP_PW}@{after_at}")
}

#[tokio::test]
async fn membership_union_rls_shows_owned_and_member_orgs_only() {
    let Some(su_url) = superuser_url() else { return };
    let su = connect(&su_url).await;

    let user = Uuid::new_v4();
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let org_c = Uuid::new_v4(); // a NON-member org

    su.execute(
        format!(
            "DO $$ BEGIN \
               IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{UNION_ROLE}') THEN \
                 CREATE ROLE {UNION_ROLE} LOGIN PASSWORD '{APP_PW}'; \
               END IF; \
             END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create union app role");

    // Probe table mirrors an owned table's shape: user_id + org_id, with
    // the RFC 0004 membership-union backstop policy.
    su.execute(
        "DROP TABLE IF EXISTS rls_union_probe;
         CREATE TABLE rls_union_probe (id serial PRIMARY KEY, user_id uuid, org_id uuid, val text);
         ALTER TABLE rls_union_probe ENABLE ROW LEVEL SECURITY;
         ALTER TABLE rls_union_probe FORCE ROW LEVEL SECURITY;
         DROP POLICY IF EXISTS rls_union_iso ON rls_union_probe;
         CREATE POLICY rls_union_iso ON rls_union_probe USING (
            user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
            OR org_id = ANY(
                 string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
               )
         );",
    )
    .await
    .expect("union probe table + policy");

    su.execute(format!("GRANT SELECT, INSERT ON rls_union_probe TO {UNION_ROLE};").as_str())
        .await
        .unwrap();
    su.execute(
        format!("GRANT USAGE, SELECT ON SEQUENCE rls_union_probe_id_seq TO {UNION_ROLE};").as_str(),
    )
    .await
    .unwrap();

    // Rows: one in each of A, B (member), C (non-member), plus one owned
    // by the user but in non-member org C (owned clause must still show it).
    let other_user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO rls_union_probe (user_id, org_id, val) VALUES \
         ($1,$2,'in-A'), ($1,$3,'in-B'), ($4,$5,'in-C-other'), ($6,$5,'owned-in-C')",
    )
    .bind(other_user)
    .bind(org_a)
    .bind(org_b)
    .bind(other_user)
    .bind(org_c)
    .bind(user) // owned-in-C is owned by `user`
    .execute(&su)
    .await
    .expect("seed union rows");

    // Scope: user is a member of A and B only.
    let app = connect(&union_app_url(&su_url)).await;
    let scope = TenantReadScope::new(user, vec![org_a, org_b]);
    let mut tx = begin_tenant_read_scoped(&app, &scope)
        .await
        .expect("read-scoped tx");
    let vals: Vec<String> = sqlx::query_scalar("SELECT val FROM rls_union_probe ORDER BY val")
        .fetch_all(&mut *tx)
        .await
        .expect("union select");
    tx.commit().await.unwrap();

    // Sees: in-A, in-B (member orgs) + owned-in-C (owned clause). NOT
    // in-C-other (non-member org, not owned).
    assert_eq!(
        vals,
        vec![
            "in-A".to_string(),
            "in-B".to_string(),
            "owned-in-C".to_string()
        ],
        "union backstop must show member-org rows + owned rows, never a non-member org's other-owned row"
    );

    let _ = su.execute("DROP TABLE IF EXISTS rls_union_probe;").await;
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {UNION_ROLE};").as_str())
        .await;
}

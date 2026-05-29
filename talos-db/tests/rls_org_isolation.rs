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
use talos_db::begin_org_scoped;
use talos_tenancy::OrgScope;
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

    // ── Cleanup ────────────────────────────────────────────────────────
    let _ = su.execute("DROP TABLE IF EXISTS rls_probe;").await;
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {APP_ROLE};").as_str())
        .await;
}

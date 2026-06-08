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
use talos_db::{
    begin_org_scoped, begin_tenant_read_scoped, begin_user_scoped, check_rls_role, UnitOfWork,
};

/// Serializes the per-test role DDL (`CREATE ROLE` / `GRANT` / `DROP
/// ROLE`). Running these tests in parallel races on the Postgres system
/// catalog (`pg_authid` / `pg_class`), which surfaces as a transient
/// `XX000 tuple concurrently updated` on a concurrent GRANT. Each test
/// holds this lock for its duration so the suite is deterministic
/// without requiring `--test-threads=1`.
static DDL_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
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
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
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
    su.execute(format!("GRANT USAGE, SELECT ON SEQUENCE rls_probe_id_seq TO {APP_ROLE};").as_str())
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
    assert_eq!(
        unscoped, 0,
        "without the GUC, RLS must hide every row (fail-closed)"
    );

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
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
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

const PERM_ROLE: &str = "talos_rls_perm_app";

/// Proves the M4 INCREMENTAL-rollout policy: permissive when the GUC is
/// unset/empty (so enabling RLS doesn't break un-wired paths — they keep
/// relying on the app layer), enforced when the GUC is set (wired paths
/// get the union backstop). Crucially exercises the pooling case: after a
/// scoped tx commits, the custom GUC resets to '' on the SAME connection,
/// and a bare query must fall back to PERMISSIVE — not deny. Uses a
/// 1-connection pool to force that connection reuse.
#[tokio::test]
async fn permissive_when_unset_policy_is_nonbreaking_then_enforces_when_set() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
    let su = connect(&su_url).await;
    let user = Uuid::new_v4();
    let org_a = Uuid::new_v4();
    let org_c = Uuid::new_v4(); // a non-member org

    su.execute(
        format!(
            "DO $$ BEGIN \
               IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{PERM_ROLE}') THEN \
                 CREATE ROLE {PERM_ROLE} LOGIN PASSWORD '{APP_PW}'; \
               END IF; \
             END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create perm role");

    // Permissive-when-unset variant of the membership-union policy.
    su.execute(
        "DROP TABLE IF EXISTS rls_perm_probe;
         CREATE TABLE rls_perm_probe (id serial PRIMARY KEY, user_id uuid, org_id uuid, val text);
         ALTER TABLE rls_perm_probe ENABLE ROW LEVEL SECURITY;
         ALTER TABLE rls_perm_probe FORCE ROW LEVEL SECURITY;
         DROP POLICY IF EXISTS rls_perm_iso ON rls_perm_probe;
         CREATE POLICY rls_perm_iso ON rls_perm_probe USING (
            NULLIF(current_setting('app.current_user_id', true), '') IS NULL
            OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
            OR org_id = ANY(
                 string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
               )
         );",
    )
    .await
    .expect("perm probe table + policy");
    su.execute(format!("GRANT SELECT, INSERT ON rls_perm_probe TO {PERM_ROLE};").as_str())
        .await
        .unwrap();
    su.execute(
        format!("GRANT USAGE, SELECT ON SEQUENCE rls_perm_probe_id_seq TO {PERM_ROLE};").as_str(),
    )
    .await
    .unwrap();

    let other = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO rls_perm_probe (user_id, org_id, val) VALUES \
         ($1,$2,'in-A'), ($3,$4,'in-C-other'), ($5,$4,'owned-in-C')",
    )
    .bind(other)
    .bind(org_a)
    .bind(other)
    .bind(org_c)
    .bind(user)
    .execute(&su)
    .await
    .expect("seed perm rows");

    // 1-connection pool so steps (1)→(3) share one physical connection,
    // forcing the post-commit GUC-reset-to-'' case in step (3).
    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&format!("postgres://{PERM_ROLE}:{APP_PW}@{after_at}"))
        .await
        .expect("connect perm app role");

    // (1) GUC unset → PERMISSIVE: sees ALL rows (un-wired path doesn't break).
    let unset: i64 = sqlx::query_scalar("SELECT count(*) FROM rls_perm_probe")
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(
        unset, 3,
        "unset GUC must be permissive so un-wired paths don't break"
    );

    // (2) Scoped (wired path): ENFORCED union → in-A + owned-in-C, not in-C-other.
    let scope = TenantReadScope::new(user, vec![org_a]);
    let mut tx = begin_tenant_read_scoped(&app, &scope).await.unwrap();
    let vals: Vec<String> = sqlx::query_scalar("SELECT val FROM rls_perm_probe ORDER BY val")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        vals,
        vec!["in-A".to_string(), "owned-in-C".to_string()],
        "a wired (scoped) path must enforce the membership-union backstop"
    );

    // (3) Same connection, GUC now reset to '' post-commit. A bare query
    // must fall back to PERMISSIVE (NULLIF('')→NULL → first clause true),
    // NOT deny — otherwise enabling RLS would break every un-wired query
    // sharing a recycled connection.
    let after_reset: i64 = sqlx::query_scalar("SELECT count(*) FROM rls_perm_probe")
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(
        after_reset, 3,
        "reset-to-empty GUC must be permissive, not deny (pooling safety for incremental rollout)"
    );

    let _ = su.execute("DROP TABLE IF EXISTS rls_perm_probe;").await;
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {PERM_ROLE};").as_str())
        .await;
}

const WF_ROLE: &str = "talos_wf_rls_app";

/// RFC 0004 M4 workflows step 2: the PERMISSIVE policy on the real
/// `workflows` table — an un-wired path (no GUC) sees all (non-breaking,
/// e.g. the engine's graph-load), while a wired/scoped read enforces the
/// union. Validated on the actual table+migration under a non-superuser
/// role.
#[tokio::test]
async fn workflows_permissive_rls_unscoped_sees_all_scoped_enforces() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
    let su = connect(&su_url).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    // Unique names so the assertions ignore any seeded workflows.
    let name_a = format!("wfa-{}", user_a.simple());
    let name_b = format!("wfb-{}", user_b.simple());

    su.execute(
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{WF_ROLE}') THEN \
               CREATE ROLE {WF_ROLE} LOGIN PASSWORD '{APP_PW}'; END IF; END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create wf role");
    su.execute(format!("GRANT SELECT, INSERT ON workflows TO {WF_ROLE};").as_str())
        .await
        .expect("grant");
    for (u, label) in [(user_a, "wa"), (user_b, "wb")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .expect("insert user");
    }
    // org_id NULL → the user_id clause carries (sufficient for the READ asserts).
    for (u, n) in [(user_a, &name_a), (user_b, &name_b)] {
        sqlx::query(
            "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
             VALUES (gen_random_uuid(), $1, $2, '', '{}')",
        )
        .bind(u)
        .bind(n)
        .execute(&su)
        .await
        .expect("insert workflow");
    }
    // Two orgs for the org-based WRITE-side (WITH CHECK) assertions below
    // (workflows.org_id FKs organizations).
    for (o, owner) in [(org_a, user_a), (org_b, user_b)] {
        sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1,$2,$3,$4)")
            .bind(o)
            .bind(format!("org-{}", o.simple()))
            .bind(format!("org-{}", o.simple()))
            .bind(owner)
            .execute(&su)
            .await
            .expect("insert org");
    }

    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = connect(&format!("postgres://{WF_ROLE}:{APP_PW}@{after_at}")).await;

    // Un-wired path (no GUC) → permissive → sees BOTH (non-breaking).
    let unscoped: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE name IN ($1, $2)")
        .bind(&name_a)
        .bind(&name_b)
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(
        unscoped, 2,
        "un-wired path must be permissive (engine/scheduler don't break)"
    );

    // Wired/scoped to user A → enforced → sees only A's.
    let mut tx = begin_tenant_read_scoped(&app, &TenantReadScope::new(user_a, vec![]))
        .await
        .unwrap();
    let scoped: Vec<String> =
        sqlx::query_scalar("SELECT name FROM workflows WHERE name IN ($1, $2)")
            .bind(&name_a)
            .bind(&name_b)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scoped,
        vec![name_a.clone()],
        "scoped read must enforce — only A's workflow"
    );

    // WRITE-side (WITH CHECK, ORG-based per migration 20260602120000): under
    // ORG A's write scope (begin_org_scoped → app.current_org_id), a write into
    // the active org is permitted, but a write that would place the row in a
    // DIFFERENT org (B) is rejected. (The wired create/update mutations rely on
    // this once enforcement is flipped on.)
    let mut tx_ok = begin_org_scoped(&app, &OrgScope::new(org_a, user_a))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES (gen_random_uuid(), $1, $2, $3, '', '{}')",
    )
    .bind(user_a)
    .bind(org_a)
    .bind(format!("okw-{}", org_a.simple()))
    .execute(&mut *tx_ok)
    .await
    .expect("a write into the active org must be permitted");
    tx_ok.commit().await.unwrap();

    let evil_name = format!("evil-{}", org_b.simple());
    let mut tx_w = begin_org_scoped(&app, &OrgScope::new(org_a, user_a))
        .await
        .unwrap();
    let rejected = sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES (gen_random_uuid(), $1, $2, $3, '', '{}')",
    )
    .bind(user_a)
    .bind(org_b)
    .bind(&evil_name)
    .execute(&mut *tx_w)
    .await;
    assert!(
        rejected.is_err(),
        "RLS WITH CHECK must reject inserting a workflow into a different org"
    );
    let _ = tx_w.rollback().await;

    // Cleanup — workflows (FK org_id/user_id) before orgs/users. Deleting by
    // user_id covers name_a/name_b (org-less) + the committed org-A "okw" row;
    // evil_name was rolled back. (`evil_name` kept above for the failed insert.)
    let _ = &evil_name;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM workflows WHERE user_id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
    for o in [org_a, org_b] {
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(o)
            .execute(&su)
            .await;
    }
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {WF_ROLE};").as_str())
        .await;
}

const SECRETS_ROLE: &str = "talos_secrets_rls_app";

/// RFC 0004/0005 S2: `secrets` permissive policy — an un-wired path (no
/// GUC, e.g. the execution-time decrypt path) sees all (non-breaking),
/// while a wired/scoped metadata read enforces the ownership/org match.
/// secrets is owned via owner_user_id/created_by (not a `user_id` column).
#[tokio::test]
async fn secrets_permissive_rls_unscoped_sees_all_scoped_enforces() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
    let su = connect(&su_url).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let kp_a = format!("ka-{}", user_a.simple());
    let kp_b = format!("kb-{}", user_b.simple());

    su.execute(
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{SECRETS_ROLE}') THEN \
               CREATE ROLE {SECRETS_ROLE} LOGIN PASSWORD '{APP_PW}'; END IF; END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create secrets role");
    su.execute(format!("GRANT SELECT ON secrets TO {SECRETS_ROLE};").as_str())
        .await
        .expect("grant");
    for (u, label) in [(user_a, "sa"), (user_b, "sb")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .expect("insert user");
    }
    let key_id: Uuid =
        sqlx::query_scalar("INSERT INTO encryption_keys (encrypted_key) VALUES ($1) RETURNING id")
            .bind(vec![0u8, 1, 2])
            .fetch_one(&su)
            .await
            .expect("insert key");
    for (u, kp) in [(user_a, &kp_a), (user_b, &kp_b)] {
        sqlx::query(
            "INSERT INTO secrets (name, key_path, encrypted_value, encryption_key_id, owner_user_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(kp)
        .bind(kp)
        .bind(vec![9u8])
        .bind(key_id)
        .bind(u)
        .execute(&su)
        .await
        .expect("insert secret");
    }

    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = connect(&format!("postgres://{SECRETS_ROLE}:{APP_PW}@{after_at}")).await;

    // Un-wired (no GUC) → permissive → both (decrypt path doesn't break).
    let unscoped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path IN ($1,$2)")
            .bind(&kp_a)
            .bind(&kp_b)
            .fetch_one(&app)
            .await
            .unwrap();
    assert_eq!(
        unscoped, 2,
        "un-wired secrets read must be permissive (decrypt path)"
    );

    // Wired/scoped to user A → only A's (owner_user_id clause).
    let mut tx = begin_tenant_read_scoped(&app, &TenantReadScope::new(user_a, vec![]))
        .await
        .unwrap();
    let scoped: Vec<String> =
        sqlx::query_scalar("SELECT key_path FROM secrets WHERE key_path IN ($1,$2)")
            .bind(&kp_a)
            .bind(&kp_b)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scoped,
        vec![kp_a.clone()],
        "scoped secrets read must enforce — only A's"
    );

    let _ = sqlx::query("DELETE FROM secrets WHERE key_path IN ($1,$2)")
        .bind(&kp_a)
        .bind(&kp_b)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM encryption_keys WHERE id = $1")
        .bind(key_id)
        .execute(&su)
        .await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {SECRETS_ROLE};").as_str())
        .await;
}

const EXEC_ROLE: &str = "talos_wfexec_rls_app";

/// RFC 0004/0005 S2: `workflow_executions` permissive policy. The
/// critical case is an org MEMBER (not the owner) reading a teammate's
/// execution on an org-shared workflow — the policy must permit it via
/// the EXISTS-on-parent-workflow clause (NOT we.org_id, which is the
/// triggerer's personal org / NULL and would wrongly hide the row). A
/// stranger sees nothing; an un-wired path sees all (engine writes
/// non-breaking).
#[tokio::test]
async fn workflow_executions_permissive_rls_member_sees_shared_stranger_blocked() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
    let su = connect(&su_url).await;
    let owner = Uuid::new_v4();
    let teammate = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let team_org = Uuid::new_v4();
    let wf = Uuid::new_v4();
    let exec_owner = Uuid::new_v4();
    let exec_mate = Uuid::new_v4();

    su.execute(
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{EXEC_ROLE}') THEN \
               CREATE ROLE {EXEC_ROLE} LOGIN PASSWORD '{APP_PW}'; END IF; END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create exec role");
    // The policy's EXISTS clause reads `workflows`, so the role needs
    // SELECT on both (workflows is itself RLS-enabled — the subquery
    // composes with its policy under the same GUC).
    su.execute(format!("GRANT SELECT ON workflow_executions TO {EXEC_ROLE};").as_str())
        .await
        .expect("grant exec");
    su.execute(format!("GRANT SELECT ON workflows TO {EXEC_ROLE};").as_str())
        .await
        .expect("grant wf");

    for (u, label) in [(owner, "wo"), (teammate, "wm"), (stranger, "ws")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .expect("insert user");
    }
    sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1,$2,$3,$4)")
        .bind(team_org)
        .bind("team")
        .bind(format!("team-{}", team_org.simple()))
        .bind(owner)
        .execute(&su)
        .await
        .expect("insert org");
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'shared-wf', 'mod://x', '{}'::jsonb)",
    )
    .bind(wf)
    .bind(owner)
    .bind(team_org)
    .execute(&su)
    .await
    .expect("insert workflow");
    for (eid, u) in [(exec_owner, owner), (exec_mate, teammate)] {
        sqlx::query(
            "INSERT INTO workflow_executions (id, workflow_id, user_id, status) \
             VALUES ($1, $2, $3, 'completed')",
        )
        .bind(eid)
        .bind(wf)
        .bind(u)
        .execute(&su)
        .await
        .expect("insert execution");
    }

    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = connect(&format!("postgres://{EXEC_ROLE}:{APP_PW}@{after_at}")).await;

    // Un-wired (no GUC) → permissive → both (engine writes non-breaking).
    let unscoped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE id IN ($1,$2)")
            .bind(exec_owner)
            .bind(exec_mate)
            .fetch_one(&app)
            .await
            .unwrap();
    assert_eq!(unscoped, 2, "un-wired execution read must be permissive");

    // Scoped as the TEAMMATE (member of team_org, NOT the owner). Must
    // see BOTH: exec_mate via user_id, exec_owner via the EXISTS clause
    // (workflow shared to team_org). This is the regression the
    // we.org_id-keyed shape would have caused.
    let mut tx = begin_tenant_read_scoped(&app, &TenantReadScope::new(teammate, vec![team_org]))
        .await
        .unwrap();
    let mate_sees: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE id IN ($1,$2)")
            .bind(exec_owner)
            .bind(exec_mate)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        mate_sees, 2,
        "org member must see a teammate's execution on an org-shared workflow (EXISTS clause)"
    );

    // Scoped as a STRANGER (no membership in team_org) → sees NEITHER.
    let lonely_org = Uuid::new_v4();
    let mut tx = begin_tenant_read_scoped(&app, &TenantReadScope::new(stranger, vec![lonely_org]))
        .await
        .unwrap();
    let stranger_sees: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE id IN ($1,$2)")
            .bind(exec_owner)
            .bind(exec_mate)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        stranger_sees, 0,
        "stranger must see no executions (IDOR backstop)"
    );

    let _ = sqlx::query("DELETE FROM workflow_executions WHERE id IN ($1,$2)")
        .bind(exec_owner)
        .bind(exec_mate)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(wf)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(team_org)
        .execute(&su)
        .await;
    for u in [owner, teammate, stranger] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {EXEC_ROLE};").as_str())
        .await;
}

const ACTORS_ROLE: &str = "talos_actors_rls_app";

/// RFC 0004/0005 S2: `actors` permissive policy. Actors are personal —
/// an un-wired internal reader (engine apply_actor_to_engine, scheduler)
/// sees all (non-breaking), while a wired/scoped read enforces the owner
/// match so one user never sees another's actor.
#[tokio::test]
async fn actors_permissive_rls_unscoped_sees_all_scoped_enforces() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let _ddl_guard = DDL_LOCK.lock().await;
    let su = connect(&su_url).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let actor_a = Uuid::new_v4();
    let actor_b = Uuid::new_v4();

    su.execute(
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{ACTORS_ROLE}') THEN \
               CREATE ROLE {ACTORS_ROLE} LOGIN PASSWORD '{APP_PW}'; END IF; END $$;"
        )
        .as_str(),
    )
    .await
    .expect("create actors role");
    su.execute(format!("GRANT SELECT ON actors TO {ACTORS_ROLE};").as_str())
        .await
        .expect("grant");
    for (u, label) in [(user_a, "aa"), (user_b, "ab")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .expect("insert user");
    }
    for (aid, u) in [(actor_a, user_a), (actor_b, user_b)] {
        sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'a')")
            .bind(aid)
            .bind(u)
            .execute(&su)
            .await
            .expect("insert actor");
    }

    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = connect(&format!("postgres://{ACTORS_ROLE}:{APP_PW}@{after_at}")).await;

    // Un-wired (no GUC) → permissive → both (engine reader non-breaking).
    let unscoped: i64 = sqlx::query_scalar("SELECT count(*) FROM actors WHERE id IN ($1,$2)")
        .bind(actor_a)
        .bind(actor_b)
        .fetch_one(&app)
        .await
        .unwrap();
    assert_eq!(unscoped, 2, "un-wired actors read must be permissive");

    // Wired/scoped to user A → only A's actor (owner clause).
    let mut tx = begin_user_scoped(&app, user_a).await.unwrap();
    let scoped: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM actors WHERE id IN ($1,$2)")
        .bind(actor_a)
        .bind(actor_b)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        scoped,
        vec![actor_a],
        "scoped actors read must enforce — only A's"
    );

    let _ = sqlx::query("DELETE FROM actors WHERE id IN ($1,$2)")
        .bind(actor_a)
        .bind(actor_b)
        .execute(&su)
        .await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
    let _ = su
        .execute(format!("DROP ROLE IF EXISTS {ACTORS_ROLE};").as_str())
        .await;
}

/// RFC 0005 S3 headline: `SET LOCAL ROLE talos_app` activates RLS even
/// when the underlying connection is a SUPERUSER (the common in-cluster
/// Postgres deploy). This is the whole point of the SET-ROLE model — RLS
/// enforcement without provisioning separate login credentials. The test
/// connects as the superuser test role and proves a scoped tx under
/// `talos_app` cannot see another user's workflow, while the bare
/// superuser connection (no SET ROLE) bypasses RLS as expected.
#[tokio::test]
async fn set_role_talos_app_enforces_rls_under_superuser_connection() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let su = connect(&su_url).await;
    use sqlx::Executor as _;

    // Migration invariant: talos_app exists and is NOSUPERUSER NOBYPASSRLS.
    let role: Option<(bool, bool)> =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'talos_app'")
            .fetch_optional(&su)
            .await
            .unwrap();
    let (is_super, bypass) = role.expect("talos_app role must exist (migration 20260529220000)");
    assert!(
        !is_super && !bypass,
        "talos_app must be NOSUPERUSER + NOBYPASSRLS or SET ROLE would not enforce RLS"
    );

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let wf = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x','sra')")
        .bind(user_a)
        .bind(format!("sra-{}@test.invalid", user_a.simple()))
        .execute(&su)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES ($1, $2, 'sr-wf', 'mod://x', '{}'::jsonb)",
    )
    .bind(wf)
    .bind(user_a)
    .execute(&su)
    .await
    .unwrap();

    // Bare superuser connection (no SET ROLE) → bypasses RLS → sees the row.
    let su_sees: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&su)
        .await
        .unwrap();
    assert_eq!(su_sees, 1, "bare superuser must bypass RLS (control)");

    // SET LOCAL ROLE talos_app + scope to user B → RLS enforces → row hidden.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; \
                 SET LOCAL app.current_user_id = '{user_b}'; \
                 SET LOCAL app.current_org_ids = ''"
            )
            .as_str(),
        )
        .await
        .unwrap();
    let b_sees: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        b_sees, 0,
        "SET ROLE talos_app must activate RLS — B cannot see A's workflow even on a superuser connection"
    );

    // Same, scoped to the owner A → visible (positive control).
    let mut tx = su.begin().await.unwrap();
    (&mut *tx)
        .execute(
            format!(
                "SET LOCAL ROLE talos_app; \
                 SET LOCAL app.current_user_id = '{user_a}'; \
                 SET LOCAL app.current_org_ids = ''"
            )
            .as_str(),
        )
        .await
        .unwrap();
    let a_sees: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        a_sees, 1,
        "owner must see own workflow under SET ROLE talos_app"
    );

    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(wf)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_a)
        .execute(&su)
        .await;
}

/// RFC 0005 S3: a [`UnitOfWork`] sets the tenant scope ONCE and shares it
/// across every call on `conn()`, and a data-access function that takes
/// `&mut sqlx::PgConnection` composes into it (the executor-threading
/// convention the repository layer migrates toward). Deterministic — does
/// not depend on the SET-ROLE flag (enforcement is proven separately).
#[tokio::test]
async fn unit_of_work_shares_scope_across_calls() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let pool = connect(&su_url).await;
    let user = Uuid::new_v4();

    let mut uow = UnitOfWork::begin(&pool, &TenantReadScope::new(user, Vec::new()))
        .await
        .expect("begin unit of work");

    // The GUC is set once and visible to a query on the shared conn …
    let g1: Option<String> =
        sqlx::query_scalar("SELECT current_setting('app.current_user_id', true)")
            .fetch_one(uow.conn())
            .await
            .unwrap();
    assert_eq!(g1.as_deref(), Some(user.to_string()).as_deref());

    // … and to a SECOND call on the same unit of work (one tx, one scope).
    async fn read_scoped_uid(conn: &mut sqlx::PgConnection) -> Option<String> {
        sqlx::query_scalar("SELECT current_setting('app.current_user_id', true)")
            .fetch_one(conn)
            .await
            .unwrap()
    }
    let g2 = read_scoped_uid(uow.conn()).await;
    assert_eq!(g2.as_deref(), Some(user.to_string()).as_deref());

    uow.commit().await.expect("commit unit of work");
}

/// RFC 0005 S3 — write-path enforcement under `SET LOCAL ROLE talos_app`.
/// Migration 20260602120000 added an explicit ORG-based `WITH CHECK` to the
/// org-scoped policies (workflows/secrets/actors): a write must land in the
/// SINGLE active org (`app.current_org_id`, set by `begin_org_scoped`) — or be
/// org-less, or made on an un-wired path (write-GUC unset → rollout-safe
/// permit). This proves the consequence that gates the enforcement flip: a
/// write into the active org succeeds, and a write that would place a row in
/// ANOTHER org is rejected by the policy (SQLSTATE 42501) — even though the
/// underlying connection is a superuser.
///
/// NOTE (contract): the org-scoped WITH CHECK pins `org_id` to the active org,
/// NOT `user_id` — pinning user_id would break the org-scoped write path (which
/// sets `app.current_org_id`, not `app.current_user_id`). Org-level isolation is
/// the RLS boundary here; the app layer sets `user_id`.
#[tokio::test]
async fn set_role_with_check_gates_cross_tenant_writes() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let su = connect(&su_url).await;
    use sqlx::Executor as _;

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let wf_ok = Uuid::new_v4();
    let wf_bad = Uuid::new_v4();
    for (u, label) in [(user_a, "wca"), (user_b, "wcb")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .unwrap();
    }
    // Two orgs (workflows.org_id FKs organizations). owner_id is irrelevant to
    // the WITH CHECK (it pins org_id, not ownership); just satisfy NOT NULL.
    for (o, owner) in [(org_a, user_a), (org_b, user_b)] {
        sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1,$2,$3,$4)")
            .bind(o)
            .bind(format!("org-{}", o.simple()))
            .bind(format!("org-{}", o.simple()))
            .bind(owner)
            .execute(&su)
            .await
            .unwrap();
    }

    // Scoped to ORG A, INSERT a workflow into ORG A → satisfies the org-based WITH CHECK.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx)
        .execute(
            format!("SET LOCAL ROLE talos_app; SET LOCAL app.current_org_id = '{org_a}'").as_str(),
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'ok', 'mod://x', '{}'::jsonb)",
    )
    .bind(wf_ok)
    .bind(user_a)
    .bind(org_a)
    .execute(&mut *tx)
    .await
    .expect("a write into the active org must satisfy the policy");
    tx.commit().await.unwrap();

    // Scoped to ORG A, INSERT a workflow into ORG B → violates the WITH CHECK.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx)
        .execute(
            format!("SET LOCAL ROLE talos_app; SET LOCAL app.current_org_id = '{org_a}'").as_str(),
        )
        .await
        .unwrap();
    let res = sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'bad', 'mod://x', '{}'::jsonb)",
    )
    .bind(wf_bad)
    .bind(user_a)
    .bind(org_b)
    .execute(&mut *tx)
    .await;
    assert!(
        res.is_err(),
        "writing a workflow into a DIFFERENT org under SET ROLE must be rejected by the WITH CHECK"
    );
    if let Err(sqlx::Error::Database(dbe)) = &res {
        assert_eq!(
            dbe.code().as_deref(),
            Some("42501"),
            "expected a row-level-security WITH CHECK violation (42501)"
        );
    }
    let _ = tx.rollback().await;

    // Cleanup (wf_bad never committed).
    let _ = sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(wf_ok)
        .execute(&su)
        .await;
    for o in [org_a, org_b] {
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(o)
            .execute(&su)
            .await;
    }
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
}

/// RFC 0006 decision (b) — the `secrets` owner pin applies to PERSONAL secrets
/// only (`org_id IS NULL`); ORG-SHARED secrets are collaborative (org pin +
/// membership/RBAC), like `workflows`/`actors`. Proves all three:
///   1. personal secret owned by the acting user        → permitted (owner pin)
///   2. personal secret owned by a DIFFERENT user       → REJECTED (owner pin)
///   3. org-shared secret owned by a DIFFERENT member   → permitted (owner pin
///      skipped for org_id IS NOT NULL; org pin satisfied)
///   4. a workflow with a different user_id under the org scope → permitted
///      (org-pinned only, unchanged)
///
/// Sets role + GUCs by hand (like `set_role_with_check_gates_cross_tenant_writes`)
/// so the WITH CHECK enforces deterministically regardless of
/// `TALOS_RLS_SET_ROLE`. Personal cases set only `app.current_user_id` (no active
/// org, as `begin_user_scoped` does); the org-shared case sets
/// `app.current_org_id` too (as `begin_org_scoped` does).
#[tokio::test]
async fn secrets_owner_pin_is_personal_only_org_shared_is_collaborative() {
    let Some(su_url) = superuser_url() else {
        return;
    };
    let su = connect(&su_url).await;
    use sqlx::Executor as _;

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let org_a = Uuid::new_v4();
    let ek = Uuid::new_v4();

    for (u, label) in [(user_a, "soa"), (user_b, "sob")] {
        sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,'x',$3)")
            .bind(u)
            .bind(format!("{label}-{}@test.invalid", u.simple()))
            .bind(label)
            .execute(&su)
            .await
            .unwrap();
    }
    // Single org; BOTH users are owners so the org pin passes for either owner_user_id.
    sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1,$2,$3,$4)")
        .bind(org_a)
        .bind(format!("org-{}", org_a.simple()))
        .bind(format!("org-{}", org_a.simple()))
        .bind(user_a)
        .execute(&su)
        .await
        .unwrap();
    // secrets.encryption_key_id is a NOT NULL FK — create a key to satisfy it so
    // the INSERT reaches the WITH CHECK rather than failing on the FK.
    sqlx::query("INSERT INTO encryption_keys (id, encrypted_key) VALUES ($1, ''::bytea)")
        .bind(ek)
        .execute(&su)
        .await
        .unwrap();

    // Personal scope: acting user, NO active org (as begin_user_scoped emits).
    let scope_personal =
        format!("SET LOCAL ROLE talos_app; SET LOCAL app.current_user_id = '{user_a}'");
    // Org scope: active org + acting user (as begin_org_scoped emits).
    let scope_org =
        format!("SET LOCAL ROLE talos_app; SET LOCAL app.current_org_id = '{org_a}'; SET LOCAL app.current_user_id = '{user_a}'");

    // 1. PERSONAL secret (org_id NULL) owned by user_a → owner pin satisfied.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx).execute(scope_personal.as_str()).await.unwrap();
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, owner_user_id, created_by, org_id) \
         VALUES ($1, 's', 'sec/personal-own', ''::bytea, $2, $3, $3, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(ek)
    .bind(user_a)
    .execute(&mut *tx)
    .await
    .expect("a personal secret owned by the acting user must satisfy the owner pin");
    tx.commit().await.unwrap();

    // 2. PERSONAL secret (org_id NULL) owned by user_b → owner pin REJECTS.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx).execute(scope_personal.as_str()).await.unwrap();
    let res = sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, owner_user_id, created_by, org_id) \
         VALUES ($1, 's', 'sec/personal-forge', ''::bytea, $2, $3, $3, NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(ek)
    .bind(user_b)
    .execute(&mut *tx)
    .await;
    assert!(
        res.is_err(),
        "user_a must NOT create a PERSONAL secret owned by user_b (owner pin)"
    );
    if let Err(sqlx::Error::Database(dbe)) = &res {
        assert_eq!(
            dbe.code().as_deref(),
            Some("42501"),
            "expected a row-level-security WITH CHECK violation (42501)"
        );
    }
    let _ = tx.rollback().await;

    // 3. ORG-SHARED secret (org_id = org_a) owned by user_b, written by member
    //    user_a → PERMITTED. Owner pin is skipped for org_id IS NOT NULL; the org
    //    pin (org_a = current_org_id) is satisfied. Collaborative, like workflows.
    let mut tx = su.begin().await.unwrap();
    (&mut *tx).execute(scope_org.as_str()).await.unwrap();
    sqlx::query(
        "INSERT INTO secrets (id, name, key_path, encrypted_value, encryption_key_id, owner_user_id, created_by, org_id) \
         VALUES ($1, 's', 'sec/org-shared', ''::bytea, $2, $3, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(ek)
    .bind(user_b) // different owner — allowed for an org-shared secret
    .bind(org_a)
    .execute(&mut *tx)
    .await
    .expect("an org-shared secret is org-pinned only — a member's write must succeed regardless of owner");
    tx.commit().await.unwrap();

    // 4. workflows stay ORG-PINNED ONLY: a workflow with a DIFFERENT user_id under
    //    the org scope must still succeed (collaboration is not user-pinned).
    let mut tx = su.begin().await.unwrap();
    (&mut *tx).execute(scope_org.as_str()).await.unwrap();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'collab', 'mod://x', '{}'::jsonb)",
    )
    .bind(Uuid::new_v4())
    .bind(user_b) // different user — allowed for org-shared workflows
    .bind(org_a)
    .execute(&mut *tx)
    .await
    .expect(
        "workflows are org-pinned only — a collaborative write with another user_id must succeed",
    );
    tx.commit().await.unwrap();

    // Cleanup.
    let _ = sqlx::query("DELETE FROM workflows WHERE org_id = $1")
        .bind(org_a)
        .execute(&su)
        .await;
    // created_by covers both the personal (org_id NULL) and org-shared rows.
    let _ = sqlx::query("DELETE FROM secrets WHERE created_by = $1 OR created_by = $2")
        .bind(user_a)
        .bind(user_b)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM encryption_keys WHERE id = $1")
        .bind(ek)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_a)
        .execute(&su)
        .await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(&su)
            .await;
    }
}

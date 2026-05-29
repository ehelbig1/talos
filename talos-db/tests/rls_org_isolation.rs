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
    let Some(su_url) = superuser_url() else { return };
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
    assert_eq!(unset, 3, "unset GUC must be permissive so un-wired paths don't break");

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
    let Some(su_url) = superuser_url() else { return };
    let su = connect(&su_url).await;
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
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
    // org_id NULL → the user_id clause carries (sufficient for this test).
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

    let after_at = su_url.rsplit_once('@').map(|(_, r)| r).unwrap_or(&su_url);
    let app = connect(&format!("postgres://{WF_ROLE}:{APP_PW}@{after_at}")).await;

    // Un-wired path (no GUC) → permissive → sees BOTH (non-breaking).
    let unscoped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE name IN ($1, $2)")
            .bind(&name_a)
            .bind(&name_b)
            .fetch_one(&app)
            .await
            .unwrap();
    assert_eq!(unscoped, 2, "un-wired path must be permissive (engine/scheduler don't break)");

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
    assert_eq!(scoped, vec![name_a.clone()], "scoped read must enforce — only A's workflow");

    // WRITE-side (WITH CHECK): under A's scope, inserting a workflow owned
    // by B is rejected — you can't write a row you don't own. (The wired
    // create/update/delete mutations rely on this once fail-closed.)
    let evil_name = format!("evil-{}", user_b.simple());
    let mut tx_w = begin_tenant_read_scoped(&app, &TenantReadScope::new(user_a, vec![]))
        .await
        .unwrap();
    let rejected = sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json) \
         VALUES (gen_random_uuid(), $1, $2, '', '{}')",
    )
    .bind(user_b)
    .bind(&evil_name)
    .execute(&mut *tx_w)
    .await;
    assert!(
        rejected.is_err(),
        "RLS WITH CHECK must reject inserting a workflow owned by another user"
    );
    let _ = tx_w.rollback().await;

    let _ = sqlx::query("DELETE FROM workflows WHERE name IN ($1,$2,$3)")
        .bind(&name_a)
        .bind(&name_b)
        .bind(&evil_name)
        .execute(&su)
        .await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(u).execute(&su).await;
    }
    let _ = su.execute(format!("DROP ROLE IF EXISTS {WF_ROLE};").as_str()).await;
}

const SECRETS_ROLE: &str = "talos_secrets_rls_app";

/// RFC 0004/0005 S2: `secrets` permissive policy — an un-wired path (no
/// GUC, e.g. the execution-time decrypt path) sees all (non-breaking),
/// while a wired/scoped metadata read enforces the ownership/org match.
/// secrets is owned via owner_user_id/created_by (not a `user_id` column).
#[tokio::test]
async fn secrets_permissive_rls_unscoped_sees_all_scoped_enforces() {
    let Some(su_url) = superuser_url() else { return };
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
    assert_eq!(unscoped, 2, "un-wired secrets read must be permissive (decrypt path)");

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
    assert_eq!(scoped, vec![kp_a.clone()], "scoped secrets read must enforce — only A's");

    let _ = sqlx::query("DELETE FROM secrets WHERE key_path IN ($1,$2)")
        .bind(&kp_a)
        .bind(&kp_b)
        .execute(&su)
        .await;
    let _ = sqlx::query("DELETE FROM encryption_keys WHERE id = $1").bind(key_id).execute(&su).await;
    for u in [user_a, user_b] {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(u).execute(&su).await;
    }
    let _ = su.execute(format!("DROP ROLE IF EXISTS {SECRETS_ROLE};").as_str()).await;
}

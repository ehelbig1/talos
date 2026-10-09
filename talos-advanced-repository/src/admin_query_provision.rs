//! Making, rotating and disabling `query_paginated`'s own database login —
//! the body of `controller admin-query-login provision | disable`, which
//! `scripts/setup-admin-query-login.sh` runs inside the controller's
//! container (it already holds `DATABASE_URL` and reaches the database in
//! every deployment shape).
//!
//! What it holds to:
//! * The password is 24 bytes from the operating system's random source,
//!   written as hex: nothing to escape in a URL, and nothing for SASLprep to
//!   change, so the verifier below is the one the server would compute.
//! * The password never reaches the database in plain text. The role is given
//!   a SCRAM-SHA-256 verifier computed here, so no statement text, server log
//!   line or `pg_stat_statements` row can carry it.
//! * Every refusal that can be known before the role is touched is checked
//!   first (the URL, the production TLS rule, the role the login joins).
//! * After the change commits, the login is used once through the same
//!   per-call checks the tool runs ([`crate::AdminQueryLogin`]); a login those
//!   checks refuse is reported, not handed out.
//!
//! See `docs/query-paginated-login.md` and
//! `docs/engineering-log/packages/2026-10-09-query-paginated-login-setup.md`.

use crate::{
    is_plain_role_name, AdminQueryLogin, AdvancedRepository, PaginationMode, QUERY_PAGINATED_ROLE,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use zeroize::Zeroizing;

/// The login `scripts/setup-admin-query-login.sh` makes for the tool.
pub const ADMIN_QUERY_LOGIN: &str = "talos_admin_query";

/// The SCRAM iteration count: Postgres's own default (`scram_iterations`,
/// 4096 on Postgres 16 and 17). A random 192-bit password needs no more.
const SCRAM_ITERATIONS: u32 = 4096;

/// The attributes the login is given, every time: LOGIN and nothing else.
const LOGIN_ATTRIBUTES: &str =
    "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT";

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    for part in data {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA-256 for one 32-byte block: SCRAM's `Hi()` (RFC 5802).
fn salted_password(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = Zeroizing::new(u);
    for _ in 1..iterations {
        u = hmac_sha256(password, &[&u]);
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    out
}

/// The SCRAM-SHA-256 verifier Postgres stores for `password`
/// (`SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, RFC 7677).
/// `password` must already be SASLprep-normalised; ASCII is.
pub fn scram_sha256_verifier(password: &str, salt: &[u8], iterations: u32) -> String {
    let salted = salted_password(password.as_bytes(), salt, iterations);
    let client_key = hmac_sha256(&salted[..], &[b"Client Key"]);
    let stored_key = Sha256::digest(client_key);
    let server_key = hmac_sha256(&salted[..], &[b"Server Key"]);
    format!(
        "SCRAM-SHA-256${iterations}:{}${}:{}",
        B64.encode(salt),
        B64.encode(stored_key),
        B64.encode(server_key)
    )
}

/// A fresh password: 24 random bytes as 48 hex characters.
pub fn generate_password() -> Zeroizing<String> {
    let bytes = Zeroizing::new(talos_random::bytes::<24>());
    let mut out = Zeroizing::new(String::with_capacity(48));
    for b in bytes.iter() {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 0x0f)]));
    }
    out
}

/// `database_url` with its user and password replaced by `login` and
/// `password`: the same host, port, database and parameters (`sslmode`), so
/// the login reaches the same database the controller does.
pub fn login_url(
    database_url: &str,
    login: &str,
    password: &str,
) -> Result<Zeroizing<String>, ProvisionError> {
    // The parse error is not kept: it may quote the URL, password and all.
    let Ok(mut url) = url::Url::parse(database_url) else {
        return Err(ProvisionError::DatabaseUrl("is not a URL"));
    };
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(ProvisionError::DatabaseUrl("is not a postgres:// URL"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(ProvisionError::DatabaseUrl("names no host"));
    }
    // A `user=` or `password=` parameter would win over the URL's own
    // credentials when the controller connects, and connect as someone else.
    if url
        .query_pairs()
        .any(|(k, _)| matches!(k.as_ref(), "user" | "password" | "passfile"))
    {
        return Err(ProvisionError::DatabaseUrl(
            "carries user, password or passfile parameters",
        ));
    }
    if url.set_username(login).is_err() || url.set_password(Some(password)).is_err() {
        return Err(ProvisionError::DatabaseUrl("cannot carry credentials"));
    }
    Ok(Zeroizing::new(url.into()))
}

/// The statements that make (or remake) the login. The password goes in and
/// only its verifier comes out: this is the one place a statement is written,
/// so no caller can hand the server the password itself. Pure, so a test can
/// hold that.
fn provision_statements(
    login: &str,
    password: &str,
    salt: &[u8],
    exists: bool,
) -> Result<[String; 2], ProvisionError> {
    let verifier = scram_sha256_verifier(password, salt, SCRAM_ITERATIONS);
    if !is_plain_role_name(login) || !is_verifier_text(&verifier) {
        return Err(ProvisionError::LoginName);
    }
    let verb = if exists { "ALTER" } else { "CREATE" };
    Ok([
        format!("{verb} ROLE \"{login}\" WITH {LOGIN_ATTRIBUTES} PASSWORD '{verifier}'"),
        format!("GRANT \"{QUERY_PAGINATED_ROLE}\" TO \"{login}\""),
    ])
}

/// A verifier is base64, digits and `$ : =` — nothing that could end the
/// string literal it is written into.
fn is_verifier_text(verifier: &str) -> bool {
    verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"+/=$:-".contains(&b))
}

/// What [`provision_login`] did.
pub struct ProvisionedLogin {
    /// The URL the controller connects as the login with
    /// (`TALOS_ADMIN_QUERY_DATABASE_URL`). A credential.
    pub url: Zeroizing<String>,
    /// Whether the login was made (`true`) or already existed and was given a
    /// new password (`false`).
    pub created: bool,
}

impl std::fmt::Debug for ProvisionedLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionedLogin")
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

/// Why the login could not be provisioned. Never carries the password or the
/// URL.
#[derive(Debug)]
pub enum ProvisionError {
    /// The login name is not a plain lower-case identifier.
    LoginName,
    /// `DATABASE_URL` cannot be turned into the login's URL.
    DatabaseUrl(&'static str),
    /// The login's URL would be refused by the tool (in production, no
    /// TLS-guaranteeing `sslmode`).
    Misconfigured(&'static str),
    /// The role the login joins does not exist yet.
    ReadRoleMissing,
    /// The database refused a statement (often: the controller's database
    /// user may not create or alter roles).
    Database(sqlx::Error),
    /// The login was made, but the tool's own per-call checks refuse it.
    Refused(String),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::LoginName => {
                f.write_str("the login name is not a plain lower-case identifier")
            }
            ProvisionError::DatabaseUrl(why) => write!(f, "DATABASE_URL {why}"),
            ProvisionError::Misconfigured(why) => {
                write!(f, "the login's URL would be refused: it {why}")
            }
            ProvisionError::ReadRoleMissing => write!(
                f,
                "the role {QUERY_PAGINATED_ROLE} does not exist; it is made by \
                 migrations/20261008200000_talos_admin_read_role.sql (see its header for a \
                 managed Postgres)"
            ),
            ProvisionError::Database(e) => write!(
                f,
                "the database refused it ({e}); the controller's database user needs CREATEROLE \
                 (or superuser) and the right to grant {QUERY_PAGINATED_ROLE}, or a superuser \
                 runs the statements in docs/query-paginated-login.md by hand"
            ),
            ProvisionError::Refused(why) => {
                write!(
                    f,
                    "the login was made, but query_paginated refuses it: {why}"
                )
            }
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<sqlx::Error> for ProvisionError {
    fn from(e: sqlx::Error) -> Self {
        ProvisionError::Database(e)
    }
}

/// Make `login` (or give it a new password if it exists), as the user
/// `pool` connects as, and return the URL it connects with.
///
/// The login gets [`LOGIN_ATTRIBUTES`] and membership in
/// [`QUERY_PAGINATED_ROLE`], in one transaction. Anything else it holds —
/// another membership, an object, a grant — is not removed: the closing check
/// refuses it and says so, and the operator decides.
pub async fn provision_login(
    pool: &PgPool,
    database_url: &str,
    login: &str,
    production: bool,
    statement_timeout_secs: u64,
) -> Result<ProvisionedLogin, ProvisionError> {
    if !is_plain_role_name(login) {
        return Err(ProvisionError::LoginName);
    }
    let password = generate_password();
    let url = login_url(database_url, login, &password)?;
    let tool_login = AdminQueryLogin::from_url(Some(&url), production, statement_timeout_secs);
    if let Some(why) = tool_login.misconfigured() {
        return Err(ProvisionError::Misconfigured(why));
    }
    let salt = talos_random::bytes::<16>();

    let mut tx = pool.begin().await?;
    let read_role: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)")
            .bind(QUERY_PAGINATED_ROLE)
            .fetch_one(&mut *tx)
            .await?;
    if !read_role {
        return Err(ProvisionError::ReadRoleMissing);
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)")
            .bind(login)
            .fetch_one(&mut *tx)
            .await?;
    for statement in provision_statements(login, &password, &salt, exists)? {
        // sql-safe: a plain lower-case role name checked above, the constant role name, and a SCRAM verifier made of base64 and `$:=` only (checked above); role DDL takes no bind parameters
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    // The same checks every call makes, once, now.
    let repo = AdvancedRepository::new(pool.clone()).with_admin_query_login(tool_login);
    if let Err(e) = repo
        .execute_paginated_select("SELECT 1 AS ok", 1, PaginationMode::Offset { offset: 0 })
        .await
    {
        return Err(ProvisionError::Refused(e.to_string()));
    }
    Ok(ProvisionedLogin {
        url,
        created: !exists,
    })
}

/// Take LOGIN away from `login`, so a URL that was handed out stops working.
/// Returns whether the login existed. Its membership and attributes are left,
/// so a later [`provision_login`] restores it.
pub async fn disable_login(pool: &PgPool, login: &str) -> Result<bool, ProvisionError> {
    if !is_plain_role_name(login) {
        return Err(ProvisionError::LoginName);
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)")
            .bind(login)
            .fetch_one(pool)
            .await?;
    if exists {
        // sql-safe: a plain lower-case role name checked above; role DDL takes no bind parameters
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER ROLE \"{login}\" NOLOGIN"
        )))
        .execute(pool)
        .await?;
    }
    Ok(exists)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Postgres 17.11 hashed `pencil-0123456789abcdef` (password_encryption
    /// = scram-sha-256) to this; the same salt and count must give the same
    /// verifier byte for byte.
    #[test]
    fn the_verifier_is_the_one_postgres_computes() {
        let postgres = "SCRAM-SHA-256$4096:PGx03V9dEzRV8/X5T/WIbA==$/G5/rBMAbb+ilQBapj2hzVZsZoSsSpmvX6SvdskMVdA=:NG0zH6Rd7bM8G+rKpXD1AxOTA/qXFhWL2CoBag911pY=";
        let salt = B64.decode("PGx03V9dEzRV8/X5T/WIbA==").unwrap();
        assert_eq!(
            scram_sha256_verifier("pencil-0123456789abcdef", &salt, 4096),
            postgres
        );
        assert!(is_verifier_text(postgres));
    }

    #[test]
    fn a_password_is_48_hex_characters_and_never_repeats() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 48);
        assert!(a
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(*a, *b);
    }

    #[test]
    fn the_login_url_keeps_the_database_and_replaces_the_credentials() {
        let url = login_url(
            "postgres://talos:pool-secret@db.internal:6543/talos?sslmode=require",
            "talos_admin_query",
            "abc123",
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "postgres://talos_admin_query:abc123@db.internal:6543/talos?sslmode=require"
        );
        assert!(!url.contains("pool-secret"));
    }

    #[test]
    fn a_database_url_that_cannot_carry_the_login_is_refused_without_quoting_it() {
        for bad in [
            "not a url with pool-secret",
            "mysql://talos:pool-secret@db/talos",
            "postgres:///talos?host=/run/postgresql&password=pool-secret",
            "postgres://talos:pool-secret@db/talos?user=other",
        ] {
            let err = login_url(bad, "talos_admin_query", "abc").unwrap_err();
            assert!(!err.to_string().contains("pool-secret"), "{err}");
        }
    }

    /// What is sent to the database names the verifier, never the password.
    #[test]
    fn the_statements_carry_the_verifier_and_not_the_password() {
        let password = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed";
        let salt = b"0123456789abcdef";
        let verifier = scram_sha256_verifier(password, salt, SCRAM_ITERATIONS);
        for exists in [false, true] {
            let statements =
                provision_statements("talos_admin_query", password, salt, exists).unwrap();
            let all = statements.join("\n");
            assert!(!all.contains(password), "{all}");
            assert!(all.contains(&verifier));
            assert!(statements[0].contains(LOGIN_ATTRIBUTES));
            assert!(statements[0].starts_with(if exists { "ALTER" } else { "CREATE" }));
            assert_eq!(
                statements[1],
                "GRANT \"talos_admin_read\" TO \"talos_admin_query\""
            );
        }
    }

    #[test]
    fn debug_never_shows_the_url() {
        let p = ProvisionedLogin {
            url: Zeroizing::new("postgres://u:s3cret@h/d".to_string()),
            created: true,
        };
        assert!(!format!("{p:?}").contains("s3cret"));
    }
}

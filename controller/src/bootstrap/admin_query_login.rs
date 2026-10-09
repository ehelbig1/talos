//! Which database login `query_paginated` runs on, decided once at start-up
//! (after migrations, before the router is built): the environment and the
//! KEK-derived password, handed to
//! `talos_advanced_repository::admin_query_provision::resolve_startup_login`,
//! which holds the rules. See docs/query-paginated-login.md.
use talos_advanced_repository::admin_query_provision::{
    resolve_startup_login, StartupInputs, ADMIN_QUERY_LOGIN,
};
use talos_advanced_repository::{
    AdminQueryLogin, AdminQueryLoginMode, ADMIN_QUERY_DATABASE_URL_VAR,
};

pub(crate) async fn resolve_admin_query_login(
    db_pool: &sqlx::PgPool,
    secrets_manager: &talos_secrets_manager::SecretsManager,
) -> AdminQueryLogin {
    let database_url = std::env::var("DATABASE_URL").ok();
    let inputs = StartupInputs {
        explicit_url_set: talos_config::read_env_or_file(ADMIN_QUERY_DATABASE_URL_VAR).is_some(),
        mode: AdminQueryLoginMode::from_env(),
        database_url: database_url.as_deref(),
        production: crate::config::is_production(),
        statement_timeout_secs: talos_db::statement_timeout_secs(),
    };
    resolve_startup_login(
        db_pool,
        inputs,
        ADMIN_QUERY_LOGIN,
        secrets_manager.admin_query_login_password(),
    )
    .await
}

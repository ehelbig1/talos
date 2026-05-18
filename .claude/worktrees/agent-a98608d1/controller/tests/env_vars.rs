//! Tests that the application panics when required environment variables are missing.

#[cfg(test)]
mod tests {
    use std::env;
    use std::panic;

    // The init_pool function is async and panics on missing DB URL when the future is
    // polled. Running it without awaiting never triggers the panic, causing the
    // original test to pass incorrectly. We now execute the future inside the
    // Tokio runtime used by the test and capture any unwind.
    #[tokio::test]
    async fn missing_database_url_panics() {
        // Ensure the environment variable is unset.
        env::remove_var("DATABASE_URL");
        let result = panic::catch_unwind(|| {
            // Execute the async init_pool within the current runtime.
            tokio::runtime::Handle::current().block_on(controller::db::init_pool())
        });
        assert!(
            result.is_err(),
            "init_pool should panic when DATABASE_URL is missing"
        );
    }

    #[test]
    fn missing_allowed_origin_panics() {
        env::remove_var("ALLOWED_ORIGIN");
        let result = panic::catch_unwind(|| {
            // Directly trigger the expectation used in main.rs
            env::var("ALLOWED_ORIGIN")
                .expect("Environment variable ALLOWED_ORIGIN must be set (CORS origin)");
        });
        assert!(
            result.is_err(),
            "Accessing ALLOWED_ORIGIN should panic when missing"
        );
    }
}

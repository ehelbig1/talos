#[cfg(test)]
mod tests {
    use crate::metrics::*;

    // ========================================================================
    // normalize_status tests
    // ========================================================================

    #[test]
    fn test_normalize_status_known_values() {
        assert_eq!(normalize_status("success"), "success");
        assert_eq!(normalize_status("error"), "error");
        assert_eq!(normalize_status("timeout"), "timeout");
        assert_eq!(normalize_status("retry_exhausted"), "retry_exhausted");
        assert_eq!(normalize_status("out_of_fuel"), "out_of_fuel");
        assert_eq!(normalize_status("trap"), "trap");
        assert_eq!(normalize_status("memory_limit"), "memory_limit");
    }

    #[test]
    fn test_normalize_status_unknown_defaults_to_other() {
        assert_eq!(normalize_status("unknown_status"), "other");
        assert_eq!(normalize_status("random"), "other");
        assert_eq!(normalize_status(""), "other");
    }

    // ========================================================================
    // normalize_error_type tests
    // ========================================================================

    #[test]
    fn test_normalize_error_type_known_values() {
        assert_eq!(normalize_error_type("timeout"), "timeout");
        assert_eq!(normalize_error_type("out_of_fuel"), "out_of_fuel");
        assert_eq!(normalize_error_type("trap"), "trap");
        assert_eq!(normalize_error_type("memory_limit"), "memory_limit");
        assert_eq!(normalize_error_type("runtime_error"), "runtime_error");
        assert_eq!(normalize_error_type("module_error"), "module_error");
        assert_eq!(
            normalize_error_type("retries_exhausted"),
            "retries_exhausted"
        );
        assert_eq!(normalize_error_type("network_error"), "network_error");
        assert_eq!(normalize_error_type("cache_error"), "cache_error");
    }

    #[test]
    fn test_normalize_error_type_unknown_defaults_to_other() {
        assert_eq!(normalize_error_type("custom_error"), "other");
        assert_eq!(normalize_error_type(""), "other");
    }

    // ========================================================================
    // normalize_retry_reason tests
    // ========================================================================

    #[test]
    fn test_normalize_retry_reason_known_values() {
        assert_eq!(normalize_retry_reason("transient_error"), "transient_error");
        assert_eq!(normalize_retry_reason("network_error"), "network_error");
        assert_eq!(normalize_retry_reason("timeout"), "timeout");
        assert_eq!(normalize_retry_reason("rate_limit"), "rate_limit");
        assert_eq!(
            normalize_retry_reason("service_unavailable"),
            "service_unavailable"
        );
    }

    #[test]
    fn test_normalize_retry_reason_unknown_defaults_to_other() {
        assert_eq!(normalize_retry_reason("some_reason"), "other");
    }

    // ========================================================================
    // normalize_rate_limit_function tests
    // ========================================================================

    #[test]
    fn test_normalize_rate_limit_function_known_values() {
        assert_eq!(normalize_rate_limit_function("http"), "http");
        assert_eq!(normalize_rate_limit_function("db"), "db");
        assert_eq!(normalize_rate_limit_function("messaging"), "messaging");
        assert_eq!(normalize_rate_limit_function("log"), "log");
        assert_eq!(normalize_rate_limit_function("fs"), "fs");
    }

    #[test]
    fn test_normalize_rate_limit_function_unknown_defaults_to_other() {
        assert_eq!(normalize_rate_limit_function("custom"), "other");
    }

    // ========================================================================
    // normalize_approval_decision tests
    // ========================================================================

    #[test]
    fn test_normalize_approval_decision_known_values() {
        assert_eq!(normalize_approval_decision("approved"), "approved");
        assert_eq!(normalize_approval_decision("denied"), "denied");
    }

    #[test]
    fn test_normalize_approval_decision_unknown_defaults_to_other() {
        assert_eq!(normalize_approval_decision("pending"), "other");
    }

    // ========================================================================
    // normalize_llm_provider tests
    // ========================================================================

    #[test]
    fn test_normalize_llm_provider_known_values() {
        assert_eq!(normalize_llm_provider("anthropic"), "anthropic");
        assert_eq!(normalize_llm_provider("openai"), "openai");
        assert_eq!(normalize_llm_provider("gemini"), "gemini");
    }

    #[test]
    fn test_normalize_llm_provider_unknown_defaults_to_other() {
        assert_eq!(normalize_llm_provider("ollama"), "other");
    }

    // ========================================================================
    // normalize_token_direction tests
    // ========================================================================

    #[test]
    fn test_normalize_token_direction_known_values() {
        assert_eq!(normalize_token_direction("input"), "input");
        assert_eq!(normalize_token_direction("output"), "output");
    }

    #[test]
    fn test_normalize_token_direction_unknown_defaults_to_other() {
        assert_eq!(normalize_token_direction("total"), "other");
    }

    // ========================================================================
    // normalize_quota_metric tests
    // ========================================================================

    #[test]
    fn test_normalize_quota_metric_known_values() {
        assert_eq!(normalize_quota_metric("http_calls"), "http_calls");
        assert_eq!(normalize_quota_metric("db_queries"), "db_queries");
        assert_eq!(
            normalize_quota_metric("messaging_publishes"),
            "messaging_publishes"
        );
        assert_eq!(normalize_quota_metric("fs_bytes"), "fs_bytes");
        assert_eq!(normalize_quota_metric("log_messages"), "log_messages");
        assert_eq!(normalize_quota_metric("memory_bytes"), "memory_bytes");
    }

    #[test]
    fn test_normalize_quota_metric_unknown_defaults_to_other() {
        assert_eq!(normalize_quota_metric("custom_metric"), "other");
    }

    // ========================================================================
    // normalize_host_function_name tests
    // ========================================================================

    #[test]
    fn test_normalize_host_function_name_known_values() {
        assert_eq!(normalize_host_function_name("http::fetch"), "http::fetch");
        assert_eq!(
            normalize_host_function_name("db::execute_query"),
            "db::execute_query"
        );
        assert_eq!(
            normalize_host_function_name("messaging::publish"),
            "messaging::publish"
        );
        assert_eq!(
            normalize_host_function_name("messaging::subscribe"),
            "messaging::subscribe"
        );
        assert_eq!(normalize_host_function_name("cache::get"), "cache::get");
        assert_eq!(normalize_host_function_name("cache::set"), "cache::set");
        assert_eq!(
            normalize_host_function_name("cache::delete"),
            "cache::delete"
        );
        assert_eq!(
            normalize_host_function_name("secrets::get_secret"),
            "secrets::get_secret"
        );
        assert_eq!(normalize_host_function_name("files::read"), "files::read");
        assert_eq!(normalize_host_function_name("files::write"), "files::write");
        assert_eq!(
            normalize_host_function_name("graphql::execute"),
            "graphql::execute"
        );
        assert_eq!(
            normalize_host_function_name("llm::complete"),
            "llm::complete"
        );
        assert_eq!(normalize_host_function_name("llm::stream"), "llm::stream");
        assert_eq!(normalize_host_function_name("email::send"), "email::send");
        assert_eq!(normalize_host_function_name("logging::log"), "logging::log");
    }

    #[test]
    fn test_normalize_host_function_name_unknown_defaults_to_other() {
        assert_eq!(normalize_host_function_name("custom::function"), "other");
        assert_eq!(normalize_host_function_name(""), "other");
    }
}

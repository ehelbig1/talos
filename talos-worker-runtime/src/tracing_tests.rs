#[cfg(test)]
mod tests {
    use crate::tracing::extract_trace_id;

    // ========================================================================
    // extract_trace_id tests
    // ========================================================================

    #[test]
    fn test_extract_trace_id_from_traceparent() {
        let headers = vec![(
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        )];
        assert_eq!(
            extract_trace_id(&headers),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string())
        );
    }

    #[test]
    fn test_extract_trace_id_from_x_trace_id() {
        let headers = vec![("X-Trace-Id".to_string(), "abc-123".to_string())];
        assert_eq!(extract_trace_id(&headers), Some("abc-123".to_string()));
    }

    #[test]
    fn test_extract_trace_id_not_found() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        assert_eq!(extract_trace_id(&headers), None);
    }

    #[test]
    fn test_extract_trace_id_empty_headers() {
        let headers: Vec<(String, String)> = vec![];
        assert_eq!(extract_trace_id(&headers), None);
    }

    #[test]
    fn test_extract_trace_id_case_insensitive() {
        let headers = vec![("TraceParent".to_string(), "upper-case-key".to_string())];
        assert_eq!(
            extract_trace_id(&headers),
            Some("upper-case-key".to_string())
        );
    }
}

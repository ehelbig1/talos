use crate::handlers::filter_events;
use serde_json::json;

#[test]
fn test_filter_events_by_keywords() {
    let events = vec![
        json!({"summary": "Meeting with Bob", "status": "confirmed"}),
        json!({"summary": "Lunch", "status": "confirmed"}),
    ];

    let config = json!({
        "FILTER_TITLE_KEYWORDS": ["meeting"]
    });

    let filtered = filter_events(&events, &config);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["summary"], "Meeting with Bob");
}

#[test]
fn test_filter_events_by_type() {
    let events = vec![
        json!({"summary": "A", "status": "confirmed"}),
        json!({"summary": "B", "status": "cancelled"}),
    ];

    let config = json!({
        "EVENT_TYPES": ["deleted"]
    });

    let filtered = filter_events(&events, &config);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["summary"], "B");
}

#[test]
fn test_filter_events_exclude_all_day() {
    let events = vec![
        json!({"summary": "Timed", "start": {"dateTime": "2024-01-01T10:00:00Z"}}),
        json!({"summary": "All Day", "start": {"date": "2024-01-01"}}),
    ];

    let config = json!({
        "EXCLUDE_ALL_DAY_EVENTS": true
    });

    let filtered = filter_events(&events, &config);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["summary"], "Timed");
}

#[test]
fn test_filter_events_empty_input() {
    let events = vec![];
    let config = json!({});
    let filtered = filter_events(&events, &config);
    assert!(filtered.is_empty());
}

#[tokio::test]
async fn test_webhook_channel_rate_limiting_logic() {
    let pool = sqlx::PgPool::connect_lazy("postgres://localhost/talos_test").unwrap();
    let service = super::GoogleCalendarService::new(pool);
    let channel_id = "test-channel-id";

    // 60 requests allowed per minute
    for _ in 0..60 {
        assert!(service.allow_webhook_channel(channel_id));
    }

    // 61st request should be rejected
    assert!(!service.allow_webhook_channel(channel_id));
}

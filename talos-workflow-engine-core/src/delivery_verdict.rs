//! The verdict a `notify-*` adapter returns, read as the engine reads it.
//!
//! `docs/notification-contract.md` ("What every adapter returns") fixes the
//! shape every sender of a phone notification answers with:
//!
//! ```jsonc
//! { "provider": "ntfy", "sent": true, "skipped": false, "dry_run": false,
//!   "status": 200, "parts_total": 1, "parts_sent": 1,
//!   "actions_sent": 2, "actions_dropped": 1, "one_tap_actions": 1,
//!   "kept_actions": 0, "link_sent": true, "link_dropped": false, "tag_sent": false }
//! ```
//!
//! That verdict is the only record of a message having been sent: the node's
//! output is encrypted at rest, and the adapter's HTTP call leaves nothing
//! behind. The engine reads it here at node completion and records a
//! `message_deliveries` row for a send that happened, so a report can count
//! messages and set action-link taps against them.
//!
//! What this is and is not. It is a reading of the contract's documented
//! fields, bounded as the contract bounds them (six parts, three actions per
//! part), used for measurement. It is not a security control: an adapter that
//! lies about its counts inflates a report, as a module that emits
//! `__ops_alert__` can raise an alert. A send is recognised by the four
//! fields every adapter returns (`provider`, `sent`, `parts_total`,
//! `parts_sent`); an output without them is some other node's and is not a
//! send. Whether the run was a dry run is the ENGINE's knowledge
//! (`NodeCompletionContext::dry_run`) first and the adapter's `dry_run` word
//! second; either one means nothing was sent.
//!
//! `talos-catalog-tests/tests/notification_contract.rs` runs every adapter
//! and reads its real verdict through [`read_delivery_verdict`], so a change
//! to the contract block that this reader does not follow fails CI.

use serde_json::Value;

/// The longest `provider` word recorded (the column's bound).
pub const MAX_PROVIDER_CHARS: usize = 32;
/// More parts than any list the contract allows (six), with room for a
/// future widening; the column's bound.
pub const MAX_PARTS: u64 = 64;
/// More actions than 64 parts of three could carry; the column's bound.
pub const MAX_ACTIONS: u64 = 1024;

/// What one send node delivered, as its adapter reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryVerdict {
    /// The adapter's word for the service (`ntfy`, `home_assistant`, ...).
    pub provider: String,
    /// Notifications composed (a single notification is one).
    pub parts_total: u32,
    /// Notifications the service accepted; at least one.
    pub parts_sent: u32,
    /// Actions delivered across every part.
    pub actions_sent: u32,
    /// Actions delivered as a background POST (one tap acts).
    pub one_tap_actions: u32,
    /// Actions the service keeps the notification open for.
    pub kept_actions: u32,
}

/// What a node output says about a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryReading {
    /// A send happened: record it.
    Sent(DeliveryVerdict),
    /// The output is not an adapter's verdict: some other node's output.
    NotASend,
    /// An adapter answered, and nothing left it: a skip, a dry run, or a
    /// verdict with no part sent.
    NothingSent,
    /// An adapter answered with a verdict this reader will not record, and
    /// the one word that says why. A malformed verdict is counted, not
    /// written: a row that fails the table's CHECKs would be a failure with
    /// no reason attached.
    Malformed(&'static str),
}

/// Read a node output as the notification contract's verdict.
///
/// Recognition is by the four fields every adapter returns; the counts an
/// adapter may omit default to zero. Bounds are the contract's, so a verdict
/// outside them is `Malformed`, never clamped.
#[must_use]
pub fn read_delivery_verdict(output: &Value) -> DeliveryReading {
    let Some(map) = output.as_object() else {
        return DeliveryReading::NotASend;
    };
    let (Some(provider), Some(sent), Some(parts_total), Some(parts_sent)) = (
        map.get("provider").and_then(Value::as_str),
        map.get("sent").and_then(Value::as_bool),
        map.get("parts_total").and_then(Value::as_u64),
        map.get("parts_sent").and_then(Value::as_u64),
    ) else {
        return DeliveryReading::NotASend;
    };

    let flag = |name: &str| map.get(name).and_then(Value::as_bool).unwrap_or(false);
    if !sent || flag("skipped") || flag("dry_run") || parts_sent == 0 {
        return DeliveryReading::NothingSent;
    }

    if provider.is_empty()
        || provider.chars().count() > MAX_PROVIDER_CHARS
        || !provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return DeliveryReading::Malformed("provider");
    }
    if parts_total == 0 || parts_total > MAX_PARTS {
        return DeliveryReading::Malformed("parts_total");
    }
    if parts_sent > parts_total {
        return DeliveryReading::Malformed("parts_sent");
    }

    let count = |name: &'static str| -> Result<u64, &'static str> {
        match map.get(name) {
            None | Some(Value::Null) => Ok(0),
            Some(v) => v.as_u64().filter(|n| *n <= MAX_ACTIONS).ok_or(name),
        }
    };
    let actions_sent = match count("actions_sent") {
        Ok(n) => n,
        Err(name) => return DeliveryReading::Malformed(name),
    };
    let one_tap_actions = match count("one_tap_actions") {
        Ok(n) if n <= actions_sent => n,
        _ => return DeliveryReading::Malformed("one_tap_actions"),
    };
    let kept_actions = match count("kept_actions") {
        Ok(n) if n <= actions_sent => n,
        _ => return DeliveryReading::Malformed("kept_actions"),
    };

    // Every value is bounded well inside u32 by the checks above; the
    // conversions cannot fail, and a failure would still be a malformed
    // verdict rather than a wrapped count.
    let narrow = |n: u64, field: &'static str| u32::try_from(n).map_err(|_| field);
    let verdict = (|| -> Result<DeliveryVerdict, &'static str> {
        Ok(DeliveryVerdict {
            provider: provider.to_string(),
            parts_total: narrow(parts_total, "parts_total")?,
            parts_sent: narrow(parts_sent, "parts_sent")?,
            actions_sent: narrow(actions_sent, "actions_sent")?,
            one_tap_actions: narrow(one_tap_actions, "one_tap_actions")?,
            kept_actions: narrow(kept_actions, "kept_actions")?,
        })
    })();
    match verdict {
        Ok(verdict) => DeliveryReading::Sent(verdict),
        Err(field) => DeliveryReading::Malformed(field),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn verdict() -> Value {
        json!({ "provider": "ntfy", "sent": true, "skipped": false, "dry_run": false,
                "status": 200, "parts_total": 2, "parts_sent": 2,
                "actions_sent": 3, "actions_dropped": 1, "one_tap_actions": 2,
                "kept_actions": 1, "link_sent": true, "link_dropped": false, "tag_sent": false })
    }

    #[test]
    fn the_contracts_verdict_is_read_as_a_send() {
        assert_eq!(
            read_delivery_verdict(&verdict()),
            DeliveryReading::Sent(DeliveryVerdict {
                provider: "ntfy".into(),
                parts_total: 2,
                parts_sent: 2,
                actions_sent: 3,
                one_tap_actions: 2,
                kept_actions: 1,
            })
        );
    }

    #[test]
    fn the_counts_an_adapter_may_omit_default_to_zero() {
        let v = json!({ "provider": "home_assistant", "sent": true, "parts_total": 1, "parts_sent": 1 });
        assert_eq!(
            read_delivery_verdict(&v),
            DeliveryReading::Sent(DeliveryVerdict {
                provider: "home_assistant".into(),
                parts_total: 1,
                parts_sent: 1,
                actions_sent: 0,
                one_tap_actions: 0,
                kept_actions: 0,
            })
        );
    }

    #[test]
    fn an_output_without_the_four_fields_is_not_a_send() {
        for other in [
            json!({ "notification": { "body": "Three things." } }),
            json!({ "sent": true, "message_id": "m1", "thread_id": "t1" }),
            json!({ "provider": "ntfy", "sent": true, "parts_total": 1 }),
            json!({ "provider": 7, "sent": true, "parts_total": 1, "parts_sent": 1 }),
            json!(["provider"]),
            json!(null),
        ] {
            assert_eq!(
                read_delivery_verdict(&other),
                DeliveryReading::NotASend,
                "{other}"
            );
        }
    }

    #[test]
    fn a_skip_a_dry_run_and_an_unsent_verdict_are_nothing_sent() {
        let mut skipped = verdict();
        skipped["skipped"] = json!(true);
        let mut dry = verdict();
        dry["dry_run"] = json!(true);
        let mut unsent = verdict();
        unsent["sent"] = json!(false);
        let mut none = verdict();
        none["parts_sent"] = json!(0);
        for v in [skipped, dry, unsent, none] {
            assert_eq!(
                read_delivery_verdict(&v),
                DeliveryReading::NothingSent,
                "{v}"
            );
        }
    }

    #[test]
    fn a_verdict_outside_the_contracts_bounds_is_malformed_and_names_the_field() {
        let cases: [(&str, Value, &str); 9] = [
            ("provider", json!(""), "provider"),
            ("provider", json!("Ntfy"), "provider"),
            ("provider", json!("a".repeat(33)), "provider"),
            ("parts_total", json!(65), "parts_total"),
            ("parts_sent", json!(3), "parts_sent"),
            ("actions_sent", json!(1025), "actions_sent"),
            ("actions_sent", json!(-1), "actions_sent"),
            ("one_tap_actions", json!(4), "one_tap_actions"),
            ("kept_actions", json!("1"), "kept_actions"),
        ];
        for (field, value, reason) in cases {
            let mut v = verdict();
            v[field] = value;
            assert_eq!(
                read_delivery_verdict(&v),
                DeliveryReading::Malformed(reason),
                "{field}"
            );
        }
    }
}

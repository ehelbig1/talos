// Canonical catalog module: modify Gmail message labels — mark read, add or
// remove labels. This is the dedup + loop-guard leg the email-your-assistant
// channel needs: after the assistant reads and acts on a message it marks it
// read (remove the UNREAD label) and/or moves it out of the trigger label so
// the same message is never processed twice.
//
// No such label-modify module existed in the catalog before this one.
//
// DRY_RUN defaults to TRUE (the house pattern): the module reports exactly
// what it WOULD change and makes NO POST. Flip DRY_RUN to false to apply.
//
// Best-effort batch: a per-message failure is recorded and the batch
// continues — one bad id never fails the whole run.
//
// SECURITY / DLP: label modification is low-sensitivity, but the module still
// logs counts only — never the OAuth token, message ids, or label names at a
// level that would leak them.

use serde_json::{json, Value};
use talos_sdk_macros::talos_module;

// Cap on messages processed per invocation — matches a tight poll cadence and
// bounds the HTTP fan-out (one POST per message).
const HARD_CAP: usize = 25;

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let data: Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&Value::Null);

    let auth = config["AUTH_HEADER"].as_str().ok_or(
        "Missing AUTH_HEADER config (expected 'Bearer vault://oauth/gmail/{user_id}/{email}/access_token')",
    )?;

    let add_labels = string_array(&config["ADD_LABELS"]);
    let remove_labels = string_array(&config["REMOVE_LABELS"]);

    // DRY_RUN defaults to true — no POST unless explicitly disabled.
    let dry_run = config["DRY_RUN"].as_bool().unwrap_or(true);

    let ids = collect_ids(config, &data, HARD_CAP);

    if ids.is_empty() {
        return Err(
            "No message ids to modify. Provide MESSAGE_IDS (array), MESSAGE_ID (single), or chain after a node that emits messages[].id."
                .to_string(),
        );
    }

    // DLP: counts only — never the ids or label names beyond their counts.
    logging::log(
        Level::Info,
        &format!(
            "gmail-modify: {} message(s), +{} label(s) / -{} label(s), dry_run={}",
            ids.len(),
            add_labels.len(),
            remove_labels.len(),
            dry_run
        ),
    );

    let mut results = Vec::with_capacity(ids.len());
    let mut modified = 0usize;

    for id in &ids {
        if dry_run {
            results.push(json!({ "id": id, "status": "dry_run" }));
            continue;
        }
        match modify_one(auth, id, &add_labels, &remove_labels) {
            Ok(_) => {
                modified += 1;
                results.push(json!({ "id": id, "status": "modified" }));
            }
            // Best-effort: record the failure, keep going.
            Err(status) => {
                results.push(json!({ "id": id, "status": status }));
            }
        }
    }

    logging::log(
        Level::Info,
        &format!(
            "gmail-modify: {} modified (of {}), dry_run={}",
            modified,
            ids.len(),
            dry_run
        ),
    );

    let out = json!({
        "modified": modified,
        "dry_run": dry_run,
        "results": results,
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

// POST one message's modify call. Returns Ok on 2xx, Err(status_label) on
// anything else so the batch can record it and continue.
fn modify_one(
    auth: &str,
    id: &str,
    add_labels: &[String],
    remove_labels: &[String],
) -> Result<(), String> {
    let payload = json!({
        "addLabelIds": add_labels,
        "removeLabelIds": remove_labels,
    });
    let body = serde_json::to_vec(&payload).map_err(|_| "serialize_error".to_string())?;

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}/modify",
            id
        ),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body,
        timeout_ms: Some(10000),
    };

    let resp = talos::core::http::fetch(&req).map_err(|_| "network_error".to_string())?;
    if resp.status == 401 {
        return Err("unauthorized".to_string());
    }
    if resp.status == 404 {
        return Err("not_found".to_string());
    }
    if resp.status >= 400 {
        return Err(format!("http_{}", resp.status));
    }
    // 2xx from the modify endpoint IS the success signal — the response body
    // (the message's new labelIds) isn't needed downstream, so we don't parse it.
    Ok(())
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────────

// Coerce a JSON value into a Vec<String>: an array of strings, or a single
// string, else empty. Non-string array entries are skipped.
fn string_array(v: &Value) -> Vec<String> {
    if let Some(arr) = v.as_array() {
        arr.iter()
            .filter_map(|e| e.as_str().map(|s| s.to_string()))
            .collect()
    } else if let Some(s) = v.as_str() {
        if s.is_empty() {
            vec![]
        } else {
            vec![s.to_string()]
        }
    } else {
        vec![]
    }
}

// Normalize the message-id list from three sources, in priority order, with
// order-preserving dedup and a hard cap:
//   1. config.MESSAGE_IDS (array)
//   2. config.MESSAGE_ID (single string)
//   3. upstream input.messages[].id  (chains after gmail-get-message /
//      gmail-list-messages), including under an `__accumulated__` merge.
fn collect_ids(config: &Value, input: &Value, cap: usize) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();

    for s in string_array(&config["MESSAGE_IDS"]) {
        push_unique(&mut ids, s);
    }
    if let Some(s) = config["MESSAGE_ID"].as_str() {
        if !s.is_empty() {
            push_unique(&mut ids, s.to_string());
        }
    }
    // Top-level upstream messages[].id
    for s in ids_from_messages(input.get("messages")) {
        push_unique(&mut ids, s);
    }
    // __accumulated__.<node>.messages[].id (multi-parent merged shape)
    if let Some(acc) = input.get("__accumulated__").and_then(|v| v.as_object()) {
        for node_out in acc.values() {
            for s in ids_from_messages(node_out.get("messages")) {
                push_unique(&mut ids, s);
            }
        }
    }

    ids.truncate(cap);
    ids
}

fn ids_from_messages(messages: Option<&Value>) -> Vec<String> {
    messages
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique(ids: &mut Vec<String>, s: String) {
    if !s.is_empty() && !ids.iter().any(|e| e == &s) {
        ids.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn string_array_from_array() {
        assert_eq!(
            string_array(&json!(["UNREAD", "INBOX"])),
            vec!["UNREAD".to_string(), "INBOX".to_string()]
        );
    }

    #[test]
    fn string_array_from_single() {
        assert_eq!(string_array(&json!("UNREAD")), vec!["UNREAD".to_string()]);
    }

    #[test]
    fn string_array_skips_non_strings_and_empty() {
        assert_eq!(
            string_array(&json!(["A", 5, null, "B"])),
            vec!["A".to_string(), "B".to_string()]
        );
        assert_eq!(string_array(&json!("")), Vec::<String>::new());
        assert_eq!(string_array(&json!(null)), Vec::<String>::new());
    }

    #[test]
    fn collect_ids_from_message_ids_array() {
        let config = json!({ "MESSAGE_IDS": ["a", "b", "c"] });
        assert_eq!(collect_ids(&config, &json!({}), 25), vec!["a", "b", "c"]);
    }

    #[test]
    fn collect_ids_from_single_message_id() {
        let config = json!({ "MESSAGE_ID": "solo" });
        assert_eq!(collect_ids(&config, &json!({}), 25), vec!["solo"]);
    }

    #[test]
    fn collect_ids_from_upstream_messages() {
        let input = json!({ "messages": [ { "id": "m1" }, { "id": "m2" } ] });
        assert_eq!(collect_ids(&json!({}), &input, 25), vec!["m1", "m2"]);
    }

    #[test]
    fn collect_ids_from_accumulated() {
        let input = json!({
            "__accumulated__": {
                "get_msg": { "messages": [ { "id": "x1" }, { "id": "x2" } ] }
            }
        });
        assert_eq!(collect_ids(&json!({}), &input, 25), vec!["x1", "x2"]);
    }

    #[test]
    fn collect_ids_dedups_across_sources() {
        let config = json!({ "MESSAGE_IDS": ["a", "b"], "MESSAGE_ID": "b" });
        let input = json!({ "messages": [ { "id": "b" }, { "id": "c" } ] });
        // a,b from array; b (single) deduped; b deduped, c added
        assert_eq!(collect_ids(&config, &input, 25), vec!["a", "b", "c"]);
    }

    #[test]
    fn collect_ids_respects_cap() {
        let config = json!({ "MESSAGE_IDS": ["a", "b", "c", "d"] });
        assert_eq!(collect_ids(&config, &json!({}), 2), vec!["a", "b"]);
    }

    #[test]
    fn collect_ids_empty_when_no_source() {
        assert_eq!(
            collect_ids(&json!({}), &json!({}), 25),
            Vec::<String>::new()
        );
    }
}

// skeleton-keeper: the ONE writer of its memory key. It adds what its input
// brings to what the key already holds, and writes the result back through
// `__memory_write__`. It reaches no network.
//
// TODO(author): say what it keeps, under which key, and from which node.
// Replace `Entry` with your record, and KEY with the key it owns.
//
// What this shape already does, and what the catalog's tests hold it to:
// * agent-node: no host, no verb (talos.json grants none);
// * idempotent: an entry already held (by id) is not added again, so a run
//   repeated after a crash changes nothing;
// * bounded: at most MAX_KEPT entries, the oldest given up first, and a run
//   adds at most MAX_PER_RUN;
// * an unreadable store is an ERROR, never an empty store that overwrites it;
// * the write carries `metadata.kind` and `skip_if_unchanged`, so a quiet run
//   rewrites nothing and a freshness contract reads "checked", not "stale".

use serde::{Deserialize, Serialize};
use serde_json::json;
use talos_sdk_macros::talos_module;

/// The memory key this module is the only writer of.
const KEY: &str = "skeleton-keeper/entries";
const MAX_KEPT: usize = 200;
const MAX_PER_RUN: usize = 50;
const FIELD_CHARS: usize = 300;

#[derive(Deserialize)]
struct Envelope {
    input: Option<Input>,
}

#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq)]
struct Entry {
    id: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize, Serialize, Default)]
struct Kept {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[talos_module(world = "agent-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let input = envelope.input.ok_or("the input did not arrive")?;
    // An unreadable store stops the run: writing over it would lose what it holds.
    let mut kept: Kept = match talos::core::agent_memory::get_entry(KEY)
        .map_err(|e| format!("the store could not be read ({e:?}); nothing was written"))?
    {
        None => Kept::default(),
        Some(entry) => serde_json::from_str(&entry.value).map_err(|_| "the store holds something that could not be read; nothing was written".to_string())?,
    };
    let mut added = 0;
    let mut already = 0;
    for entry in input.entries.into_iter().take(MAX_PER_RUN) {
        let entry = Entry { id: plain(&entry.id), text: plain(&entry.text) };
        if entry.id.is_empty() {
            continue;
        }
        if kept.entries.iter().any(|e| e.id == entry.id) {
            already += 1;
            continue;
        }
        kept.entries.push(entry);
        added += 1;
    }
    let over = kept.entries.len().saturating_sub(MAX_KEPT);
    kept.entries.drain(..over);
    let out = json!({
        "kind": "skeleton_keeper",
        "added": added,
        "already_kept": already,
        "kept": kept.entries.len(),
        "__memory_write__": {
            "key": KEY,
            "value": kept,
            "memory_type": "episodic",
            "metadata": {"kind": "skeleton_keeper"},
            "ttl_hours": 2160,
            "skip_if_unchanged": true,
        },
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Text as it may be kept: no control characters, cut to a length.
fn plain(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(FIELD_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use talos_module_testkit::host;

    fn run_with(entries: Value) -> Result<Value, String> {
        run(json!({"input": {"entries": entries}}).to_string()).map(|o| serde_json::from_str(&o).unwrap())
    }

    #[test]
    fn it_adds_what_is_new_and_writes_its_one_key() {
        host::memory::put(KEY, json!({"entries": [{"id": "a", "text": "kept before"}]}).to_string());
        let out = run_with(json!([{"id": "a", "text": "again"}, {"id": "b", "text": "new"}])).unwrap();
        assert_eq!((out["added"].clone(), out["already_kept"].clone(), out["kept"].clone()), (json!(1), json!(1), json!(2)));
        let write = &out["__memory_write__"];
        assert_eq!(write["key"], KEY);
        assert_eq!(write["value"]["entries"], json!([{"id": "a", "text": "kept before"}, {"id": "b", "text": "new"}]));
        assert_eq!((write["metadata"]["kind"].clone(), write["skip_if_unchanged"].clone()), (json!("skeleton_keeper"), json!(true)));
    }

    #[test]
    fn an_unreadable_store_writes_nothing() {
        host::memory::fail(true);
        assert!(run_with(json!([{"id": "a"}])).unwrap_err().contains("nothing was written"));
        host::memory::fail(false);
        host::memory::put(KEY, "not json");
        assert!(run_with(json!([{"id": "a"}])).unwrap_err().contains("nothing was written"));
    }

    #[test]
    fn it_is_bounded_and_gives_up_the_oldest_first() {
        let held: Vec<Value> = (0..MAX_KEPT).map(|n| json!({"id": format!("old-{n}")})).collect();
        host::memory::put(KEY, json!({"entries": held}).to_string());
        let new: Vec<Value> = (0..MAX_PER_RUN + 5).map(|n| json!({"id": format!("new-{n}")})).collect();
        let out = run_with(json!(new)).unwrap();
        assert_eq!((out["added"].clone(), out["kept"].clone()), (json!(MAX_PER_RUN), json!(MAX_KEPT)));
        assert_eq!(out["__memory_write__"]["value"]["entries"][0]["id"], json!(format!("old-{MAX_PER_RUN}")));
    }
}

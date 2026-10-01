//! The bounded snapshot of a node's input that the engine stores as a
//! `node_input` event, and the constants its readers need.
//!
//! The snapshot is capped at [`NODE_INPUT_PREVIEW_MAX_BYTES`]. An input that
//! fits is stored whole. One that does not is stored SHORTENED rather than cut:
//! long strings, long arrays, wide objects and deep nesting are abbreviated
//! (each abbreviation carries a `…` marker saying what was left out) so the
//! result is still one valid JSON document whose keys and nesting can be read.
//! A shortened snapshot ends with [`NODE_INPUT_SHORTENED_SUFFIX`], which is how
//! a reader tells the two apart.
//!
//! Until 2026-10-01 an oversized input was serialized in full and cut at the
//! byte limit, which left an unparseable prefix: measured over seven days,
//! 2,854 of 9,261 stored inputs (31 %) could only be shown as a raw string.
//!
//! [`ENGINE_AUTHORED_INPUT_KEYS`] are never written, at any depth: the merged
//! input carries decrypted actor memory and the accumulated context, and
//! neither belongs in a plaintext event row.

use crate::reserved_keys::{WithoutEngineAuthoredKeys, ENGINE_AUTHORED_INPUT_KEYS};
use serde::ser::{SerializeMap, SerializeSeq};
use serde_json::Value;
use std::io;

/// Largest stored snapshot body, in bytes (the suffix is not counted).
pub const NODE_INPUT_PREVIEW_MAX_BYTES: usize = 4096;

/// Appended to a snapshot that was shortened to fit. The text before it is a
/// complete JSON document for every snapshot written by
/// [`node_input_preview`]; rows written before 2026-10-01 carry the same
/// suffix after a cut-off prefix that does not parse.
pub const NODE_INPUT_SHORTENED_SUFFIX: &str = "...(truncated)";

/// The key under which a shortened object reports the keys it left out.
pub const OMITTED_KEYS_MARKER: &str = "…";

/// How much of each part of the input one shortening pass keeps.
#[derive(Clone, Copy)]
struct Limits {
    /// Bytes kept of a string value.
    string_bytes: usize,
    /// Elements kept of an array.
    items: usize,
    /// Entries kept of an object.
    keys: usize,
    /// Bytes kept of an object key.
    key_bytes: usize,
    /// Nesting levels rendered; a container below that is summarised.
    depth: usize,
}

/// Tried in order; the first whose output fits is stored. The last one is
/// small enough to fit whatever the input (pinned by a test): 8 keys of at
/// most 32 bytes, each with a scalar, a 8-byte string or a one-line summary.
const PASSES: &[Limits] = &[
    Limits {
        string_bytes: 400,
        items: 8,
        keys: 64,
        key_bytes: 96,
        depth: 6,
    },
    Limits {
        string_bytes: 160,
        items: 4,
        keys: 48,
        key_bytes: 64,
        depth: 5,
    },
    Limits {
        string_bytes: 64,
        items: 3,
        keys: 32,
        key_bytes: 48,
        depth: 4,
    },
    Limits {
        string_bytes: 24,
        items: 2,
        keys: 24,
        key_bytes: 32,
        depth: 3,
    },
    Limits {
        string_bytes: 12,
        items: 1,
        keys: 12,
        key_bytes: 32,
        depth: 2,
    },
    Limits {
        string_bytes: 8,
        items: 1,
        keys: 8,
        key_bytes: 32,
        depth: 1,
    },
];

/// The snapshot of `input` to store in a `node_input` event.
///
/// Work is bounded by the output, not the input: every serialization stops as
/// soon as it has written more than the limit, and a shortening pass never
/// visits the elements it leaves out (it reads only their count).
#[must_use]
pub fn node_input_preview(input: &Value) -> String {
    if let Some(whole) = serialize_within_limit(&WithoutEngineAuthoredKeys(input)) {
        return whole;
    }
    for limits in PASSES {
        let shortened = Shortened {
            value: input,
            limits: *limits,
            depth: 0,
        };
        if let Some(mut body) = serialize_within_limit(&shortened) {
            body.push_str(NODE_INPUT_SHORTENED_SUFFIX);
            return body;
        }
    }
    // Unreachable for JSON built by the engine (the last pass always fits);
    // kept so a future change to PASSES cannot store an unparseable body.
    format!("\"input too large to summarise\"{NODE_INPUT_SHORTENED_SUFFIX}")
}

/// Splits a stored snapshot into its JSON text and whether it was shortened.
#[must_use]
pub fn split_stored_preview(stored: &str) -> (&str, bool) {
    match stored.strip_suffix(NODE_INPUT_SHORTENED_SUFFIX) {
        Some(body) => (body, true),
        None => (stored, false),
    }
}

fn is_engine_authored(key: &str) -> bool {
    ENGINE_AUTHORED_INPUT_KEYS.contains(&key)
}

/// Serializes `value`, giving up as soon as the output passes the limit.
fn serialize_within_limit<T: serde::Serialize>(value: &T) -> Option<String> {
    let mut out = LimitedBuf {
        buf: Vec::with_capacity(512),
    };
    serde_json::to_writer(&mut out, value).ok()?;
    // serde_json writes only valid UTF-8.
    String::from_utf8(out.buf).ok()
}

struct LimitedBuf {
    buf: Vec<u8>,
}

impl io::Write for LimitedBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > NODE_INPUT_PREVIEW_MAX_BYTES {
            return Err(io::Error::other("node input preview limit reached"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Shortened<'a> {
    value: &'a Value,
    limits: Limits,
    depth: usize,
}

impl Shortened<'_> {
    fn child<'b>(&self, value: &'b Value) -> Shortened<'b> {
        Shortened {
            value,
            limits: self.limits,
            depth: self.depth + 1,
        }
    }
}

impl serde::Serialize for Shortened<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let limits = self.limits;
        match self.value {
            Value::Object(m) => {
                if self.depth >= limits.depth {
                    let keys = m.keys().filter(|k| !is_engine_authored(k)).count();
                    return s.serialize_str(&format!("{{… {keys} keys}}"));
                }
                let mut map = s.serialize_map(None)?;
                let mut written = 0usize;
                let mut omitted = 0usize;
                for (k, v) in m {
                    if is_engine_authored(k) {
                        continue;
                    }
                    if written < limits.keys {
                        map.serialize_entry(&cut(k, limits.key_bytes, false), &self.child(v))?;
                        written += 1;
                    } else {
                        omitted += 1;
                    }
                }
                if omitted > 0 {
                    map.serialize_entry(OMITTED_KEYS_MARKER, &format!("+{omitted} more keys"))?;
                }
                map.end()
            }
            Value::Array(a) => {
                if self.depth >= limits.depth {
                    return s.serialize_str(&format!("[… {} items]", a.len()));
                }
                let mut seq = s.serialize_seq(None)?;
                for v in a.iter().take(limits.items) {
                    seq.serialize_element(&self.child(v))?;
                }
                if a.len() > limits.items {
                    seq.serialize_element(&format!("… +{} more items", a.len() - limits.items))?;
                }
                seq.end()
            }
            Value::String(text) => s.serialize_str(&cut(text, limits.string_bytes, true)),
            other => other.serialize(s),
        }
    }
}

/// `text` if it is within `max_bytes`, otherwise its start (cut on a
/// character boundary) followed by a marker; `with_count` adds how many bytes
/// were left out.
fn cut(text: &str, max_bytes: usize, with_count: bool) -> std::borrow::Cow<'_, str> {
    if text.len() <= max_bytes {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let kept = &text[..end];
    std::borrow::Cow::Owned(if with_count {
        format!("{kept}… (+{} bytes)", text.len() - end)
    } else {
        format!("{kept}…")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parsed(stored: &str) -> (Value, bool) {
        let (body, shortened) = split_stored_preview(stored);
        assert!(
            body.len() <= NODE_INPUT_PREVIEW_MAX_BYTES,
            "body is {} bytes",
            body.len()
        );
        let value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("stored body is not JSON ({e}): {body}"));
        (value, shortened)
    }

    #[test]
    fn an_input_that_fits_is_stored_whole_and_unmarked() {
        let input = json!({"config": {"MODEL": "m"}, "input": {"n": 1}, "list": [1, 2, 3]});
        let (value, shortened) = parsed(&node_input_preview(&input));
        assert!(!shortened);
        assert_eq!(value, input);
    }

    #[test]
    fn an_oversized_input_keeps_every_key_and_stays_valid_json() {
        // The shape that used to be cut mid-string: one long value sorted
        // ahead of the keys that follow it.
        let input = json!({
            "config": {"TO": "someone", "DRY_RUN": true},
            "html": "x".repeat(20_000),
            "items": (0..500).map(|i| json!({"id": i, "text": "y".repeat(300)})).collect::<Vec<_>>(),
            "zeta": {"deep": {"deeper": {"value": 1}}},
        });
        let stored = node_input_preview(&input);
        let (value, shortened) = parsed(&stored);
        assert!(shortened);
        let obj = value.as_object().expect("an object");
        for key in ["config", "html", "items", "zeta"] {
            assert!(obj.contains_key(key), "`{key}` missing from {stored}");
        }
        assert_eq!(obj["config"], json!({"TO": "someone", "DRY_RUN": true}));
        let html = obj["html"].as_str().expect("a string");
        assert!(
            html.starts_with("xxxx") && html.contains("bytes)"),
            "{html}"
        );
        let items = obj["items"].as_array().expect("an array");
        assert!(items.len() < 500);
        assert!(
            items
                .last()
                .and_then(Value::as_str)
                .is_some_and(|m| m.contains("more items")),
            "{items:?}"
        );
        assert_eq!(items[0]["id"], json!(0));
    }

    #[test]
    fn engine_authored_keys_are_never_stored_at_any_depth() {
        let secret = "SECRET-MEMORY";
        for filler in [0usize, 30_000] {
            let mut input = json!({
                "data": 1,
                "pad": "p".repeat(filler),
                "nested": {"keep": true},
                "list": [{"keep": 2}],
            });
            for key in ENGINE_AUTHORED_INPUT_KEYS {
                input[*key] = json!({"memories": [secret]});
                input["nested"][*key] = json!(secret);
                input["list"][0][*key] = json!(secret);
            }
            let stored = node_input_preview(&input);
            assert!(!stored.contains(secret), "{stored}");
            for key in ENGINE_AUTHORED_INPUT_KEYS {
                assert!(!stored.contains(key), "`{key}` stored: {stored}");
            }
            let (value, shortened) = parsed(&stored);
            assert_eq!(shortened, filler > 0);
            assert_eq!(value["data"], json!(1));
            assert_eq!(value["nested"]["keep"], json!(true));
        }
    }

    #[test]
    fn a_cut_never_lands_inside_a_character() {
        // An em-dash is three bytes; every pass's string limit is tried.
        let input = json!({"text": "—".repeat(5_000), "é".repeat(200): 1});
        let (value, shortened) = parsed(&node_input_preview(&input));
        assert!(shortened);
        assert!(value["text"].as_str().is_some_and(|t| t.starts_with('—')));
    }

    #[test]
    fn the_last_pass_fits_whatever_the_input() {
        // Wide, deep, long keys and long strings at once.
        let long_key = |i: usize| format!("{i}-{}", "k".repeat(500));
        let leaf: serde_json::Map<String, Value> = (0..10)
            .map(|i| (long_key(i), json!("v".repeat(2_000))))
            .collect();
        let mut level = Value::Object(leaf);
        for width in [12, 80] {
            let wide: serde_json::Map<String, Value> = (0..width)
                .map(|i| (long_key(i), json!([level.clone()])))
                .collect();
            level = Value::Object(wide);
        }
        let stored = node_input_preview(&level);
        let (value, shortened) = parsed(&stored);
        assert!(shortened);
        let obj = value.as_object().expect("an object");
        assert!(obj.contains_key(OMITTED_KEYS_MARKER), "{stored}");
        assert!(!stored.contains("too large to summarise"), "{stored}");
    }

    #[test]
    fn the_last_pass_bound_is_arithmetic_not_luck() {
        // Worst case for the final pass: every key and value at its limit.
        let last = PASSES[PASSES.len() - 1];
        // A key is at most key_bytes + the marker; a value is at most a
        // shortened string (string_bytes + marker + count) or a summary.
        let per_entry = (last.key_bytes + 8) + (last.string_bytes + 40) + 8;
        let worst = (last.keys + 1) * per_entry + 2;
        assert!(worst <= NODE_INPUT_PREVIEW_MAX_BYTES, "worst case {worst}");
        assert_eq!(last.depth, 1, "the bound above assumes one rendered level");
    }

    #[test]
    fn a_non_object_input_is_handled() {
        let (value, shortened) = parsed(&node_input_preview(&json!("z".repeat(10_000))));
        assert!(shortened);
        assert!(value.as_str().is_some_and(|s| s.starts_with("zzz")));
        let (value, shortened) = parsed(&node_input_preview(&json!(null)));
        assert!(!shortened);
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn an_old_cut_off_row_is_still_reported_as_shortened() {
        let old = format!("{{\"html\":\"<div{NODE_INPUT_SHORTENED_SUFFIX}");
        let (body, shortened) = split_stored_preview(&old);
        assert!(shortened);
        assert!(serde_json::from_str::<Value>(body).is_err());
    }
}

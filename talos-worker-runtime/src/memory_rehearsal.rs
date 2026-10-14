//! A rehearsal against an actor's memory: reads reach the actor, writes can
//! be left unapplied, and the run says which keys it touched (2026-10-14).
//!
//! `test_module(actor_id)` already scoped a rehearsal's `agent_memory` calls
//! to that actor, writes included: a keeper module rehearsed against real
//! state wrote real state. Without `actor_id` it read nothing. So a module
//! whose bugs depend on what is stored could be seen working on real state
//! only by also letting it change that state.
//!
//! This value is set on the context of an in-process rehearsal only, like
//! [`crate::http_replay::HttpReplay`]. It is not a field of any wire message,
//! so a dispatched job cannot carry one.
//!
//! * Reads (`get`, `get-entry`, `list-keys`, `search`, `search-filtered`) go
//!   to the actor as before, and the keys read, the prefixes listed and the
//!   number of searches are recorded. Never a value, never a search query.
//! * Writes (`set`, `delete`, `store-with-embedding`) are recorded. With
//!   `discard_writes`, they are answered `Ok` and NOT sent: everything that
//!   decides whether the write MAY be made (the capability world, the write
//!   ceiling, key validation) still runs first, so a write the actor's
//!   ceiling refuses is still refused.
//! * Bounded: at most [`MAX_KEYS`] keys and [`MAX_WRITES`] writes listed, the
//!   rest counted.

use std::collections::BTreeSet;
use std::sync::Mutex;

/// The most distinct keys (and, separately, prefixes) listed in a report.
pub const MAX_KEYS: usize = 256;
/// The most writes listed in a report.
pub const MAX_WRITES: usize = 64;
/// The longest key kept in a report, in characters.
const MAX_KEY_CHARS: usize = 200;

#[derive(Default)]
struct Log {
    keys_read: BTreeSet<String>,
    prefixes_listed: BTreeSet<String>,
    searches: u32,
    writes: Vec<(&'static str, String)>,
    not_listed: u32,
}

/// What a memory rehearsal records, and whether it applies writes.
pub struct MemoryRehearsal {
    discard_writes: bool,
    log: Mutex<Log>,
}

fn bounded(key: &str) -> String {
    key.chars().take(MAX_KEY_CHARS).collect()
}

/// Shows the mode only: what the run touched is the caller's, not a log's.
impl std::fmt::Debug for MemoryRehearsal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryRehearsal")
            .field("discard_writes", &self.discard_writes)
            .finish_non_exhaustive()
    }
}

impl MemoryRehearsal {
    /// A rehearsal that records memory calls, and leaves writes unapplied
    /// when `discard_writes`.
    #[must_use]
    pub fn new(discard_writes: bool) -> Self {
        Self {
            discard_writes,
            log: Mutex::new(Log::default()),
        }
    }

    /// Whether writes are answered without being sent.
    #[must_use]
    pub fn discards_writes(&self) -> bool {
        self.discard_writes
    }

    /// A key read by `get` / `get-entry`.
    pub fn record_read(&self, key: &str) {
        if let Ok(mut log) = self.log.lock() {
            if log.keys_read.len() < MAX_KEYS || log.keys_read.contains(key) {
                log.keys_read.insert(bounded(key));
            } else {
                log.not_listed = log.not_listed.saturating_add(1);
            }
        }
    }

    /// A `list-keys` call (`""` for no prefix).
    pub fn record_list(&self, prefix: Option<&str>) {
        let prefix = prefix.unwrap_or("");
        if let Ok(mut log) = self.log.lock() {
            if log.prefixes_listed.len() < MAX_KEYS || log.prefixes_listed.contains(prefix) {
                log.prefixes_listed.insert(bounded(prefix));
            } else {
                log.not_listed = log.not_listed.saturating_add(1);
            }
        }
    }

    /// A semantic search. The query is never kept.
    pub fn record_search(&self) {
        if let Ok(mut log) = self.log.lock() {
            log.searches = log.searches.saturating_add(1);
        }
    }

    /// A write (`set`, `delete`, `store-with-embedding`) the guest asked for.
    pub fn record_write(&self, op: &'static str, key: &str) {
        if let Ok(mut log) = self.log.lock() {
            if log.writes.len() < MAX_WRITES {
                log.writes.push((op, bounded(key)));
            } else {
                log.not_listed = log.not_listed.saturating_add(1);
            }
        }
    }

    /// The report a rehearsal's reply carries.
    #[must_use]
    pub fn report(&self) -> serde_json::Value {
        let Ok(log) = self.log.lock() else {
            return serde_json::json!({ "unreadable": true });
        };
        serde_json::json!({
            "writes_applied": !self.discard_writes,
            "keys_read": log.keys_read.iter().collect::<Vec<_>>(),
            "prefixes_listed": log.prefixes_listed.iter().collect::<Vec<_>>(),
            "searches": log.searches,
            "writes": log
                .writes
                .iter()
                .map(|(op, key)| serde_json::json!({ "op": op, "key": key }))
                .collect::<Vec<_>>(),
            "not_listed": log.not_listed,
        })
    }

    /// How many distinct keys were read.
    #[must_use]
    pub fn keys_read_count(&self) -> usize {
        self.log.lock().map_or(0, |l| l.keys_read.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_names_keys_and_never_values() {
        let r = MemoryRehearsal::new(true);
        r.record_read("work/kinds");
        r.record_read("work/kinds");
        r.record_list(Some("work/log/"));
        r.record_search();
        r.record_write("set", "work/log/x");
        let report = r.report();
        assert_eq!(report["writes_applied"], false);
        assert_eq!(report["keys_read"], serde_json::json!(["work/kinds"]));
        assert_eq!(report["prefixes_listed"], serde_json::json!(["work/log/"]));
        assert_eq!(report["searches"], 1);
        assert_eq!(
            report["writes"],
            serde_json::json!([{ "op": "set", "key": "work/log/x" }])
        );
        assert_eq!(r.keys_read_count(), 1);
    }

    #[test]
    fn a_report_is_bounded_and_counts_the_rest() {
        let r = MemoryRehearsal::new(false);
        for i in 0..(MAX_KEYS + 5) {
            r.record_read(&format!("k{i}"));
        }
        for i in 0..(MAX_WRITES + 3) {
            r.record_write("set", &format!("w{i}"));
        }
        let report = r.report();
        assert_eq!(report["keys_read"].as_array().unwrap().len(), MAX_KEYS);
        assert_eq!(report["writes"].as_array().unwrap().len(), MAX_WRITES);
        assert_eq!(report["not_listed"], 8);
        assert_eq!(report["writes_applied"], true);
    }
}

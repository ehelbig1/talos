//! The graph-node-id → engine node UUID mapping.
//!
//! A workflow graph identifies its nodes by an author-chosen string
//! (`{"id": "extract", ...}` in `graph_json`). Everything downstream of the
//! executor — `execution_events.node_id`, per-node timings, the timeout
//! attribution snapshot — keys on a [`Uuid`] instead. [`engine_node_uuid`] is
//! the one function that converts between them.
//!
//! # Why this lives here and not next to the loader
//!
//! The mapping is a **wire contract**, not a loader implementation detail.
//! The graph loader is the only writer, but the rows it produces are read
//! back by analytics, failure breakdowns, execution traces, and (since this
//! module was added) workflow validation. A reader that re-derives the
//! mapping with its own copy of the arithmetic and gets it subtly wrong does
//! not fail loudly — its join matches **nothing**, and zero matched rows is
//! indistinguishable from "this workflow has no problems". Putting the
//! function in the crate both sides already depend on is what stops a
//! silent-empty-join from being reachable by drift.
//!
//! # Stability
//!
//! The derivation is **frozen**. `execution_events` rows written by every
//! prior release carry ids produced by this exact arithmetic; changing it
//! orphans all of them at once, with no error anywhere. It is pinned by
//! [`tests`] against values read out of a live events table.

use uuid::Uuid;

/// Map a graph node's author-facing id to the [`Uuid`] the executor uses.
///
/// * An id that already parses as a UUID is used verbatim.
/// * Anything else is hashed: the **first 16 bytes of `SHA-256(id)`**, taken
///   as raw UUID bytes via [`Uuid::from_bytes`].
///
/// The hashed form deliberately does **not** go through [`Uuid::new_v5`]: v5
/// would overwrite four bits with the version nibble and two with the variant,
/// producing different bytes than the ones already on disk. The result is
/// therefore not a version-tagged RFC 4122 UUID, and that is intentional —
/// it is a 128-bit identifier that happens to be carried in a `uuid` column.
///
/// Distinct ids collide only on a 128-bit SHA-256 prefix collision, so within
/// one graph (a handful of nodes) uniqueness is not a practical concern.
/// Uniqueness is **per node, not per module**: two nodes running the same
/// module get different ids, which is what keeps cycle detection honest.
///
/// # Renames are new identities
///
/// The id is the only input. Renaming a node from `extract` to `extract_v2`
/// produces a different UUID and detaches it from every historical event —
/// correct for attribution, but it means history-based checks go quiet after
/// a rename rather than carrying the old node's record forward.
///
/// ```
/// use talos_workflow_engine_core::engine_node_uuid;
/// // A UUID-shaped id passes through unchanged.
/// let explicit = "0f5f4a2c-1c3e-4a7d-9b2f-0c1d2e3f4a5b";
/// assert_eq!(engine_node_uuid(explicit).to_string(), explicit);
/// // A human-authored id hashes deterministically.
/// assert_eq!(
///     engine_node_uuid("extract").to_string(),
///     "f1cf2fd5-c868-9512-8d55-9088259a132d"
/// );
/// ```
#[must_use]
pub fn engine_node_uuid(graph_node_id: &str) -> Uuid {
    Uuid::parse_str(graph_node_id).unwrap_or_else(|_| {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(graph_node_id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        Uuid::from_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::engine_node_uuid;

    /// Pinned against ids read out of a LIVE `execution_events` table
    /// (2026-08-28), not against this function's own output. Each pair is
    /// `(graph_json node id, the node_id the executor actually wrote)`.
    ///
    /// This is the tripwire that makes the mapping a contract: if the
    /// derivation is ever "cleaned up" (to `Uuid::new_v5`, to a different
    /// hash, to a different byte slice) every one of these fails, instead of
    /// every history join silently returning nothing.
    #[test]
    fn derivation_matches_ids_observed_in_the_events_table() {
        for (graph_id, observed) in [
            ("extract", "f1cf2fd5-c868-9512-8d55-9088259a132d"),
            ("gmail_work", "c189b115-c97e-73d0-998b-df1f607c041e"),
            ("merge", "283128ac-ef14-943c-127f-7327ca8f57e7"),
            ("gmail", "576ba7c2-e4ab-b718-4ca4-09154dbbbd53"),
            ("calendar", "5152790e-278e-b890-39f8-bfaa354b944e"),
            ("brief", "29a8825b-d242-f143-86ee-528d76e0e8f1"),
            ("compose", "db669af6-34b7-5c7f-2984-00f3b6c2aa8b"),
            ("prep_judge", "08d5dfbc-f68f-94c6-e73c-20c3b5c053df"),
            // Re-measured 2026-08-28 when the READER copies of this
            // derivation were folded into this function. These seven are the
            // highest-event-count graph ids in the live table (27k, 21k, 13k,
            // 13k, 13k, 6.8k, 1.7k events respectively), i.e. the joins that
            // would go silently empty first if the arithmetic ever moved.
            ("fetch", "e7d3799e-cc09-f5cb-c446-aa0a79bb1fb9"),
            ("send", "27ce1d1b-f427-0020-e179-9f12e647f5cb"),
            ("verify_extract", "49aabc38-d51d-b8eb-b360-1ba13d54f45c"),
            ("thread_load", "d2c92efc-ac1a-c09c-aa75-24ba0db5f35a"),
            ("compose_reply", "581c25ca-08fb-69f6-3db6-ccbbf9c47c66"),
            ("ops_digest", "8df29c3b-d313-3be7-d86c-411befdbc31a"),
            ("classify_severity", "36003222-516e-712b-1a64-03af22644105"),
        ] {
            assert_eq!(
                engine_node_uuid(graph_id).to_string(),
                observed,
                "derivation drifted for graph node '{graph_id}' — every history \
                 join against execution_events for this node now matches zero rows"
            );
        }
    }

    /// A UUID-shaped id is adopted verbatim, NOT hashed. Authors who paste a
    /// UUID as the node id get that UUID in the events table.
    /// NOTE: no live workflow currently uses a UUID-shaped graph node id
    /// (checked against the events table 2026-08-28), so unlike the hashed
    /// arm above this one CANNOT be pinned against observed data. It is a
    /// synthetic assertion on the parse fast path.
    #[test]
    fn uuid_shaped_ids_pass_through_unhashed() {
        let explicit = "0f5f4a2c-1c3e-4a7d-9b2f-0c1d2e3f4a5b";
        assert_eq!(engine_node_uuid(explicit).to_string(), explicit);
        assert_ne!(engine_node_uuid(explicit), engine_node_uuid("some-label"));
    }

    /// Distinct labels map to distinct ids; the same label is stable across
    /// calls. (Uniqueness is per NODE — the module a node runs is not an
    /// input, so two nodes sharing a module still differ.)
    #[test]
    fn distinct_labels_are_distinct_and_stable() {
        assert_eq!(engine_node_uuid("extract"), engine_node_uuid("extract"));
        assert_ne!(engine_node_uuid("extract"), engine_node_uuid("Extract"));
        assert_ne!(engine_node_uuid("extract"), engine_node_uuid("extract "));
    }

    /// The empty id is not special-cased anywhere in the loader, so it must
    /// still produce a stable value rather than panicking on the slice.
    #[test]
    fn empty_id_is_stable_and_does_not_panic() {
        assert_eq!(engine_node_uuid(""), engine_node_uuid(""));
    }
}

//! Exact-duplicate partition for one WORM ingest batch.
//!
//! # The split, and why the writer cannot close the other half
//!
//! At-least-once is the transport's contract and the producer's retry loop has
//! its own multiplication path, so the same audit event can reach this
//! subscriber more than once. Two cases, and they are NOT symmetric:
//!
//! * **Same batch.** Both copies are in memory at once. The writer drops the
//!   later one here, before grouping, so the `.jsonl` object it writes holds
//!   the event once. This is what [`partition_batch_duplicates`] does.
//! * **Later batch.** The first copy is already an object in the store.
//!   Recognising it would mean LISTING and READING the execution's prefix —
//!   and the ledger writer's S3 identity is **write-only by design** (the
//!   read-only verifier identity is a separate credential precisely so a
//!   compromised writer cannot read the ledger back). Widening it to close
//!   this case would trade a benign duplicate for the ability to read the
//!   whole audit trail. **Do not widen it.**
//!
//! The later-batch case is therefore handled at the VERIFIER instead:
//! `talos_audit_event::ChainBreak::DuplicateDelivery` reports byte-identical
//! copies without calling them tamper evidence, wherever they were written.
//! One case is closed at the writer, the other is classified at the reader,
//! and neither is silently swallowed.
//!
//! # What counts as "the same event"
//!
//! `(execution_id, sequence_num, hash, hmac_signature)`. The `hash` is the
//! wrapper's published hash, which is safe to use as a content identity here
//! because every message reaching this partition has already passed
//! `classify_audit_message`, which REFUSES any message whose published hash is
//! not the canonically recomputed one. A conflicting pair (one sequence, two
//! contents) shares no key, is NOT deduped, and reaches the verifier as the
//! tamper evidence it is.

/// The identity an exact duplicate is judged on. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatchEventKey {
    pub execution_id: String,
    pub sequence_num: u64,
    /// The wrapper's published hash — already proven equal to the canonical
    /// recomputation by `classify_audit_message`.
    pub hash: String,
    /// `None` for an unsigned event; unsigned and signed copies of otherwise
    /// identical content are deliberately NOT the same event.
    pub hmac_signature: Option<String>,
}

/// One dropped copy, carried out so the caller can ACK it and say what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedDuplicate {
    /// Index into the caller's batch — the ACK handle.
    pub idx: usize,
    pub execution_id: String,
    /// The event's `action` (`execution_complete`, `secret.resolve`, …). The
    /// only content field in the log line: it is a closed producer-authored
    /// vocabulary, unlike the payload.
    pub event_kind: String,
}

/// Split one batch into the copies to WRITE and the exact duplicates to DROP.
///
/// First occurrence wins; order is preserved. Pure — no NATS, no S3, no
/// database — so the rule is unit-testable, which the batch handler it is
/// called from is not.
#[must_use]
pub fn partition_batch_duplicates<I>(events: I) -> (Vec<usize>, Vec<DroppedDuplicate>)
where
    I: IntoIterator<Item = (usize, BatchEventKey, String)>,
{
    let mut seen: std::collections::HashSet<BatchEventKey> = std::collections::HashSet::new();
    let mut keep = Vec::new();
    let mut dropped = Vec::new();
    for (idx, key, event_kind) in events {
        let execution_id = key.execution_id.clone();
        if seen.insert(key) {
            keep.push(idx);
        } else {
            dropped.push(DroppedDuplicate {
                idx,
                execution_id,
                event_kind,
            });
        }
    }
    (keep, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(exec: &str, seq: u64, hash: &str, sig: Option<&str>) -> BatchEventKey {
        BatchEventKey {
            execution_id: exec.to_string(),
            sequence_num: seq,
            hash: hash.to_string(),
            hmac_signature: sig.map(str::to_string),
        }
    }

    /// The live shape: one object whose two lines were byte-identical.
    #[test]
    fn an_exact_duplicate_is_written_once() {
        let (keep, dropped) = partition_batch_duplicates([
            (0, key("ex", 1, "h", Some("s")), "execution_complete".into()),
            (1, key("ex", 1, "h", Some("s")), "execution_complete".into()),
        ]);
        assert_eq!(keep, vec![0], "the FIRST copy is the one written");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].idx, 1);
        assert_eq!(dropped[0].event_kind, "execution_complete");
        assert_eq!(dropped[0].execution_id, "ex");
    }

    /// The control, and the reason the key is not `(execution_id, sequence)`:
    /// two events claiming one sequence with DIFFERENT content are a
    /// substitution. Dropping one would destroy the evidence.
    #[test]
    fn a_conflicting_pair_is_never_deduped() {
        let (keep, dropped) = partition_batch_duplicates([
            (0, key("ex", 1, "h1", Some("s1")), "a".into()),
            (1, key("ex", 1, "h2", Some("s2")), "a".into()),
        ]);
        assert_eq!(keep, vec![0, 1]);
        assert!(dropped.is_empty());
    }

    /// A signature stripped from an otherwise identical copy is a content
    /// difference, not a redelivery.
    #[test]
    fn a_stripped_signature_is_not_the_same_event() {
        let (keep, dropped) = partition_batch_duplicates([
            (0, key("ex", 1, "h", Some("s")), "a".into()),
            (1, key("ex", 1, "h", None), "a".into()),
        ]);
        assert_eq!(keep, vec![0, 1]);
        assert!(dropped.is_empty());
    }

    /// Different executions never collide, however equal their sequences.
    #[test]
    fn distinct_executions_do_not_collide() {
        let (keep, dropped) = partition_batch_duplicates([
            (0, key("a", 1, "h", Some("s")), "x".into()),
            (1, key("b", 1, "h", Some("s")), "x".into()),
        ]);
        assert_eq!(keep, vec![0, 1]);
        assert!(dropped.is_empty());
    }

    /// Four copies (the live ledger's largest class) leave one, and every
    /// dropped index comes back so the caller can ACK it — an unacked message
    /// is redelivered forever.
    #[test]
    fn every_surplus_copy_is_returned_for_acknowledgement() {
        let ev = |i| (i, key("ex", 1, "h", Some("s")), "execution_complete".into());
        let (keep, dropped) = partition_batch_duplicates([ev(0), ev(1), ev(2), ev(3)]);
        assert_eq!(keep, vec![0]);
        assert_eq!(
            dropped.iter().map(|d| d.idx).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    /// A batch with nothing repeated is passed through untouched — the
    /// steady state, and the mutation target that proves the partition is not
    /// simply dropping rows.
    #[test]
    fn a_clean_batch_is_unchanged() {
        let (keep, dropped) = partition_batch_duplicates([
            (0, key("ex", 1, "h1", Some("s1")), "a".into()),
            (1, key("ex", 2, "h2", Some("s2")), "b".into()),
            (2, key("ex", 3, "h3", Some("s3")), "c".into()),
        ]);
        assert_eq!(keep, vec![0, 1, 2]);
        assert!(dropped.is_empty());
    }
}

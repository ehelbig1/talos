# 2026-10-01 — an oversized node input is stored shortened, not cut; a redaction marker is explained

**Defect 1.** The engine stored each dispatched node's input as a
`node_input` event by serializing the whole input and cutting the text at
4096 bytes. A cut lands mid-structure, so the stored text is not JSON and
`get_node_io` could only return it as one raw string: the input's keys and
nesting could not be read. Keys sorting after the first long value were not
stored at all.

**Measured (7 days, read-only).** 2,854 of 9,261 stored inputs (30.8 %) were
cut. For one hourly notifier workflow it was every input (335 of 335).

**Fix.** One home, `talos_workflow_engine_core::input_preview`:
* `node_input_preview(input)` stores an input that fits unchanged. One that
  does not is SHORTENED — long strings, long arrays, wide objects and deep
  nesting are abbreviated, each abbreviation marked with `…` and what was left
  out — so the body is still one JSON document with every top-level key. Six
  passes of decreasing generosity are tried; the last fits whatever the input
  (pinned by arithmetic and by an adversarial fixture). The body keeps the
  `...(truncated)` suffix, so existing readers are unchanged.
* Work is bounded by the OUTPUT: each serialization stops once it has written
  more than the limit, and a pass never visits the elements it leaves out.
  Before, the whole input was serialized to a string on every dispatch just to
  be cut.
* Engine-authored keys are still never stored, at any depth.
* `get_node_io` reports `input_status` — `complete`, `shortened`,
  `unparseable`, `not_recorded`, `unreadable` — and an `input_note`. A failed
  read of the snapshot was rendered as `"input": null`, the same as "nothing
  stored"; it is now `unreadable`.

**Defect 2.** A tool result showing `[REDACTED:EMAIL]` in a node's output read
as if the address had been lost between two nodes. Redaction is applied where
a value is stored or displayed (measured: every `redact_*` call in the engine
crates is on a store, event or log path), never to what a running workflow
hands the next node.

**Fix.** The tool dispatcher appends one notice (`REDACTION_NOTICE`) as a
separate text block to any result whose text shows a `[REDACTED:` marker. The
first block is untouched, so a caller parsing it as JSON still can.

**Not changed.**
* The 4096-byte limit and the sink's 8 KiB cap.
* Rows already stored: a cut row stays cut and is reported `unparseable`.
* Catalog-template tool calls return without the dispatcher's decorator and
  so get no notice (they get no argument warnings either).

**Stated limits.**
* The event sink redacts the stored TEXT, and the token rule can replace a
  `"key":"value"` pair as one token, which breaks the JSON. Measured: 0 of
  6,406 complete snapshots in 7 days; such a row is reported `unparseable`
  with that cause named.
* A shortened snapshot shows at most 64 keys per object and 8 items per
  array; the rest are counted, not shown.

**Guards.** `input_preview::tests` (8), `node_input_report_tests` (5),
`a_result_showing_a_dlp_marker_gets_the_redaction_notice_once`, and the
engine's existing `the_node_input_event_never_persists_engine_authored_keys`.

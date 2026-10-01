# 2026-10-01 — `ml_reembed_dataset`: a dataset's vectors can be repaired and brought onto one runtime

**Defects.**
1. `DatasetService::re_embed_examples` — the path for rows embedded by
   another model — had NO caller. Changing `EMBEDDING_MODEL` would have left
   every ML example behind the strict model filter with nothing to bring it
   back.
2. A row stored without an embedding (the embedder was unavailable at append)
   is described throughout as "backfillable", and nothing backfilled it.
   Measured on the reference fleet: **95 of 3,202 examples** have no
   embedding and are invisible to kNN serving and to eval.
3. Moving the same embedding model to another runtime (measured the same day:
   the host's GPU-backed Ollama is ~50x faster than the in-stack CPU embedder,
   cosine 1.000000, NOT byte-identical) leaves a seam: `ml_dedupe_dataset`
   groups on `md5(embedding)`, so an old and a new copy of one text do not
   collapse.

**Fix.** One operator tool, `ml_reembed_dataset`, over
`DatasetService::re_embed_survey` + `re_embed_batch`:
* `scope: stale` (default) — rows with no vector or a vector from another
  model. `scope: all` — every row, for a runtime change.
* **Dry-run by default.** `apply: true` runs ONE bounded pass: at most
  `limit` rows (default 200, max 500) or 20 s, whichever comes first, in `id`
  order after the `after` cursor. Resumable; a row that cannot be embedded is
  stepped over (counted `failed`, left as it was), never retried at the head
  of every later pass.
* A row is written only when its vector or model actually changes.
* The dataset's `updated_at` is not touched: it drives retraining, and a
  re-embed changes no label and no text.
* A pass that changed rows writes `ml_dataset_reembedded` to
  `admin_event_log` on its own transaction.

**Security.**
* Dataset text is embedded only by a host-local provider: the tool refuses up
  front when the configured provider is external, and the pass itself calls
  the embedder with `local_only = true` as the append path does.
* Owner-only (`require_dataset_owner`; a foreign or absent dataset is one
  answer). The select and the write both carry `dataset_id`.
* An unreadable `scope` or `after` is an error, not a default: `all` misread
  as `stale` would report "done" over rows it never looked at. A non-boolean
  `apply` is a dry run.

**Removed.** `re_embed_examples` (no caller; superseded).

**Guards.**
* `controller/tests/ml_reembed_tests` (real database, embedder supplied by the
  test): stale scope touches only stale rows and leaves `updated_at` alone;
  `all` closes the dedupe seam and rewrites only the row whose bytes differ;
  a pass is bounded, resumable, steps over a failing row, never touches
  another dataset, makes progress on a spent budget, and refuses a
  wrong-width vector.
* `controller/tests/ml_reembed_tool_tests` (through the tool, with a stand-in
  local embedder): dry-run default embeds and writes nothing; a stranger gets
  "not found" and nothing changes; apply re-embeds and records; a full pass
  over a consistent dataset writes and records nothing.
* Mutation-checked, 4 applied, 4 caught: owner gate removed; dataset predicate
  dropped from the select; audit record removed; unchanged-row guard removed.
* Handler unit tests for argument parsing and the reply's next step.

**Stated limits.**
* The external-provider refusal is not driven by a test (a test process has
  one embedding configuration, and it is local); `local_only = true` in the
  pass is the control, and it is covered in `talos-memory`.
* A pass holds one tenant-scoped transaction for up to its 20 s budget, plus
  one embedder call that is already in flight.
* Parametric (logistic-regression) artifacts trained on the old vectors are
  not refitted; the measured vector difference is ~1e-5.

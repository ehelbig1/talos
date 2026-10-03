# The boot seed sizes a shared catalog row from its template

2026-10-03

## Why

A catalog template may declare `recommended_fuel`. A first install writes
that limit to the installed copy. The boot seed, which writes the SHARED row
of every template, never wrote `modules.max_fuel` at all: on the reference
deployment all 79 shared rows carried the column default, 2,000,000,
whatever their template recommended (`json-api-reader` 18.1 M, `Plaid: Bank
Digest` 50 M, `LLM Inference` 9.9 M).

The 2026-10-01 record left this alone as "the system catalog rows' own
limits, which nothing executes under". Measured, that is not so:
`list_module_catalog` tells a caller a `usable_shared` module needs no
install, and on the reference deployment 21 live workflow nodes run directly
on shared rows — 14 of them with no `max_fuel` of their own — for 819 runs in
30 days.

## What changed

* `talos_compilation::recommended_max_fuel(manifest)` is the one reader of a
  manifest's `recommended_fuel`: the limit, `None` when it declares none, an
  error naming the field when it cannot be read. The install handler read it
  inline; it reads through this now.
* `CatalogUpsert::max_fuel` — the seed's row writer carries the limit, on
  both of its paths (matched by slug, matched by name).
* The seed passes the template's recommendation; for a template that
  recommends nothing, the column default, written explicitly so a template
  that stops recommending goes back to it; for a recommendation that cannot
  be read, nothing — the row keeps the limit it has and the seed says so.
* `hybrid-classify-alerts` recommended 1,727,560. Its installed copy on the
  reference deployment used a median of 1,768,663 and a peak of 3,977,347
  over 692 runs in 30 days, so a fresh install failed most runs. It now
  resolves to 8,127,560 and is in the test that holds a recommendation to
  twice a measured need.

## Effect on the reference deployment at its next boot

14 of 79 shared rows change: 13 are raised, one is lowered (`Smart
Classifier`, 2,000,000 → 1,000,000, its own recommendation). None of the 14
has a live node running on its shared row — the five shared rows that do
(`Echo/Debug`, `Mock Responder`, `Send HTML Email (Gmail)`, `JSON Transform`,
`Alert Normalize (Email)`) declare no recommendation and keep 2,000,000. So
no running workflow's limit moves.

## Decisions

* **The manifest's number is written as it stands, including when it is
  below the old default.** The shared row is then what a first install
  would write, and nothing else writes a shared row's limit. Taking
  `max(default, recommended)` would make the two disagree.
* **Only the shared row is written.** A user's installed copy keeps its own
  limit (the 2026-10-01 keep-on-reinstall decision); a test pins it.
* **An unreadable recommendation neither raises nor lowers.** The template
  is still seeded — its source and grants track disk — and the limit is left
  alone with a warning. Install still refuses such a template.

## Measured and not changed

* `llm-inference` recommends 9,894,000; its copies peaked at 27,954,586
  (p95 7,383,103) over 495 runs. It is general-purpose — the cost follows
  the prompt — and every node using it sets its own `max_fuel`. The
  recommendation covers p95; left.
* `smart-classifier` (1,000,000) and eight other templates had no run in 30
  days on this deployment. Their recommendations are unmeasured here.

## Stated limits

* The registry-sync writer (`talos-registry/src/sync.rs`, used when
  `TALOS_REGISTRY_URL` is set) is a second writer of shared rows and is not
  changed. It writes neither `max_fuel` nor `allowed_methods` nor
  `capability_world`, so a row it creates keeps those columns' defaults:
  2,000,000, no verb allowed, `minimal-node`. Not used on the reference
  deployment. Recorded for its own change.
* The seed's call site is held by a textual pin; the row writer and the
  reader are driven by tests.

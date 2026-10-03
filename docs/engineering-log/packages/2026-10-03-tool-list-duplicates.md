# Catalog tools listed twice; and why the tool descriptions were not trimmed

2026-10-03

## What was asked, and what the measurement said

The plan was to trim tool descriptions to their contract, on the estimate
that a third to a half would come off. Measured on the deployed tool list
(456 tools, 549 KB of schema, 390 KB of it description text):

* **23 of 1,890 description strings** carry a date, a ticket number or
  "pre-fix"/"until". History is not where the bytes are.
* The long strings are contract: grant semantics, refusal rules, input
  shapes. The 22 strings of 600 bytes or more in the eight tools a module
  build uses are 27 KB of 59 KB, and each long sentence in them was added
  after a call that went wrong without it.
* Text repeated verbatim across tools is 10 KB in all, most of it inside the
  duplicate tools below.

So the estimate is refuted and **the broad trim is not done**. Rewriting
those descriptions shorter would trade a fixed token cost for calls that fail
in the ways the sentences prevent. What the measurement did find:

## Six tools were listed twice under one name

A catalog module a user has installed exists twice in `modules` — the shared
catalog row and their own copy, same name — and `tools/list` turned both into
a tool. Six pairs on the reference deployment (`LLM_Inference-v1`, three
Gmail tools, `Google_Health__Daily_Readings-v1`, `Hybrid_Classify__Alerts_-v1`),
21 KB of duplicate schema. A tool name is an identifier: a client keeps one
of the two or rejects the list.

**Fix.** `one_row_per_catalog_tool` keeps one row per TOOL name (the
sanitised name, which is what must be unique). The shared catalog row wins,
because calling the tool installs from the catalog, so the catalog's
description and config schema describe what the call does; an installed copy
can be older than the catalog. `NodeTemplateMetadata` gains `shared`
(`user_id IS NULL`), read in the same statement.

Not changed: `list_templates` and `get_platform_info` read the same listing
and still show both rows, which is correct there — they list modules, and the
two rows are two modules.

## One repeated string shortened

`FUEL_PER_BYTE_GUIDANCE` is carried by four tools. 874 → 583 bytes: the
worked example (20 items of 60 KB) went; the range, default, measured rates,
the pointer to measuring with a rehearsal and the refusal rule stayed.

## Stated limits

* The dedupe is tested as a pure function over the rows. No test drives
  `tools/list` end to end with an installed copy present; the live read after
  deploy is the check (six names once each, about 21 KB less schema).
* Tool descriptions remain 390 KB. A client that loads every tool pays that;
  one that loads tools on demand pays for the ones it loads.

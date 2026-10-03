# json-api-reader: measured, and rebuilt around what the measurement showed

2026-10-03 (the same day the template merged, #1057)

## Why

The template shipped with `recommended_fuel` marked as an estimate: 20 fuel
per byte. Nothing had run it. Built locally with the production profile and
run through the worker runtime against made-up responses, it cost about 250
fuel per byte on ordinary entries (350 bytes, 15 fields), 86,000 per entry,
and a 1,000-entry response could not finish inside the 50 M per-node ceiling
whatever `MAX_ROWS` said. Its description promised up to 1,000 entries.

## What was wrong

Two things, found by measuring one variable at a time.

1. **The paging-cursor case built the whole branch.** When a `TOP` field
   shared its first key with `ROWS_AT` — `data.next_cursor` beside
   `data.items`, the usual layout — the module parsed all of `data` into a
   `serde_json::Value` to serve both. That is the tree the module said it
   never builds. Removing `TOP` from the same run cut the cost fivefold.
2. **Kept rows were built as values.** A `Value` per kept field, a map per
   row, a second map to put the fields in order: about 35,000 of the 52,000
   fuel per kept row was allocation.

## What changed

* No tree anywhere. The pass finds where each value ends with a scanner that
  tracks strings and bracket depth only. A kept value is validated by
  serde_json (through `deserialize_any`, so escapes, surrogates, UTF-8 and
  number ranges are all checked — serde_json's own skipper checks less) and
  its text is copied into the output. Rows are written as text.
* `TOP` fields are found on the way down. A `TOP` field that is the branch
  holding the list, or lies inside the single object `ROWS_AT` names, is
  found too; neither builds anything.
* The set of picks in play at a level is a 32-bit set, so narrowing it per
  key allocates nothing.
* String scanning steps eight bytes at a time. Without it the scanner was
  2.7 times slower than serde_json on long text (23 against 8.5 fuel per
  byte), which would have been a regression for mail-like responses.

## Measured (production profile, `opt-level = "z"`)

| response | before | after |
|---|---|---|
| 100 entries × 350 B, keep 3 fields, cursor beside the list | 8.6 M | 1.9 M |
| the same, keep 9 fields | — | 3.8 M |
| 100 entries × 4 KB (long text), keep 3 | 11.5 M | 3.8 M |
| 1,000 entries × 350 B, keep the first 100 | over 50 M | 9.0 M |
| 1,000 entries × 350 B, keep all, 3 fields | over 50 M | 18.4 M |
| 1,000 entries × 4 KB (4 MB), keep 100 | over 50 M | 27.7 M |
| 2,000 numeric entries, keep 100 | 48.9 M | 6.3 M |

As a rule: about 26 fuel per byte of response (7 for long text), plus about
1,000 per kept entry and 3,200 per kept field. `recommended_fuel` now
resolves to 18.1 M, and the template is in the test that holds a manifest's
recommendation to twice a measured need.

## Decisions

* **Text that is stepped over is not validated as JSON.** That is the trade:
  validating what is thrown away is most of what the old pass paid for.
  Everything the output depends on is checked: the objects on the way to
  `ROWS_AT`, the list, each kept entry's own structure, every kept value. A
  test pins both halves — the same malformed token is refused where it is
  kept and read past where it is not.
* **Correctness is held by comparison, not by inspection.** A test generates
  400 documents (quotes, backslashes, brackets inside strings, text outside
  ASCII, lengths either side of the eight-byte step), writes each compactly
  and pretty-printed, and requires the scanner's output to equal a full
  `Value` parse under six configs. A second runs every prefix and every
  single-byte change of a response through it: it must refuse or answer,
  never panic, and an answer must be JSON. Breaking the escape rule on
  purpose failed four tests.
* **The build profile stays.** `opt-level = 3` saved 27% of fuel for a 33%
  larger binary on the first version. Not the lever.
* **A hand-written skipper alone was not the fix.** The first attempt
  replaced serde_json's skipper and changed almost nothing, because the cost
  was the tree and the allocations. Recorded so the next module is measured
  before it is rewritten.

## Stated limits

* The measurement is local: the template compiled with the platform's
  profile and run through the worker runtime with recorded responses. It has
  not been run on the deployed platform; a rehearsal after the next deploy
  (`test_module` with `http_fixtures` and `fuel_profile`) is the check.
* The measuring harness is not in the repository (a throwaway test and a
  scratch build). The numbers are in the table above and in the manifest.
* A key repeated in one object: the last occurrence that has the field is
  the one kept. A full parse would keep the last occurrence whole.
* An installed copy does not change until it is reinstalled.

# A module's clock comes from the host

`commitments` (the owner's authoring lane) passed its round-trip test for
fourteen days and then failed it on 2026-10-17: the fixture's commitment was
due 2026-10-02, the module expires one fourteen days after its due date, and
the module read the date with `chrono::Utc::now()`, which no test can set.
The test kit drives the host clock (`talos_module_testkit::host::clock`),
but only a module that reads `datetime::now_unix()` sees it. The lane fix
(talos-workflows #87) moved that one read to the host; this package is the
rule that keeps the next module from reading its own.

## Decided

- **One rule, `talos_module_source::clock::own_clock_reads`**: over the
  module before its `#[cfg(test)]` module, comments blanked, string literals
  skipped, every line that calls `Utc::now`, `Local::now` or `SystemTime::now`
  as a whole word (`OWN_CLOCK_CALLS`, the one list). The reading comes back
  typed (`OwnClockRead { line, call }`) with a `Display` that says what to
  call instead. It lives in the source crate because of the one-home rule
  (2026-10-16 package): the catalog gate and the lane gate both call it.
- **`Instant::now()` is allowed.** It is a monotonic duration a module may
  time its own work with; it is never a date, and a test has no reason to pin
  it.
- **No opt-out marker.** The hosts rule has `// host-not-requested:` because a
  URL can be data; a clock read has no such second meaning. A module that
  wants a date takes it from the host.
- **The catalog gate**, `talos-catalog-tests/tests/clock_from_host.rs`, runs
  over `template_dirs()` (the skeletons too) with a `PREDATING` list that
  only shrinks.
- **`literals::without_comments` keeps the line breaks of a blanked block
  comment**, so a reading over it can name a source line. Its other callers
  (`config_keys`) read keys, not lines; unchanged for them.
- **`lint::find_word_outside_string`** (crate-private) is the string-aware
  search with a boundary on both sides; the lint's own
  `find_keyword_outside_string` (left boundary only) is now a call of the
  same scan.
- `docs/writing-a-template.md` gains the gate's table row and the sentence;
  `CLAUDE.md` gains one sentence in the WASM module rules.

## Measured

Over the 101 templates and 5 skeletons on 2026-10-17, seven read their own
clock, none a monotonic instant:

| template | line | call |
|---|---|---|
| briefing-html-generator | 187 | `chrono::Utc::now` |
| capture-home-assistant | 197 | `SystemTime::now` |
| capture-ntfy | 192 | `SystemTime::now` |
| google-calendar-list-events | 211 | `Utc::now` |
| google-health-daily | 384 | `Utc::now` |
| jwt-validator | 118 | `SystemTime::now` |
| plaid-bank-digest | 694 | `Utc::now` |

Seven others already read `datetime::now_unix()`. Every one of the twelve
capability worlds imports `datetime`, so the rule is satisfiable in all of
them. In the lane, fourteen modules read their own clock after #87 (the
lane's gate lists them).

## Latent vs live

Live in the lane (the failing test), latent in the catalog: a template's
test that depends on today's date would show the same way, and a replay of a
recorded run against a window computed from today drifts from its recording
silently (`google-calendar-list-events` computes "the next N days" from
`Utc::now()`).

## Deliberately NOT done

- **Fixing the seven templates.** Each is a behaviour change a test should
  cover (`jwt-validator` reads the clock to check `exp`, a security rule);
  they come off the list one at a time with their own tests.
- **Reading the clock through the test kit's clock in the compile lint.**
  The compile lint refuses what cannot run in the sandbox; an own-clock read
  runs, it only cannot be tested, so it is a catalog and lane gate, not a
  compile error.
- **A marker to admit a clock read.** See Decided.

## Stated limits

- A string literal is recognised as the compile lint recognises one; a raw
  string that both holds an inner `"` and names a call is read as code and
  refused, not admitted.
- A call reached through an alias (`use chrono::Utc as Clock; Clock::now()`)
  is not found. No template or lane module does this; the rule reads text,
  as the rest of the crate does.

## One home

`talos_module_source::clock` (`OWN_CLOCK_CALLS`, `own_clock_reads`);
`talos-catalog-tests/tests/clock_from_host.rs` for the catalog's population.

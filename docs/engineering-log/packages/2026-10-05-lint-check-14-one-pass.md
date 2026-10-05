# Lint check 14 in one pass (2026-10-05)

## Measured

`make lint` runs on every push (the pre-push hook) and in CI. Timed per
check on 2026-10-05: 194 seconds in all, and check 14 (talos-api error
sites must be marked `.extend_safe()`) took 67 of them. It looped over about
600 sites in bash and, for each, spawned `sed`, `echo` and `grep` for every
line of a 20-line look-ahead, the 8 lines above and the 5 message lines.

Next slowest, for a later change: check 63 (14.4 s), 70 (14.1 s), 52 (10.4 s),
64 (8.3 s).

## Changed

- `scripts/lint-extend-safe.py` decides each site in one pass, with a
  `--self-test` the check runs first. The seed `grep` that picks the sites,
  and its history (MCP-963, MCP-1048), stays in `lint-structural.sh`.
- A helper that fails, or whose self-test fails, fails the lint and prints
  no verdict — never the green line.
- The lint took 130 seconds with a planted bare call (which check 14 named).

## Equivalence

The old bash loop and the helper were run over the real `talos-api/src` and
two altered copies: every `.extend_safe()` removed, and every third one
removed in half the files with the opt-out markers removed in the other
half. Results: 0 and 0, 448 and 448, 29 and 29 violations — identical sets.
Output order differed only because the comparison harness's `grep` (a shell
function in the session that ran it) lists files in a varying order.

## Decided: one rule tightened

The loop had a blind spot of the kind MCP-1200 fixed: scanning forward from a
bare call, a line holding BOTH the next `async_graphql::Error::new(` and that
call's own `.extend_safe()` counted as covering the bare one, because the
marker was tested first. Now whichever comes first on that line decides.
Over the 598 real sites, 0 change verdict, so it ships at no cost. Undoing it
fails the self-test case "next line holds both, call first".
